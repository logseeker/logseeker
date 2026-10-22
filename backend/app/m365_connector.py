"""Microsoft 365 監査ログコネクタ（Office 365 Management Activity API から定期取得する）。

  1. クライアント資格情報でトークンを取る（Entra ID のアプリ登録。権限は ActivityFeed.Read）
  2. 対象のコンテンツ種別（Audit.Exchange 等）の購読が無ければ開始する
  3. 前回の続きから現在までに作られたコンテンツ(blob)を一覧し、まだ取り込んでいない blob を取得する
  4. blob の中の監査レコードを m365_audit.ingest_records() で取り込む（Id で重複を除く）

APIの制約（Microsoftの仕様）:
  - 一覧できるのは過去7日まで。1回の一覧の範囲は24時間まで（それを超える分は分けて問い合わせる）
  - イベントが起きてから blob に入るまで、数十分〜最長24時間ほど遅れることがある
    （一覧は blob の作成時刻で行うので、遅れて作られた blob も次回以降の一覧で拾える）
  - 一覧のページ送りはレスポンスヘッダー NextPageUri

設定は settings テーブル（m365_*）に持つ。クライアントシークレットは画面へ返さない。
定期実行は monitor_scheduler 等と同じく起動時に始めるスレッド（start()）。
"""
import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .db import SessionLocal
from .m365_audit import (DEDUP_BLOB, DEFAULT_SOURCE, SOURCE_TYPE, ingest_records, mark_seen, prune_blobs,
                         seen_ids)
from .models import Event, Setting

log = logging.getLogger("m365_connector")

# コンテンツ種別（Management Activity API）。DLP.All は機密情報の中身を含むため既定では取らない
# （別の権限 ActivityFeed.ReadDlp も要る）。
CONTENT_TYPES = ["Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint", "Audit.General", "DLP.All"]
DEFAULT_CONTENT_TYPES = CONTENT_TYPES[:4]
INTERVALS_MIN = (5, 15, 30, 60)
DEFAULT_INTERVAL_MIN = 15
MAX_LOOKBACK = timedelta(days=7) - timedelta(minutes=10)  # API の上限（7日）より少し内側
OVERLAP = timedelta(hours=1)    # 一覧に反映されるまでの遅れの取りこぼし対策（重複は contentId で除く）
WINDOW = timedelta(hours=24)    # 1回の一覧の最大範囲
HTTP_TIMEOUT = 60

_P = "m365_"
_lock = threading.Lock()        # 定期実行と「今すぐ取得」が重ならないように
_token: dict = {}               # {"key": (tenant, client), "value": str, "exp": epoch}


class M365Error(Exception):
    pass


# ---------------------------------------------------------------- 設定

def _get(db: Session, key: str, default: str = "") -> str:
    row = db.get(Setting, _P + key)
    return row.value if (row and row.value is not None) else default


def _set(db: Session, key: str, value: str) -> None:
    row = db.get(Setting, _P + key)
    if not row:
        row = Setting(key=_P + key)
        db.add(row)
    row.value = value


def get_config(db: Session) -> dict:
    types = [t for t in _get(db, "content_types", ",".join(DEFAULT_CONTENT_TYPES)).split(",") if t in CONTENT_TYPES]
    try:
        interval = int(_get(db, "interval_min", str(DEFAULT_INTERVAL_MIN)))
    except ValueError:
        interval = DEFAULT_INTERVAL_MIN
    return {
        "enabled": _get(db, "enabled") == "1",
        "tenant_id": _get(db, "tenant_id"),
        "client_id": _get(db, "client_id"),
        "client_secret": _get(db, "client_secret"),
        "content_types": types,
        "interval_min": interval if interval in INTERVALS_MIN else DEFAULT_INTERVAL_MIN,
    }


def save_config(db: Session, body: dict) -> list[str]:
    """画面からの保存。client_secret は空なら既存のまま。戻り: 監査ログ用の変更内容。"""
    cur = get_config(db)
    changes = []
    if bool(body.get("enabled")) != cur["enabled"]:
        changes.append("自動取得を有効化" if body.get("enabled") else "自動取得を無効化")
    for k, label in (("tenant_id", "テナントID"), ("client_id", "クライアントID")):
        v = (body.get(k) or "").strip()
        if v != cur[k]:
            changes.append(f"{label}を変更")
        _set(db, k, v)
    if (body.get("client_secret") or "").strip():
        _set(db, "client_secret", body["client_secret"].strip())
        changes.append("クライアントシークレットを変更")
        _token.clear()
    types = [t for t in (body.get("content_types") or []) if t in CONTENT_TYPES] or DEFAULT_CONTENT_TYPES
    if types != cur["content_types"]:
        changes.append("取得するログの種類: " + "・".join(types))
    interval = int(body.get("interval_min") or DEFAULT_INTERVAL_MIN)
    if interval not in INTERVALS_MIN:
        interval = DEFAULT_INTERVAL_MIN
    if interval != cur["interval_min"]:
        changes.append(f"取得間隔: {interval}分")
    _set(db, "enabled", "1" if body.get("enabled") else "0")
    _set(db, "content_types", ",".join(types))
    _set(db, "interval_min", str(interval))
    if cur["tenant_id"] != (body.get("tenant_id") or "").strip() or cur["client_id"] != (body.get("client_id") or "").strip():
        _token.clear()
    db.commit()
    return changes


def _cursors(db: Session) -> dict:
    try:
        return json.loads(_get(db, "cursors") or "{}")
    except ValueError:
        return {}


def status(db: Session) -> dict:
    cfg = get_config(db)
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    count = db.scalar(select(func.count()).select_from(Event).where(Event.source_type == SOURCE_TYPE)) or 0
    count_24h = db.scalar(select(func.count()).select_from(Event).where(
        Event.source_type == SOURCE_TYPE, Event.received_at >= since)) or 0
    return {
        "enabled": cfg["enabled"], "tenant_id": cfg["tenant_id"], "client_id": cfg["client_id"],
        "has_secret": bool(cfg["client_secret"]), "content_types": cfg["content_types"],
        "interval_min": cfg["interval_min"], "all_content_types": CONTENT_TYPES,
        "intervals": list(INTERVALS_MIN), "running": _lock.locked(),
        "last_run_at": _get(db, "last_run_at") or None, "last_status": _get(db, "last_status") or None,
        "last_ok": _get(db, "last_ok") == "1", "cursors": _cursors(db),
        "event_count": count, "event_count_24h": count_24h,
    }


# ---------------------------------------------------------------- HTTP

def _http(method: str, url: str, headers: dict | None = None, data: bytes | None = None):
    """戻り: (JSON, レスポンスヘッダー)。HTTPエラーはMicrosoftのエラーメッセージ付きで M365Error。"""
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            body = r.read().decode("utf-8", "replace")
            return (json.loads(body) if body.strip() else None), r.headers
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            j = json.loads(raw)
            err = j.get("error")
            if isinstance(err, dict):  # Management API: {"error":{"code":"AF20022","message":"..."}}
                msg = f"{err.get('code', '')} {err.get('message', '')}".strip()
            else:                      # トークン: {"error":"invalid_client","error_description":"AADSTS..."}
                msg = f"{err or ''} {(j.get('error_description') or '').splitlines()[0] if j.get('error_description') else ''}".strip()
        except ValueError:
            msg = raw[:300]
        raise M365Error(f"HTTP {e.code}: {msg}") from None
    except urllib.error.URLError as e:
        raise M365Error(f"接続できません: {e.reason}") from None


def _access_token(cfg: dict) -> str:
    key = (cfg["tenant_id"], cfg["client_id"])
    if _token.get("key") == key and _token.get("exp", 0) > time.time() + 60:
        return _token["value"]
    url = f"{settings.M365_LOGIN_BASE}/{urllib.parse.quote(cfg['tenant_id'])}/oauth2/v2.0/token"
    form = urllib.parse.urlencode({
        "client_id": cfg["client_id"], "client_secret": cfg["client_secret"],
        "scope": f"{settings.M365_API_BASE}/.default", "grant_type": "client_credentials",
    }).encode()
    j, _ = _http("POST", url, {"Content-Type": "application/x-www-form-urlencoded"}, form)
    if not j or not j.get("access_token"):
        raise M365Error("トークンを取得できませんでした")
    _token.update(key=key, value=j["access_token"], exp=time.time() + int(j.get("expires_in", 3600)))
    return j["access_token"]


def _feed(cfg: dict, path: str, params: dict | None = None) -> str:
    q = dict(params or {})
    q["PublisherIdentifier"] = cfg["tenant_id"]  # 呼び出し回数の上限をテナント単位にする（Microsoft推奨）
    return (f"{settings.M365_API_BASE}/api/v1.0/{urllib.parse.quote(cfg['tenant_id'])}/activity/feed/"
            f"{path}?{urllib.parse.urlencode(q)}")


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _require(cfg: dict) -> None:
    missing = [label for k, label in (("tenant_id", "テナントID"), ("client_id", "クライアントID"),
                                      ("client_secret", "クライアントシークレット")) if not cfg[k]]
    if missing:
        raise M365Error("未設定の項目があります: " + "・".join(missing))


def subscriptions(cfg: dict, token: str) -> dict[str, str]:
    """{コンテンツ種別: "enabled" / "disabled"}。購読していない種別は含まれない。"""
    j, _ = _http("GET", _feed(cfg, "subscriptions/list"), _auth(token))
    return {s.get("contentType"): str(s.get("status") or "").lower() for s in (j or []) if isinstance(s, dict)}


def test_connection(db: Session) -> dict:
    """接続テスト: トークン取得と購読状況の確認だけ（取り込みはしない・購読も開始しない）。"""
    cfg = get_config(db)
    try:
        _require(cfg)
        token = _access_token(cfg)
        subs = subscriptions(cfg, token)
    except M365Error as e:
        return {"ok": False, "message": str(e)}
    return {"ok": True, "message": "接続できました",
            "subscriptions": {t: subs.get(t, "未購読") for t in CONTENT_TYPES}}


# ---------------------------------------------------------------- 取得

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _list_content(cfg: dict, token: str, ctype: str, start: datetime, end: datetime):
    url = _feed(cfg, "subscriptions/content", {"contentType": ctype, "startTime": _iso(start), "endTime": _iso(end)})
    while url:
        j, headers = _http("GET", url, _auth(token))
        for c in (j or []):
            if isinstance(c, dict) and c.get("contentUri"):
                yield c
        url = headers.get("NextPageUri")


def _fetch_type(db: Session, cfg: dict, token: str, ctype: str, start: datetime, now: datetime) -> tuple[int, int, int]:
    """1種別ぶん。戻り: (blob数, 取り込んだ件数, 重複で飛ばした件数)。blob ごとに commit する。"""
    blobs = stored = dup = 0
    t = start
    while t < now:
        end = min(t + WINDOW, now)
        for c in _list_content(cfg, token, ctype, t, end):
            cid = str(c.get("contentId") or c["contentUri"])[:128]
            if seen_ids(db, DEDUP_BLOB, [cid]):
                continue
            records, _ = _http("GET", c["contentUri"], _auth(token))
            s, d = ingest_records(db, [r for r in (records or []) if isinstance(r, dict)],
                                  source=DEFAULT_SOURCE, channel="connector")
            mark_seen(db, DEDUP_BLOB, cid)
            db.commit()
            blobs, stored, dup = blobs + 1, stored + s, dup + d
        t = end
    return blobs, stored, dup


def run_once(db: Session) -> dict:
    """1回分の取得。設定の有効/無効は見ない（定期実行側で判定する。「今すぐ取得」は無効でも動く）。"""
    if not _lock.acquire(blocking=False):
        return {"ok": False, "message": "取得中です"}
    started = datetime.now(timezone.utc)
    try:
        cfg = get_config(db)
        results, errors = [], []
        try:
            _require(cfg)
            token = _access_token(cfg)
            subs = subscriptions(cfg, token)
            for ctype in cfg["content_types"]:
                if subs.get(ctype) != "enabled":
                    _http("POST", _feed(cfg, "subscriptions/start", {"contentType": ctype}), _auth(token), b"")
        except M365Error as e:
            errors.append(str(e))
            cfg["content_types"] = []  # 認証・購読で失敗したら取得しない

        cursors = _cursors(db)
        floor = started - MAX_LOOKBACK
        total_blobs = total = total_dup = 0
        for ctype in cfg["content_types"]:
            prev = cursors.get(ctype)
            start = (datetime.fromisoformat(prev) - OVERLAP) if prev else floor
            start = max(start, floor)
            try:
                b, s, d = _fetch_type(db, cfg, token, ctype, start, started)
            except M365Error as e:
                db.rollback()
                errors.append(f"{ctype}: {e}")
                continue  # この種別の続きは次回（カーソルを進めない）
            cursors[ctype] = started.isoformat()
            _set(db, "cursors", json.dumps(cursors))
            db.commit()
            total_blobs, total, total_dup = total_blobs + b, total + s, total_dup + d
            results.append(f"{ctype.split('.', 1)[1]} {s:,}件")
        prune_blobs(db)

        ok = not errors
        msg = (f"{total:,}件を取り込み（重複{total_dup:,}件を除外・コンテンツ{total_blobs:,}件）"
               + (" / " + " / ".join(errors) if errors else ""))
        _set(db, "last_run_at", started.isoformat())
        _set(db, "last_status", msg[:1000])
        _set(db, "last_ok", "1" if ok else "0")
        db.commit()
        if total or errors:
            (log.info if ok else log.warning)("M365: %s", msg)
        return {"ok": ok, "message": msg, "stored": total, "duplicates": total_dup, "details": results}
    finally:
        _lock.release()


def run_in_background() -> bool:
    """「今すぐ取得」。取得は数分かかることがあるのでリクエストを待たせない。戻り: 開始したか。"""
    if _lock.locked():
        return False

    def _job():
        db = SessionLocal()
        try:
            run_once(db)
        except Exception as e:  # noqa
            log.warning("m365 run error: %s", e)
        finally:
            db.close()

    threading.Thread(target=_job, daemon=True).start()
    return True


def _loop() -> None:
    time.sleep(150)  # 起動直後はDB準備待ち
    next_run = 0.0
    while True:
        db = SessionLocal()
        try:
            cfg = get_config(db)
            if cfg["enabled"] and time.time() >= next_run:
                run_once(db)
                next_run = time.time() + cfg["interval_min"] * 60
        except Exception as e:  # noqa
            log.warning("m365 scheduler error: %s", e)
        finally:
            db.close()
        time.sleep(60)


def start() -> None:
    threading.Thread(target=_loop, daemon=True).start()
