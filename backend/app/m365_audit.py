"""Microsoft 365 統合監査ログ（source_type / class = m365_audit）のパーサーと取り込み口。

入力は Office 365 Management Activity API が返す監査レコードのJSON（Purviewの監査ログ検索から
エクスポートしたCSVの AuditData 列も同じ形）。M365コネクタ（m365_connector.py）とCSV取り込み
ツール（tools/import_m365_csv.py）の両方がここを通すので、取り込み経路で結果は変わらない。

- payload はMicrosoftのJSONを無改変で保存する。送信元として付けるのは class だけ（taxonomy.md §6.8）。
- 正規化（events の導出列）は normalize.py の m365_audit 分岐から normalize_m365() を呼ぶ。
- 同じレコードを二度取り込まない（API の取得範囲の重なり・CSVとAPIの併用）。判定はレコードの Id。
"""
import ipaddress
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .models import ConnectorSeen

SOURCE_TYPE = "m365_audit"
DEFAULT_SOURCE = "m365"
DEDUP_RECORD = "m365"          # ConnectorSeen.connector: 監査レコードの Id
DEDUP_BLOB = "m365_blob"       # ConnectorSeen.connector: Management Activity API のコンテンツ(blob) の contentId

# UserLoginFailed のうち「資格情報が通らなかった・拒否された」エラー番号（AADSTS）。
# これ以外の番号（50074=MFAを求めるための中断、50199=確認画面、65001=アプリの同意が無い等）は、
# Microsoftの記録上は UserLoginFailed でも、パスワードが違ったわけではなく通常のサインインの途中経過。
# 失敗に数えると、MFA付きの正規のサインイン（中断→成功）が毎回失敗の連続に見えてしまうため、
# event_result は unknown にする（実データ105件中、資格情報の失敗は19件だけだった）。
# パスワードの期限切れ（50055・50144）も、パスワード自体は正しいので失敗に数えない。
CREDENTIAL_FAILURE_CODES = {
    "50034",   # ユーザーが存在しない
    "50053",   # アカウントのロック（スマートロックアウト・不審なIPからの試行）
    "50056",   # パスワードが無い・不正
    "50057",   # アカウントが無効
    "50064",   # 資格情報の検証に失敗
    "50126",   # ユーザー名またはパスワードが違う
    "500121",  # MFA（強力な認証）に失敗・拒否された
    "53003",   # 条件付きアクセスでブロック
    "50105",   # アプリへのアクセスが割り当てられていない
}

_OK = {"succeeded", "success", "successful", "true"}
_NG = {"failed", "failure", "error", "authorizationfailure", "false"}

_RE_V4_PORT = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):\d+$")
_RE_V6_PORT = re.compile(r"^\[([0-9A-Fa-f:.]+)\](?::\d+)?$")


def clean_ip(value) -> str | None:
    """ClientIP 等の値から、GeoIP・集計に使えるIPだけを取り出す（payload は変えない）。
    実データの形: 1.2.3.4 / 1.2.3.4:port / [IPv6]:port / IPv6 / ::ffff:1.2.3.4 / NA / true。
    IPとして読めない値と、ループバック・未指定アドレス（Exchangeの内部処理の [::1]）は捨てる。"""
    if not isinstance(value, str):
        return None
    s = value.strip()
    m = _RE_V4_PORT.match(s) or _RE_V6_PORT.match(s)
    if m:
        s = m.group(1)
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_unspecified:
        return None
    return str(ip)


def _get(payload: dict, key: str):
    """Taxonomy KEY と同じく大文字小文字を区別せずに引く（payload は変えない）。"""
    if key in payload:
        return payload[key]
    low = key.lower()
    for k, v in payload.items():
        if str(k).lower() == low:
            return v
    return None


def _creation_time(payload: dict) -> tuple[datetime | None, str | None]:
    """CreationTime はタイムゾーン表記の無いUTC（例: 2026-10-13T17:34:20）。
    汎用の時刻解決（timeparse）はタイムゾーン無しをJSTとみなすため、そのままでは9時間ずれる。"""
    raw = _get(payload, "CreationTime")
    if not isinstance(raw, str) or not raw.strip():
        return None, None
    try:
        dt = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return None, raw
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt, raw


def _result(op: str, payload: dict) -> str:
    if op == "UserLoggedIn":
        return "success"
    if op == "UserLoginFailed":
        code = str(_get(payload, "ErrorNumber") or "").strip()
        if not code:
            return "failure"  # 番号が無ければMicrosoftの記録どおり失敗
        return "failure" if code in CREDENTIAL_FAILURE_CODES else "unknown"
    rs = str(_get(payload, "ResultStatus") or "").strip().lower()
    if rs in _OK:
        return "success"
    if rs in _NG:
        return "failure"
    return "unknown"  # 値なし（約4割）・PartiallySucceeded 等


def _message(workload: str, op: str, payload: dict) -> str:
    """一覧で読める1行の要約。値はpayloadにあるものだけを並べる（推定はしない）。"""
    head = f"{workload} / {op}" if workload else op
    if op == "UserLoginFailed":
        err = _get(payload, "LogonError")
        code = _get(payload, "ErrorNumber")
        detail = "・".join(str(x) for x in (err, code) if x)
        return f"{head}（{detail}）" if detail else head
    for k in ("SourceFileName", "ObjectId", "SiteUrl"):
        v = _get(payload, k)
        if isinstance(v, str) and v.strip():
            return f"{head}: {v.strip()[:300]}"
    return head


def normalize_m365(payload: dict, norm: dict) -> None:
    """normalize._category_extras の m365_audit 分岐。payload は読むだけ。"""
    op = str(_get(payload, "Operation") or "").strip()
    workload = str(_get(payload, "Workload") or "").strip()

    dt, raw = _creation_time(payload)
    if dt:
        norm["event_time"], norm["event_time_original"], norm["event_time_confidence"] = dt, raw, "high"

    norm["event_category"] = ("authentication" if op in ("UserLoggedIn", "UserLoginFailed") else "audit")
    norm["event_action"] = op[:64] or None
    norm["event_result"] = _result(op, payload)
    norm["service_name"] = workload[:128] or None

    # 操作ユーザー・送信元IP は m365_audit の中だけで決める（taxonomy.md v1.15 の方針）。
    # userid / clientip を taxonomy_fields の汎用の候補に加えると、Windowsの UserID（SID）のように
    # 同名KEYを持つ他Classの結果まで変わってしまうため。
    user = _get(payload, "UserId")
    norm["actor_user"] = str(user).strip()[:255] if user not in (None, "") else None
    ip = None
    for k in ("ClientIP", "ClientIPAddress", "ActorIpAddress"):
        ip = clean_ip(_get(payload, k))
        if ip:
            break
    norm["source_ip"] = ip

    norm["message"] = _message(workload, op, payload)


# ---------------------------------------------------------------- 取り込み

def to_payload(record: dict) -> dict:
    """送信元として class を付ける（taxonomy.md §5: class はログ送信元が設定する）。他のKEYは無改変。"""
    if any(str(k).lower() == "class" for k in record):
        return record
    return {"class": SOURCE_TYPE, **record}


def seen_ids(db: Session, connector: str, ids: list[str]) -> set[str]:
    out: set[str] = set()
    for i in range(0, len(ids), 1000):
        chunk = ids[i:i + 1000]
        out.update(db.execute(select(ConnectorSeen.item_id).where(
            ConnectorSeen.connector == connector, ConnectorSeen.item_id.in_(chunk))).scalars().all())
    return out


def mark_seen(db: Session, connector: str, item_id: str) -> None:
    db.add(ConnectorSeen(connector=connector, item_id=item_id[:128]))


def ingest_records(db: Session, records: list[dict], source: str = DEFAULT_SOURCE,
                   channel: str = "connector") -> tuple[int, int]:
    """監査レコードを取り込む。戻り: (取り込んだ件数, 取り込み済みのため飛ばした件数)。commit は呼び出し側。
    Id があるレコードは、過去に取り込んだもの・同じ呼び出しの中で重複したものを飛ばす。"""
    from .pipeline import ingest_one  # pipeline → normalize → このモジュール の循環を避ける
    ids =[str(r.get("Id")) for r in records if isinstance(r, dict) and r.get("Id")]
    done = seen_ids(db, DEDUP_RECORD, ids) if ids else set()
    stored = dup = 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        rid = str(rec.get("Id") or "")
        if rid and rid in done:
            dup += 1
            continue
        ingest_one(db, to_payload(rec), source=source, source_type=SOURCE_TYPE, channel=channel)
        if rid:
            mark_seen(db, DEDUP_RECORD, rid)
            done.add(rid)
        stored += 1
    return stored, dup


def prune_blobs(db: Session, days: int = 8) -> None:
    """API のコンテンツ(blob)は7日で消えるので、それより古い contentId の記録は要らない。"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    db.execute(delete(ConnectorSeen).where(ConnectorSeen.connector == DEDUP_BLOB,
                                           ConnectorSeen.seen_at < cutoff))
