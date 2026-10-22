"""Microsoft 365 統合監査ログ（source_type / class = m365_audit）の送信JSON生成・パーサー・取り込み口。

入力は Office 365 Management Activity API が返す監査レコード（Purviewの監査ログ検索からエクスポートした
CSVの AuditData 列も同じ形）。M365コネクタ（m365_connector.py）とCSV取り込みツール（tools/import_m365_csv.py）の
両方がここを通すので、取り込み経路で結果は変わらない。

- コネクタ・CSVツールは「ログ送信元」として、監査レコードを既存のTaxonomy KEY（action・username・srcipv4・
  eventtime・result・errorcode 等）で組み立てたJSONにして取り込む（to_payload。taxonomy.md §6.8）。
  FireEye Helix が Office 365 を共通KEYで扱うのと同じ考え方で、MicrosoftのKEY名はTaxonomyに加えない。
  監査レコード全体は rawmsg に無改変の文字列として残す。
- 正規化（events の導出列）は normalize.py の m365_audit 分岐から normalize_m365() を呼ぶ。
  時刻・送信元IP・ユーザー・サービスは汎用の Taxonomy KEY の優先順で入るので、ここでは分類だけを決める。
- 同じレコードを二度取り込まない（API の取得範囲の重なり・CSVとAPIの併用）。判定は監査レコードの Id。
"""
import ipaddress
import json
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
_RE_TZ = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")

# 監査レコードのKEY → 送信JSONのTaxonomy KEY（値はそのまま入れる。taxonomy.md §6.8）。
# 左に複数書いたものは、先頭から順に最初に値があるもの。
_MAP: list[tuple[str, tuple[str, ...]]] = [
    ("service", ("Workload",)),
    ("action", ("Operation",)),
    ("username", ("UserId",)),
    ("result", ("ResultStatus",)),
    ("objectname", ("ObjectId",)),
    ("errorcode", ("ErrorNumber",)),
    ("failurereason", ("LogonError",)),
    ("useragent", ("UserAgent",)),
    ("application", ("ApplicationDisplayName",)),
    ("appid", ("ApplicationId", "ClientAppId", "AppId")),
    ("filename", ("SourceFileName",)),
    ("filepath", ("SourceRelativeUrl",)),
    # SiteUrl は url に入れない。url は汎用の正規化で url_path（Webのパス）になり、
    # 危険パス・攻撃ペイロード等のWeb用ルールにSharePointのURLが掛かってしまうため（rawmsg には残る）
    ("mailbox", ("MailboxOwnerUPN",)),
    ("subject", ("Subject",)),
    ("mailfrom", ("P1Sender",)),
    ("parameters", ("Parameters",)),
    ("modifiedproperties", ("ModifiedProperties",)),
    ("extendedproperties", ("ExtendedProperties",)),
    ("target", ("Target",)),
    ("sessionid", ("SessionId",)),
    ("deviceid", ("DeviceId",)),
]


def clean_ip(value) -> str | None:
    """ClientIP 等の値から、GeoIP・集計に使えるIPだけを取り出す。
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


def _get(d: dict, key: str):
    """KEYを大文字小文字を区別せずに引く（Taxonomy KEYの照合規則と同じ）。"""
    if key in d:
        return d[key]
    low = key.lower()
    for k, v in d.items():
        if str(k).lower() == low:
            return v
    return None


def _empty(v) -> bool:
    return v is None or v == "" or v == [] or v == {}


def to_payload(record: dict) -> dict:
    """監査レコード → 送信JSON（ログ送信元としての生成。taxonomy.md §6.8）。
    MicrosoftのKEYは既存のTaxonomy KEYへ値をそのまま入れ、レコード全体は rawmsg に残す。"""
    out: dict = {"class": SOURCE_TYPE}
    ct = _get(record, "CreationTime")
    if isinstance(ct, str) and ct.strip():
        # CreationTime はタイムゾーン表記の無いUTC。そのままでは汎用の時刻解決がJSTとみなして9時間ずれるため、
        # 送信元としてUTCであることを明示する
        s = ct.strip()
        out["eventtime"] = s if _RE_TZ.search(s) else s + "Z"
    for key, srcs in _MAP:
        for src in srcs:
            v = _get(record, src)
            if not _empty(v):
                out[key] = v
                break
    for src in ("ClientIP", "ClientIPAddress", "ActorIpAddress"):
        ip = clean_ip(_get(record, src))
        if ip:
            out["srcipv6" if ":" in ip else "srcipv4"] = ip
            break
    out["rawmsg"] = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    return out


def _result(op: str, payload: dict) -> str:
    if op == "UserLoggedIn":
        return "success"
    if op == "UserLoginFailed":
        code = str(_get(payload, "errorcode") or "").strip()
        if not code:
            return "failure"  # 番号が無ければMicrosoftの記録どおり失敗
        return "failure" if code in CREDENTIAL_FAILURE_CODES else "unknown"
    rs = str(_get(payload, "result") or "").strip().lower()
    if rs in _OK:
        return "success"
    if rs in _NG:
        return "failure"
    return "unknown"  # 値なし（約4割）・PartiallySucceeded 等


def _message(service: str, op: str, payload: dict) -> str:
    """一覧で読める1行の要約。値はpayloadにあるものだけを並べる（推定はしない）。"""
    head = f"{service} / {op}" if service else op
    if op == "UserLoginFailed":
        detail = "・".join(str(x) for x in (_get(payload, "failurereason"), _get(payload, "errorcode")) if x)
        return f"{head}（{detail}）" if detail else head
    for k in ("filename", "objectname"):
        v = _get(payload, k)
        if isinstance(v, str) and v.strip():
            return f"{head}: {v.strip()[:300]}"
    return head


def normalize_m365(payload: dict, norm: dict) -> None:
    """normalize._category_extras の m365_audit 分岐。payload は読むだけ。
    event_time・source_ip・actor_user・service_name は汎用の Taxonomy KEY（eventtime・srcipv4/srcipv6・
    username・service）から入っている。"""
    op = str(_get(payload, "action") or "").strip()
    service = str(_get(payload, "service") or "").strip()
    norm["event_category"] = "authentication" if op in ("UserLoggedIn", "UserLoginFailed") else "audit"
    norm["event_action"] = op[:64] or None
    norm["event_result"] = _result(op, payload)
    norm["message"] = _message(service, op, payload)


# ---------------------------------------------------------------- 取り込み

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
    ids = [str(r.get("Id")) for r in records if isinstance(r, dict) and r.get("Id")]
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
