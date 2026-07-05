"""生ログ(テキスト) → JSON への『忠実』変換。
原則:
  - 値は一切書き換えない（翻訳・意味付け・成否判定・国付与などはしない）。
  - 元の1行は必ず "raw" にそのまま保持する。
  - ログに元から在る項目だけを、見たままの値で取り出す（無い項目は作らない）。
CSV はここを通さず、列名・値そのままを dict 化する（load_logs 側）。
※これは『例外的な取り込み手段』。本来の入口は JSON をそのまま受ける /ingest。"""
import re

# --- YAMAHA ルーター syslog ---
_RE_YAMAHA = re.compile(
    r"^(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}):\s*(?:\[(?P<tag>[^\]]+)\]\s*)?(?P<message>.*)$"
)
# --- Apache access (combined/common) ---
_RE_ACCESS = re.compile(
    r'^(?P<client>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\S+)\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?\s*$'
)
# --- Apache error ---
_RE_ERROR = re.compile(
    r'^\[(?P<time>[^\]]+)\]\s+\[(?P<level>[^\]]+)\]\s+(?:\[client (?P<client>[^\]]+)\]\s+)?(?P<message>.*)$'
)
# --- Samba（結合済み複数行）---
_RE_SMB_TIME = re.compile(r"^\[(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")
_RE_SMB_USER = re.compile(r"user\s+\[(?P<user>[^\]]+)\]")
# --- LiteSpeed access（先頭に ["vhost"]、末尾にも vhost が付く combined）---
_RE_LSWS_ACCESS = re.compile(
    r'^\[?"?(?P<vhost>[^\]"]+)"?\]?\s+'
    r'(?P<client>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\S+)\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    r'(?:\s+"[^"]*")?\s*$'
)
# --- LiteSpeed error（時刻 [LEVEL] [pid] [context]: message）---
_RE_LSWS_ERROR = re.compile(
    r'^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
    r'\[(?P<level>[^\]]+)\]\s+'
    r'(?:\[(?P<pid>\d+)\]\s+)?'
    r'(?:\[(?P<context>[^\]]*)\]\s*:?\s*)?(?P<message>.*)$'
)
_RE_TS_HEAD = re.compile(r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
# --- logw アクセスログ（行全体が " で囲まれる: "vhost ip - - [time] "req" status size"）---
_RE_LOGW = re.compile(
    r'^"?(?P<vhost>\S+)\s+(?P<client>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)"?\s*$'
)

# --- 標準 syslog（host/process が行内に在る）---
_RE_SYSLOG = re.compile(
    r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<process>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)


def _clean(d: dict, raw: str) -> dict:
    """None のグループを捨て、raw を必ず残す。"""
    out = {k: v for k, v in d.items() if v is not None}
    out["raw"] = raw
    return out


def conv_yamaha(line: str) -> dict:
    m = _RE_YAMAHA.match(line)
    if not m:
        return {"raw": line}
    return _clean(m.groupdict(), line)


def conv_apache_access(line: str) -> dict:
    m = _RE_ACCESS.match(line)
    if not m:
        return {"raw": line}
    return _clean(m.groupdict(), line)


def conv_apache_error(line: str) -> dict:
    m = _RE_ERROR.match(line)
    if not m:
        return {"raw": line}
    return _clean(m.groupdict(), line)


def conv_samba(merged: str) -> dict:
    data: dict = {}
    mt = _RE_SMB_TIME.match(merged)
    if mt:
        data["time"] = mt.group("time")
    mu = _RE_SMB_USER.search(merged)
    if mu:
        data["user"] = mu.group("user")
    return _clean(data, merged)


def conv_syslog(line: str) -> dict:
    m = _RE_SYSLOG.match(line)
    if not m:
        return {"raw": line}
    return _clean(m.groupdict(), line)


def conv_lsws_access(line: str) -> dict:
    m = _RE_LSWS_ACCESS.match(line)
    if not m:
        return {"raw": line}
    return _clean(m.groupdict(), line)


def conv_lsws_error(line: str) -> dict:
    m = _RE_LSWS_ERROR.match(line)
    if not m:
        return {"raw": line}
    return _clean(m.groupdict(), line)


def conv_logw_access(line: str) -> dict:
    m = _RE_LOGW.match(line)
    if not m:
        return {"raw": line}
    return _clean(m.groupdict(), line)


def conv_stderr(merged: str) -> dict:
    """複数行を結合済み。先頭の時刻だけ取り出し、本文は raw に保持。"""
    data: dict = {}
    mt = _RE_TS_HEAD.match(merged)
    if mt:
        data["time"] = mt.group("time")
    return _clean(data, merged)


def conv_lsrestart(pair: str) -> dict:
    """'曜 月 日 時刻 JST 年' と 次行のステータスを ' | ' で結合して渡す。"""
    if " | " in pair:
        time_str, msg = pair.split(" | ", 1)
        return {"time": time_str, "message": msg, "raw": pair}
    return {"raw": pair}


# kind 名 → 変換関数
CONVERTERS = {
    "yamaha": conv_yamaha,
    "apache_access": conv_apache_access,
    "apache_error": conv_apache_error,
    "samba": conv_samba,
    "syslog": conv_syslog,
    "lsws_access": conv_lsws_access,
    "lsws_error": conv_lsws_error,
    "logw_access": conv_logw_access,
    "stderr": conv_stderr,
    "lsrestart": conv_lsrestart,
}
