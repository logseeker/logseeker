"""event_time 解釈（派生）。payload は改変しない。元文字列と confidence も返す。
confidence: high(tz付き) / medium(tzなし日時) / low(年なし補完) / none(解釈不能)。"""
from datetime import datetime, timedelta, timezone

JST = timezone(timedelta(hours=9))

TS_KEYS = [
    "event_time", "timestamp", "time", "ts", "datetime", "date",
    "@timestamp", "EventReceivedTime", "EventTime", "eventTime",
    "日付", "Date", "Time", "Timestamp",
]


def parse_time(s: str) -> tuple[datetime | None, str]:
    """文字列 → (datetime, confidence)。"""
    s = (s or "").strip()
    if not s:
        return None, "none"
    # ISO8601（tz付き/なし）
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo:
            return dt, "high"
        return dt.replace(tzinfo=JST), "medium"
    except ValueError:
        pass
    # Apache: 23/Apr/2026:12:09:35 +0900
    try:
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z"), "high"
    except ValueError:
        pass
    # tzなし日時
    for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%a %b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=JST), "medium"
        except ValueError:
            continue
    # syslog: Jun 22 23:17:01（年なし → 当年補完）
    try:
        dt = datetime.strptime(s, "%b %d %H:%M:%S")
        return dt.replace(year=datetime.now(JST).year, tzinfo=JST), "low"
    except ValueError:
        return None, "none"


def resolve_time(payload: dict) -> tuple[datetime | None, str | None, str]:
    """payload の時刻フィールドを探して (datetime, 元文字列, confidence) を返す。"""
    if not isinstance(payload, dict):
        return None, None, "none"
    for key in TS_KEYS:
        v = payload.get(key)
        if isinstance(v, (str, int, float)) and str(v).strip():
            dt, conf = parse_time(str(v))
            if dt:
                return dt, str(v), conf
    return None, None, "none"
