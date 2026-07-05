"""payload → 軽量タクソノミー(normalized_events) への正規化（PROJECT.md §7,8,10,14）。
- payload は読むだけ・改変しない。
- 正規化できない項目は null。無理に推定しすぎない（§19.2）。
- source_type ごとの mapping(候補キー) + 汎用 extractor + 種別ごとの分類で導出する。
"""
import re
from typing import Any

from . import extractors
from .timeparse import resolve_time

# source_type → { taxonomy_field: [payload候補キー...] }（直接コピー）
MAPPINGS: dict[str, dict[str, list[str]]] = {
    # 候補キーは小文字系(LiteSpeed/自前) + NXLog の PascalCase を両対応。
    "web_access": {
        "source_ip": ["client", "MessageSourceAddress", "SourceIPAddress", "RemoteIPAddress",
                      "ClientAddress", "RemoteIP", "remote_addr"],
        "url_domain": ["vhost", "ServerName", "http_host", "Host"],
        "request": ["request"],
        "http_method": ["HTTPMethod", "RequestMethod", "request_method"],
        "url_path": ["HTTPURL", "RequestURI", "HTTPURI", "request_uri", "uri"],
        "http_status_code": ["status", "HTTPResponseStatus", "ResponseStatus", "StatusCode", "code"],
        "http_user_agent": ["user_agent", "HTTPUserAgent", "UserAgent", "http_user_agent"],
        "http_referer": ["referer", "HTTPReferer", "Referer", "http_referer"],
        "actor_user": ["user", "RemoteUser", "UserName", "remote_user"],
        "observer_name": ["Hostname"],
    },
    "web_error": {
        "message": ["message", "Message"],
        "service_name": ["context", "ApacheModule"],
        "event_severity": ["level", "ApacheLogLevel", "Severity"],
        "source_ip": ["ClientAddress", "client", "MessageSourceAddress"],
    },
    "application": {
        "message": ["message", "raw"],
    },
    "google_workspace_audit": {
        "event_action": ["イベント"],
        "message": ["説明"],
        "actor_user": ["アクター"],
        "source_ip": ["IP アドレス", "IPアドレス"],
        "target_resource": ["リソース"],
    },
    "router": {
        "message": ["message"],
    },
    "nas": {
        "observer_name": ["host"],
        "service_name": ["process"],
        "message": ["message"],
    },
    "auth": {
        "actor_user": ["user"],
        "observer_name": ["host"],
        "service_name": ["process"],
        "message": ["message", "raw"],
    },
    # メール（NXLog Postfix / Exchange）
    "mail": {
        "source_ip": ["ClientIP", "RelayIP", "client_ip"],
        "actor_user": ["Sender", "From", "sender"],
        "target_user": ["Recipient", "To", "recipient"],
        "observer_name": ["HostName", "Hostname"],
        "service_name": ["Component", "SourceName"],
        "request_id": ["QueueID", "MessageID"],
        "message": ["Message", "message"],
        "event_severity": ["Severity"],
    },
    # Windows イベントログ（NXLog im_msvistalog）
    "windows_event": {
        "actor_user": ["TargetUserName", "SubjectUserName", "AccountName", "User"],
        "source_ip": ["IpAddress", "ClientAddress"],
        "observer_name": ["Hostname", "HostName"],
        "host_name": ["Hostname", "HostName"],
        "service_name": ["ProviderName", "SourceName", "Channel"],
        "message": ["Message", "message"],
        "event_severity": ["Severity"],
    },
    # Linux ログ（NXLog: syslog/journald。認証の user/IP は Message 内なので下で抽出）
    "linux": {
        "observer_name": ["Hostname"],
        "host_name": ["Hostname"],
        "service_name": ["ProcessName", "SourceName", "SystemdUnit"],
        "actor_user": ["User"],
        "message": ["Message", "message"],
        "event_severity": ["Severity"],
    },
}

_RE_FOR_USER = re.compile(r"for (?:invalid user )?(?P<user>[\w.\-@$]+)")
_RE_AUTH_USER = re.compile(r"(?:authenticating user|disconnected from(?: authenticating)?|Accepted \S+ for) (?P<user>[\w.\-@$]+)")
# LiteSpeed等は PHP の stderr を [NOTICE] で包むので、本文の "PHP Warning/Fatal/Notice" から重大度を取る
_RE_PHP = re.compile(r"PHP (Warning|Fatal error|Parse error|Notice|Deprecated|Recoverable fatal error)", re.I)


def _php_level(text: str) -> tuple[str | None, str | None]:
    m = _RE_PHP.search(text or "")
    if not m:
        return None, None
    lvl = m.group(1).lower()
    if "fatal" in lvl or "parse" in lvl:
        return "error", "php_error"
    if "warning" in lvl:
        return "warning", "php_warning"
    return "notice", "php_notice"

# source（取り込み元）ごとの表示名/機器名。ログにも設定にも無い機器名は作らない（§4）。
# device_name はログに在ればそれを優先し、ここは設定値(source_config相当)のフォールバック。
SOURCE_CONFIG: dict[str, dict[str, str | None]] = {
    "yamaha": {"source_name": "YAMAHAルーター", "device_name": "YAMAHAルーター"},
    "nas": {"source_name": "NAS nas-01", "device_name": "nas-01"},
    "litespeed": {"source_name": None, "device_name": None},  # Web: source_name=ドメイン(vhost)
    "google_workspace": {"source_name": "Google Workspace", "device_name": None},
}

PARSER_VERSION = "0.1"

_AUTH_FAIL = ("fail", "failed", "failure", "denied", "invalid", "wrong_password", "no_such_user")
_AUTH_OK = ("succeeded", "accepted", "success", "opened")


def _first(payload: dict, keys: list[str]) -> Any:
    for k in keys:
        v = payload.get(k)
        if v not in (None, ""):
            return v
    return None


def _category_extras(source_type: str, payload: dict, norm: dict) -> None:
    """source_type ごとの category/action/result/protocol などの導出。"""
    if source_type == "web_access":
        norm["event_category"] = "web"
        norm["event_action"] = "http_request"
        status = norm.get("http_status_code")
        if status and status.isdigit():
            norm["event_result"] = "failure" if int(status) >= 400 else "success"
        else:
            norm["event_result"] = "unknown"

    elif source_type == "web_error":
        norm["event_category"] = "application"
        norm["event_type"] = "error"
        norm["event_result"] = "unknown"
        sev, act = _php_level(str(payload.get("message") or payload.get("raw") or ""))
        norm["event_action"] = act or "app_error"
        if sev:  # 本文が "PHP Warning/Fatal/Notice" なら包みの[NOTICE]より本文を優先
            norm["event_severity"] = sev

    elif source_type == "application":
        norm["event_category"] = "application"
        norm["event_result"] = "unknown"
        sev, act = _php_level(str(payload.get("message") or payload.get("raw") or ""))
        norm["event_action"] = act or "app_event"
        if sev:
            norm["event_severity"] = sev

    elif source_type == "google_workspace_audit":
        norm["event_category"] = "audit"
        norm["event_result"] = "unknown"

    elif source_type == "router":
        norm["event_category"] = "network"
        tag = str(payload.get("tag") or "").upper()
        msg = str(payload.get("message") or "")
        if "DHCP" in tag:
            norm["event_action"] = "dhcp"
            norm["network_protocol"] = "DHCP"
            norm["network_transport"] = "UDP"
        elif "IKE" in tag:
            norm["event_action"] = "ike"
            norm["network_protocol"] = "IKE"
            norm["network_transport"] = "UDP"
        else:
            norm["event_action"] = (tag.lower() or None)
        norm["event_result"] = "unknown"
        norm["source_ip"] = extractors.extract_ip(msg)
        norm["mac_address"] = extractors.extract_mac(msg)

    elif source_type == "nas":
        norm["event_category"] = "system"
        norm["event_result"] = "unknown"

    elif source_type == "auth":
        norm["event_category"] = "authentication"
        text = str(payload.get("raw") or payload.get("message") or "").lower()
        if any(k in text for k in _AUTH_FAIL):
            norm["event_action"], norm["event_result"] = "login_failed", "failure"
        elif any(k in text for k in _AUTH_OK):
            norm["event_action"], norm["event_result"] = "login_success", "success"
        else:
            norm["event_result"] = "unknown"

    elif source_type == "mail":
        norm["event_category"] = "mail"
        status = str(payload.get("Status") or "").lower()
        norm["event_action"] = payload.get("Status") or payload.get("Component") or "mail"
        if status in ("sent", "delivered"):
            norm["event_result"] = "success"
        elif status in ("bounced", "deferred", "reject", "rejected", "failed"):
            norm["event_result"] = "failure"
        else:
            norm["event_result"] = "unknown"

    elif source_type == "linux":
        msg = str(payload.get("Message") or payload.get("message") or "")
        low = msg.lower()
        proc = str(payload.get("ProcessName") or payload.get("SourceName") or "").lower()
        is_auth = ("sshd" in proc or "sudo" in proc or any(k in low for k in (
            "accepted ", "failed password", "invalid user", "authentication failure",
            "session opened", "session closed", "[preauth]", "authenticating user",
            "disconnected from authenticating", "too many authentication")))
        if is_auth:
            norm["event_category"] = "authentication"
            ip = extractors.extract_ip(msg)
            if ip:
                norm.setdefault("source_ip", ip)
            m = _RE_FOR_USER.search(msg) or _RE_AUTH_USER.search(msg)
            if m:
                norm.setdefault("actor_user", m.group("user"))
            if any(k in low for k in ("accepted", "session opened")):
                norm["event_action"], norm["event_result"] = "login_success", "success"
            elif any(k in low for k in (
                    "failed password", "invalid user", "authentication failure",
                    "connection closed by authenticating", "[preauth]",
                    "disconnected from authenticating", "too many authentication",
                    "no supported authentication", "connection reset by authenticating")):
                norm["event_action"], norm["event_result"] = "login_failed", "failure"
                if norm.get("actor_user") == "root":
                    norm["event_severity"] = "warning"
            else:
                norm["event_result"] = "unknown"
        else:
            norm["event_category"] = "system"
            norm["event_result"] = "unknown"

    elif source_type == "windows_event":
        channel = str(payload.get("Channel") or "").lower()
        norm["event_category"] = "security" if channel == "security" else "system"
        eid = payload.get("EventID")
        norm["event_action"] = f"event_{eid}" if eid is not None else None
        if str(eid) == "4624":
            norm["event_result"] = "success"      # ログオン成功
        elif str(eid) == "4625":
            norm["event_result"] = "failure"      # ログオン失敗
        else:
            norm["event_result"] = "unknown"


_RE_VHOST = re.compile(r"/var/vhost/([^/]+)/")
_RE_WSGI = re.compile(r"wsgi:([^:\]]+)")


def _extract_domain(payload: dict) -> str | None:
    for k in ("vhost", "domain", "url_domain"):
        if payload.get(k):
            return str(payload[k])
    text = str(payload.get("context") or payload.get("raw") or payload.get("message") or "")
    m = _RE_VHOST.search(text) or _RE_WSGI.search(text)
    return m.group(1) if m else None


def _identity(source: str | None, source_type: str | None, payload: dict, norm: dict) -> None:
    """ログソース名/機器名/ドメインを決める（§4,§7-9）。ログにも設定にも無い名前は作らない。"""
    cfg = SOURCE_CONFIG.get(source or "", {})
    is_web = source_type in ("web_access", "web_error", "application")

    # ドメイン(vhost): Webは必ず出す
    if is_web and not norm.get("url_domain"):
        dom = _extract_domain(payload)
        if dom:
            norm["url_domain"] = dom

    # ホスト/機器: payload優先 → 既存observer → 設定値。無ければ None（画面で - / Unknown）
    device = (payload.get("device_name") or payload.get("hostname") or payload.get("host")
              or norm.get("observer_name") or cfg.get("device_name"))
    norm["device_name"] = str(device) if device else None
    if payload.get("host"):
        norm.setdefault("observer_name", str(payload["host"]))
        norm.setdefault("host_name", str(payload["host"]))

    # ログソース名: Webはドメイン、それ以外は設定名 → 機器名 → source
    if is_web:
        norm["source_name"] = norm.get("url_domain") or cfg.get("source_name") or norm.get("device_name") or source or "Unknown"
    else:
        norm["source_name"] = cfg.get("source_name") or norm.get("device_name") or norm.get("url_domain") or source or "Unknown"


def normalize(payload: dict, source: str | None, source_type: str | None) -> tuple[dict, str]:
    """payload を正規化フィールド dict にする。戻り: (norm, parse_status)。"""
    norm: dict[str, Any] = {}
    st = source_type or "unknown"

    # 1) mapping による直接コピー（値は文字列化して保持・改変しない）
    for field, keys in MAPPINGS.get(st, {}).items():
        v = _first(payload, keys)
        if v is not None:
            norm[field] = str(v)

    # 2) event_time（派生・confidence付き）
    dt, original, conf = resolve_time(payload)
    norm["event_time"] = dt
    norm["event_time_original"] = original
    norm["event_time_confidence"] = conf

    # 3) HTTPリクエスト分解（request文字列がある場合のみ。直接マップ済みの値は上書きしない）
    if norm.get("request"):
        for k, v in extractors.parse_http_request(norm["request"]).items():
            norm.setdefault(k, v)

    # 4) 種別ごとの分類
    _category_extras(st, payload, norm)

    # 5) ログソース名/機器名/ドメインの決定（推定しない）
    _identity(source, st, payload, norm)

    # 6) message フォールバック（無ければ payload の raw/message）
    if not norm.get("message"):
        norm["message"] = payload.get("message") or payload.get("raw")

    # parse_status: 何も拾えなければ partial
    meaningful = any(norm.get(k) for k in ("event_time", "source_ip", "actor_user", "event_action", "message"))
    return norm, ("success" if meaningful else "partial")
