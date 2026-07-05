"""ログ種別に依存しない汎用抽出（PROJECT.md §10.2）。値は payload から取り出すだけ・改変しない。"""
import re

_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{0,4}\b")
_RE_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
_RE_HTTP_REQ = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<target>\S+)(?:\s+(?P<proto>\S+))?$")


def extract_ip(text: str) -> str | None:
    if not text:
        return None
    m = _RE_IPV4.search(text)
    if m:
        return m.group(0)
    m = _RE_IPV6.search(text)
    return m.group(0) if m else None


def extract_mac(text: str) -> str | None:
    m = _RE_MAC.search(text or "")
    return m.group(0) if m else None


def parse_http_request(request: str) -> dict:
    """'GET /a/b?x=1 HTTP/2' → {http_method, url_path, url_query}。"""
    out: dict = {}
    m = _RE_HTTP_REQ.match((request or "").strip())
    if not m:
        return out
    out["http_method"] = m.group("method")
    target = m.group("target") or ""
    if "?" in target:
        path, query = target.split("?", 1)
        out["url_path"] = path
        out["url_query"] = query
    else:
        out["url_path"] = target
    return out
