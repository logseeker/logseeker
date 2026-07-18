"""GeoIP 国コード・ASN付与。MaxMind GeoLite2-Country / GeoLite2-ASN (mmdb) があれば使用、無ければ null。
OS非依存・オフライン。mmdb はライセンス物なので後から差し込む運用。"""
import ipaddress
import logging
from functools import lru_cache
from pathlib import Path

from .config import settings

log = logging.getLogger("geoip")

try:
    import geoip2.database  # type: ignore
    _GEOIP2_AVAILABLE = True
except Exception:  # pragma: no cover
    _GEOIP2_AVAILABLE = False


@lru_cache(maxsize=1)
def _reader():
    """Country mmdb リーダを遅延生成。存在しなければ None。"""
    if not _GEOIP2_AVAILABLE:
        return None
    path = Path(settings.GEOIP_DB_PATH)
    if not path.exists():
        log.warning("GeoIP mmdb not found at %s -> country will be null", path)
        return None
    try:
        return geoip2.database.Reader(str(path))
    except Exception as e:  # pragma: no cover
        log.warning("Failed to open GeoIP mmdb: %s", e)
        return None


@lru_cache(maxsize=1)
def _asn_reader():
    """ASN mmdb リーダを遅延生成。存在しなければ None。"""
    if not _GEOIP2_AVAILABLE:
        return None
    path = Path(settings.GEOIP_ASN_DB_PATH)
    if not path.exists():
        log.warning("GeoIP ASN mmdb not found at %s -> asn will be null", path)
        return None
    try:
        return geoip2.database.Reader(str(path))
    except Exception as e:  # pragma: no cover
        log.warning("Failed to open GeoIP ASN mmdb: %s", e)
        return None


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # パースできないものは国判定しない


def country_of(ip: str | None) -> str | None:
    """IPからISO国コードを返す。不明・プライベート・mmdb無しは None。"""
    if not ip or _is_private(ip):
        return None
    reader = _reader()
    if reader is None:
        return None
    try:
        return reader.country(ip).country.iso_code  # 例: "JP", "CN"
    except Exception:
        return None


def asn_of(ip: str | None) -> tuple[int | None, str | None]:
    """IPから (AS番号, 組織名) を返す。不明・プライベート・mmdb無しは (None, None)。"""
    if not ip or _is_private(ip):
        return None, None
    reader = _asn_reader()
    if reader is None:
        return None, None
    try:
        r = reader.asn(ip)
        return r.autonomous_system_number, r.autonomous_system_organization
    except Exception:
        return None, None
