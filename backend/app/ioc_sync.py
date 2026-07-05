"""脅威インテリフィード同期（AbuseIPDB / AlienVault OTX）→ ローカル ioc テーブルへ取り込み。
突合は従来どおりローカル（高速・突合時オフライン）。外部APIは指標の取得にのみ使う。"""
import ipaddress
import json
import logging
import re
import urllib.request

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import IOC, IocFeed, Setting

log = logging.getLogger("ioc_sync")
DEFAULT_SYNC_HOURS = 6
_DOMAIN = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def _http(url: str, headers: dict, timeout: int = 30) -> dict:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _detect(v: str) -> str | None:
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        return "domain" if _DOMAIN.match(v) else None


def _refresh_source(db: Session, source: str, indicators: list[tuple[str, str]]) -> int:
    """source の既存IOCを置き換え（全更新）。indicators=[(type,value),...]"""
    db.query(IOC).filter(IOC.source == source).delete()
    seen = set()
    n = 0
    for itype, value in indicators:
        if not itype or not value or (itype, value) in seen:
            continue
        seen.add((itype, value))
        db.add(IOC(indicator_type=itype, value=value[:255], source=source, description=None))
        n += 1
    db.commit()
    return n


def sync_abuseipdb(db: Session, key: str, confidence: int = 90) -> tuple[int, str]:
    # https://docs.abuseipdb.com/#blacklist-endpoint
    data = _http("https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=%d" % confidence,
                 {"Key": key, "Accept": "application/json"})
    inds = [("ip", row["ipAddress"]) for row in data.get("data", []) if row.get("ipAddress")]
    return _refresh_source(db, "abuseipdb", inds), f"{len(inds)}件取得"


def sync_otx(db: Session, key: str, max_pages: int = 20) -> tuple[int, str]:
    # https://otx.alienvault.com/api/  購読パルスの指標を取得
    inds: list[tuple[str, str]] = []
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page=1"
    pages = 0
    while url and pages < max_pages:
        d = _http(url, {"X-OTX-API-KEY": key})
        for pulse in d.get("results", []):
            for ind in pulse.get("indicators", []):
                t = (ind.get("type") or "").lower()
                v = ind.get("indicator")
                if not v:
                    continue
                if t in ("ipv4", "ipv6"):
                    inds.append(("ip", v))
                elif t in ("domain", "hostname"):
                    inds.append(("domain", v))
        url = d.get("next")
        pages += 1
    return _refresh_source(db, "otx", inds), f"{len(inds)}件取得 ({pages}ページ)"


_SYNCERS = {"abuseipdb": sync_abuseipdb, "otx": sync_otx}


def sync_all(db: Session) -> list[dict]:
    """有効かつキー有りのフィードを同期。各結果を返す。"""
    from datetime import datetime, timezone
    results = []
    feeds = db.execute(select(IocFeed)).scalars().all()
    for feed in feeds:
        if not feed.enabled or not feed.api_key or feed.name not in _SYNCERS:
            continue
        try:
            count, status = _SYNCERS[feed.name](db, feed.api_key)
            feed.last_count, feed.last_status = count, status
        except Exception as e:  # noqa
            count, status = 0, f"エラー: {e}"
            feed.last_status = status
            log.warning("ioc sync %s failed: %s", feed.name, e)
        feed.last_synced_at = datetime.now(timezone.utc)
        db.commit()
        results.append({"name": feed.name, "count": count, "status": status})
    return results


def get_sync_hours(db: Session) -> int:
    row = db.get(Setting, "ioc_sync_hours")
    try:
        return int(row.value) if row and row.value else DEFAULT_SYNC_HOURS
    except (TypeError, ValueError):
        return DEFAULT_SYNC_HOURS


def ensure_feed_rows(db: Session) -> None:
    """abuseipdb / otx の行を用意（無ければ作成）。"""
    existing = {f.name for f in db.execute(select(IocFeed)).scalars().all()}
    for name in ("abuseipdb", "otx"):
        if name not in existing:
            db.add(IocFeed(name=name, enabled=False))
    db.commit()
