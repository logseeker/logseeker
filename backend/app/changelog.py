"""お知らせ・更新履歴（GitHub Releasesを一次情報源とする）。
GitHub APIから取得した結果を Setting テーブルへ JSON でキャッシュする（既定1時間）。
private repoの場合や未認証レート制限(60回/時)に達する場合は CHANGELOG_GITHUB_TOKEN を設定する。"""
import json
import logging
import time
import urllib.error
import urllib.request

from sqlalchemy.orm import Session

from .config import settings
from .models import Setting

log = logging.getLogger("changelog")

K_CACHE_JSON = "changelog_cache_json"
K_CACHE_AT = "changelog_cache_at"


def _get(db: Session, key: str) -> str | None:
    row = db.get(Setting, key)
    return row.value if (row and row.value is not None) else None


def _set(db: Session, key: str, value: str) -> None:
    row = db.get(Setting, key)
    if not row:
        row = Setting(key=key)
        db.add(row)
    row.value = value
    db.commit()


def _fetch_from_github() -> list[dict]:
    url = f"https://api.github.com/repos/{settings.CHANGELOG_REPO}/releases"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "LogSeeker-changelog"}
    if settings.CHANGELOG_GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.CHANGELOG_GITHUB_TOKEN}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read().decode("utf-8"))
    out = []
    for rel in data:
        if rel.get("draft"):
            continue
        out.append({
            "tag_name": rel.get("tag_name"),
            "name": rel.get("name") or rel.get("tag_name"),
            "body": rel.get("body") or "",
            "published_at": rel.get("published_at"),
            "html_url": rel.get("html_url"),
            "prerelease": bool(rel.get("prerelease")),
        })
    return out


def get_releases(db: Session, force: bool = False) -> list[dict]:
    """キャッシュ付きでリリース一覧を返す。GitHub取得に失敗した場合は、古いキャッシュがあればそれを返す
    （レート制限や一時的な通信障害でお知らせ機能全体が落ちないように）。"""
    now = time.time()
    cached_at = _get(db, K_CACHE_AT)
    cached_json = _get(db, K_CACHE_JSON)
    ttl = max(1, settings.CHANGELOG_CACHE_HOURS) * 3600

    if not force and cached_at and cached_json:
        try:
            if now - float(cached_at) < ttl:
                return json.loads(cached_json)
        except (TypeError, ValueError):
            pass

    try:
        releases = _fetch_from_github()
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        log.warning("failed to fetch GitHub releases (%s): %s", settings.CHANGELOG_REPO, e)
        if cached_json:
            return json.loads(cached_json)
        return []

    _set(db, K_CACHE_JSON, json.dumps(releases, ensure_ascii=False))
    _set(db, K_CACHE_AT, str(now))
    return releases
