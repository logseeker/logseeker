"""お知らせ・更新履歴。リリースノートは同梱の releases.json（新しい順）を読む。

以前は GitHub Releases を API で取りに行っていたが、リポジトリの非公開化に備えて同梱方式にした。
リリースノートはコードと一緒に届くので、外部への通信・トークン・レート制限が要らない。
ファイルは backend/tools/release_notes.py でタグを打つ前に追記する。"""
import json
import logging
from pathlib import Path

from sqlalchemy.orm import Session

log = logging.getLogger("changelog")

NOTES = Path(__file__).with_name("releases.json")
_cache: dict = {"mtime": None, "data": []}


def get_releases(db: Session | None = None, force: bool = False) -> list[dict]:
    """リリースノートを新しい順で返す。ファイルが更新されたら（git pull 後など）読み直す。
    db / force は以前の呼び出し方との互換のために残している（使わない）。"""
    try:
        mtime = NOTES.stat().st_mtime
    except FileNotFoundError:
        log.warning("release notes not found: %s", NOTES)
        return []
    if _cache["mtime"] != mtime:
        try:
            data = json.loads(NOTES.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            log.warning("failed to read release notes %s: %s", NOTES, e)
            return _cache["data"]
        _cache.update(mtime=mtime, data=[{
            "tag_name": r.get("tag_name"),
            "name": r.get("name") or r.get("tag_name"),
            "body": r.get("body") or "",
            "published_at": r.get("published_at"),
            "prerelease": bool(r.get("prerelease")),
        } for r in data if r.get("tag_name")])
    return _cache["data"]
