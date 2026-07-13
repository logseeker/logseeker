"""REST ingest（PROJECT.md §5.1, §11.1）。受信JSONを payload として保存し pipeline に流す。
本文は無改変。source/source_type は付帯メタ。不正JSONは dead_letter へ。"""
import json
import logging
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .ingest_stats import record_bytes
from .pipeline import dead_letter, ingest_one
from .schema import IngestResponse

log = logging.getLogger("ingest")
router = APIRouter()


def require_token(authorization: str | None = Header(default=None)) -> None:
    if not settings.auth_enabled:
        return
    # 比較はタイミング攻撃対策で定数時間（トークン長の推測を防ぐ）
    if not secrets.compare_digest(authorization or "", f"Bearer {settings.INGEST_TOKEN}"):
        raise HTTPException(status_code=401, detail="invalid or missing token")


async def _ingest(request: Request, db: Session, source: str | None, source_type: str | None):
    body = await request.body()
    if len(body) > settings.MAX_INGEST_BYTES:
        raise HTTPException(status_code=413, detail="payload too large")
    client_ip = request.client.host if request.client else None
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as e:
        dead_letter(db, body.decode("utf-8", "replace"), "invalid_json", str(e),
                    channel="api", source=source, source_type=source_type, receiver_ip=client_ip)
        db.commit()
        record_bytes(len(body), source=source)
        raise HTTPException(status_code=400, detail="invalid JSON")

    records = payload if isinstance(payload, list) else [payload]
    stored = skipped = 0
    detail: list[str] = []
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            rec = {"value": rec}
        try:
            ingest_one(db, rec, source=source, source_type=source_type, channel="api", receiver_ip=client_ip)
            stored += 1
        except Exception as e:  # 想定外でも他レコードは継続
            skipped += 1
            detail.append(f"record[{i}]: {e}")
    db.commit()
    # 転送量記録は本来の取り込みと切り離す（1リクエスト=受信body全体のバイト数として1件記録）。
    record_bytes(len(body), source=source)
    return IngestResponse(accepted=len(records), stored=stored, skipped=skipped, detail=detail)


@router.post("/ingest", response_model=IngestResponse)
async def ingest(request: Request, source: str | None = None, source_type: str | None = None,
                 db: Session = Depends(get_db), _: None = Depends(require_token)):
    return await _ingest(request, db, source, source_type)


@router.post("/ingest/{source}", response_model=IngestResponse)
async def ingest_source(source: str, request: Request, source_type: str | None = None,
                        db: Session = Depends(get_db), _: None = Depends(require_token)):
    return await _ingest(request, db, source, source_type)


@router.post("/ingest/bulk", response_model=IngestResponse)
async def ingest_bulk(request: Request, source: str | None = None, source_type: str | None = None,
                      db: Session = Depends(get_db), _: None = Depends(require_token)):
    return await _ingest(request, db, source, source_type)
