"""REST ingest（PROJECT.md §5.1, §11.1）。受信JSONを payload として保存し pipeline に流す。
本文は無改変。source/source_type は付帯メタ。不正JSONは dead_letter へ。

本文は JSON（1件 or 配列）に加え、NDJSON（1行1JSON）も受け付ける。HTTPS(443)経由で
TCP 516 と同じ送り方ができるようにするため（NXLog om_http のバッチ送信等）。
source / source_type は URL（クエリ/パス）指定を優先し、無ければ各レコードの JSON 内の
値を使う（TCP 受信と同じキー: source / _source, source_type / _source_type）。"""
import json
import logging
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from . import auth as A
from .config import settings
from .db import get_db
from .ingest_stats import record_bytes
from .pipeline import dead_letter, ingest_one
from .schema import IngestResponse

log = logging.getLogger("ingest")
router = APIRouter()

_NDJSON_TYPES = {
    "application/x-ndjson", "application/ndjson",
    "application/jsonl", "application/x-jsonlines", "application/jsonlines",
}


def require_token(authorization: str | None = Header(default=None)) -> None:
    if not settings.auth_enabled:
        return
    # 比較はタイミング攻撃対策で定数時間（トークン長の推測を防ぐ）
    if not secrets.compare_digest(authorization or "", f"Bearer {settings.INGEST_TOKEN}"):
        raise HTTPException(status_code=401, detail="invalid or missing token")


def _split_records(text: str, content_type: str) -> tuple[list, list[tuple[str, str]]]:
    """本文をレコード列に分解する。戻り値は (レコード, 不正行[(行, エラー)])。
    NDJSON の Content-Type なら行単位。それ以外は JSON 全体として読み、
    「1件目の後ろに続きがある」(Extra data) 場合だけ NDJSON とみなす
    （Content-Type を application/json のまま複数行を送る実装があるため）。
    それ以外の不正JSONは JSONDecodeError をそのまま送出する。"""
    if content_type.split(";")[0].strip().lower() not in _NDJSON_TYPES:
        try:
            payload = json.loads(text)
            return (payload if isinstance(payload, list) else [payload]), []
        except json.JSONDecodeError as e:
            if e.msg != "Extra data":
                raise
    records, bad = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as e:
            bad.append((line, str(e)))
    return records, bad


def _meta(rec: dict, *keys: str) -> str | None:
    for k in keys:
        v = rec.get(k)
        if isinstance(v, str) and v:
            return v
    return None


async def _ingest(request: Request, db: Session, source: str | None, source_type: str | None):
    body = await request.body()
    if len(body) > settings.MAX_INGEST_BYTES:
        raise HTTPException(status_code=413, detail="payload too large")
    client_ip = A.client_ip(request)
    text = body.decode("utf-8-sig", "replace")
    try:
        records, bad = _split_records(text, request.headers.get("content-type", ""))
    except json.JSONDecodeError as e:
        records, bad = [], [(text, str(e))]
    if not records and bad:
        # 1件も読めなければ従来通り本文全体を dead_letter にして 400
        dead_letter(db, text, "invalid_json", bad[0][1],
                    channel="api", source=source, source_type=source_type, receiver_ip=client_ip)
        db.commit()
        record_bytes(len(body), source=source)
        raise HTTPException(status_code=400, detail="invalid JSON")

    stored = skipped = 0
    detail: list[str] = []
    bytes_source = source
    for line, err in bad:  # NDJSON の不正行だけ個別に dead_letter（他の行は取り込む）
        dead_letter(db, line[:4096], "invalid_json", err,
                    channel="api", source=source, source_type=source_type, receiver_ip=client_ip)
        skipped += 1
        detail.append(f"invalid line: {err}")
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            rec = {"value": rec}
        src = source or _meta(rec, "source", "_source")
        stype = source_type or _meta(rec, "source_type", "_source_type")
        bytes_source = bytes_source or src
        try:
            ingest_one(db, rec, source=src, source_type=stype, channel="api", receiver_ip=client_ip)
            stored += 1
        except Exception as e:  # 想定外でも他レコードは継続
            skipped += 1
            detail.append(f"record[{i}]: {e}")
    db.commit()
    # 転送量記録は本来の取り込みと切り離す（1リクエスト=受信body全体のバイト数として1件記録）。
    record_bytes(len(body), source=bytes_source)
    return IngestResponse(accepted=len(records) + len(bad), stored=stored, skipped=skipped, detail=detail)


@router.post("/ingest", response_model=IngestResponse)
async def ingest(request: Request, source: str | None = None, source_type: str | None = None,
                 db: Session = Depends(get_db), _: None = Depends(require_token)):
    return await _ingest(request, db, source, source_type)


# /ingest/{source} より先に定義する（後だと "bulk" が source 名として先に一致してしまう）
@router.post("/ingest/bulk", response_model=IngestResponse)
async def ingest_bulk(request: Request, source: str | None = None, source_type: str | None = None,
                      db: Session = Depends(get_db), _: None = Depends(require_token)):
    return await _ingest(request, db, source, source_type)


@router.post("/ingest/{source}", response_model=IngestResponse)
async def ingest_source(source: str, request: Request, source_type: str | None = None,
                        db: Session = Depends(get_db), _: None = Depends(require_token)):
    return await _ingest(request, db, source, source_type)
