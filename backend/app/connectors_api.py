"""外部連携（コネクタ）の設定画面用API。現在は Microsoft 365 監査ログのみ（m365_connector.py）。
テナントID等も設定の一部なので、参照もシステム管理者に限る。クライアントシークレットは返さない。"""
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import audit_log as L
from . import m365_connector as M
from .auth import require_sysadmin
from .db import get_db

router = APIRouter(prefix="/api/connectors")


class M365Config(BaseModel):
    enabled: bool = False
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str | None = None   # 空なら既存のまま
    content_types: list[str] = []
    interval_min: int = M.DEFAULT_INTERVAL_MIN


@router.get("/m365")
def m365_status(db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    return M.status(db)


@router.put("/m365")
def m365_save(request: Request, body: M365Config, db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    changes = M.save_config(db, body.model_dump())
    L.note(request, "connector.m365", target="Microsoft 365", detail=L.join(changes, "変更なし"))
    return M.status(db)


@router.post("/m365/test")
def m365_test(request: Request, db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    res = M.test_connection(db)
    L.note(request, "connector.m365_test", target="Microsoft 365", detail=res["message"],
           status="success" if res["ok"] else "failure")
    return res


@router.post("/m365/run")
def m365_run(request: Request, db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    started = M.run_in_background()
    L.note(request, "connector.m365_run", target="Microsoft 365",
           detail="取得を開始" if started else "取得中のため開始しなかった")
    return {"started": started}
