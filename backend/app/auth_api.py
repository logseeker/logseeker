"""認証・ユーザー管理・監査ログのAPI。
ロール:
  viewer(user)   : 閲覧・ダウンロード
  editor         : + インシデント/コメントの作成・編集
  sysadmin(sudo) : + ライセンス/通知/IOC/API設定・監査閲覧・(viewer/editorの)ユーザー作成
  admin(root)    : + 全ユーザー管理・sudo/root への昇格・認証ON/OFF・SSO設定
"""
import csv
import io

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import auth as A
from .config import settings
from .db import get_db
from .models import AuditLog, User
from .schema import AuthToggle, LoginRequest, SSOConfig, UserCreate, UserUpdate

router = APIRouter(prefix="/api")


def _user_dict(u: User) -> dict:
    return {
        "id": u.id, "username": u.username, "display_name": u.display_name,
        "role": u.role, "role_label": A.ROLE_LABELS.get(u.role, u.role),
        "enabled": u.enabled, "is_sso": bool(u.sso_subject),
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
    }


# ---------------- 認証状態 / ログイン ----------------
@router.get("/auth/status")
def auth_status(user: User | None = Depends(A.get_current_user), db: Session = Depends(get_db)):
    """フロント初期化用。認証要否と現在ユーザー、SSO設定有無を返す。"""
    from .sso import sso_status
    return {
        "auth_required": A.is_auth_required(db),
        "user": _user_dict(user) if user else None,
        "roles": [{"value": k, "label": v} for k, v in A.ROLE_LABELS.items()],
        "sso": sso_status(db),
    }


@router.post("/auth/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else None
    u = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    if not u or not u.enabled or not A.verify_password(body.password, u.password_hash):
        A.audit(db, action="login", status="failure", username=body.username,
                method="POST", path="/api/auth/login", ip=ip,
                detail="認証失敗（ユーザー名またはパスワード不一致）")
        return Response(status_code=401, content='{"error":"ユーザー名またはパスワードが違います"}',
                        media_type="application/json")
    token = A.create_session(db, u)
    A.audit(db, action="login", status="success", user=u, method="POST",
            path="/api/auth/login", ip=ip)
    return {"token": token, "user": _user_dict(u)}


@router.post("/auth/logout")
def logout(request: Request, authorization: str | None = None,
           user: User | None = Depends(A.get_current_user), db: Session = Depends(get_db)):
    from fastapi import Header  # local import avoids shadowing
    auth = request.headers.get("authorization")
    token = A._bearer(auth)
    if token:
        A.destroy_session(db, token)
    if user:
        A.audit(db, action="logout", status="success", user=user,
                ip=request.client.host if request.client else None)
    return {"ok": True}


@router.get("/auth/me")
def me(user: User | None = Depends(A.get_current_user)):
    return _user_dict(user) if user else {"user": None}


# ---------------- ユーザー管理 ----------------
def _can_manage_target_role(actor: User | None, target_role: str, db: Session) -> bool:
    """sysadmin は viewer/editor のみ管理可。admin は全ロール可。認証OFF時は全許可。"""
    if not A.is_auth_required(db):
        return True
    if not actor:
        return False
    if actor.role == "admin":
        return True
    if actor.role == "sysadmin":
        return target_role in ("viewer", "editor")
    return False


@router.get("/users")
def list_users(_: User | None = Depends(A.require_sysadmin), db: Session = Depends(get_db)):
    rows = db.execute(select(User).order_by(User.id)).scalars().all()
    return [_user_dict(u) for u in rows]


@router.post("/users")
def create_user(body: UserCreate, request: Request,
                actor: User | None = Depends(A.require_sysadmin), db: Session = Depends(get_db)):
    if body.role not in A.ROLES:
        return Response(status_code=400, content='{"error":"不正なロール"}', media_type="application/json")
    if not _can_manage_target_role(actor, body.role, db):
        return Response(status_code=403, content='{"error":"そのロールのユーザーを作成する権限がありません"}',
                        media_type="application/json")
    if db.execute(select(User).where(User.username == body.username)).scalar_one_or_none():
        return Response(status_code=409, content='{"error":"同名のユーザーが既に存在します"}',
                        media_type="application/json")
    u = User(username=body.username, display_name=body.display_name, role=body.role,
             password_hash=A.hash_password(body.password), enabled=True)
    db.add(u)
    db.commit()
    A.audit(db, action="user.create", user=actor, target=body.username,
            detail=f"role={body.role}", ip=request.client.host if request.client else None)
    return _user_dict(u)


@router.put("/users/{user_id}")
def update_user(user_id: int, body: UserUpdate, request: Request,
                actor: User | None = Depends(A.require_sysadmin), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u:
        return Response(status_code=404, content='{"error":"not found"}', media_type="application/json")
    # 対象の現ロール・新ロール双方に対する管理権限が必要
    if not _can_manage_target_role(actor, u.role, db):
        return Response(status_code=403, content='{"error":"このユーザーを編集する権限がありません"}',
                        media_type="application/json")
    changes = []
    if body.role is not None and body.role != u.role:
        if body.role not in A.ROLES:
            return Response(status_code=400, content='{"error":"不正なロール"}', media_type="application/json")
        if not _can_manage_target_role(actor, body.role, db):
            return Response(status_code=403, content='{"error":"そのロールへ変更する権限がありません"}',
                            media_type="application/json")
        changes.append(f"role:{u.role}->{body.role}")
        u.role = body.role
    if body.display_name is not None:
        u.display_name = body.display_name
    if body.enabled is not None:
        # 自分自身は無効化させない（ロックアウト防止）
        if u.id == (actor.id if actor else None) and not body.enabled:
            return Response(status_code=400, content='{"error":"自分自身は無効化できません"}',
                            media_type="application/json")
        if u.enabled != body.enabled:
            changes.append(f"enabled:{u.enabled}->{body.enabled}")
        u.enabled = body.enabled
    if body.password:
        u.password_hash = A.hash_password(body.password)
        changes.append("password reset")
    db.commit()
    A.audit(db, action="user.update", user=actor, target=u.username,
            detail=", ".join(changes) or "no change",
            ip=request.client.host if request.client else None)
    return _user_dict(u)


@router.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request,
                actor: User | None = Depends(A.require_sysadmin), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u:
        return Response(status_code=404, content='{"error":"not found"}', media_type="application/json")
    if actor and u.id == actor.id:
        return Response(status_code=400, content='{"error":"自分自身は削除できません"}', media_type="application/json")
    if not _can_manage_target_role(actor, u.role, db):
        return Response(status_code=403, content='{"error":"このユーザーを削除する権限がありません"}',
                        media_type="application/json")
    # 最後の admin を消さない
    if u.role == "admin":
        admins = db.execute(select(User).where(User.role == "admin", User.enabled == True)).scalars().all()  # noqa: E712
        if len([a for a in admins if a.id != u.id]) == 0:
            return Response(status_code=400, content='{"error":"最後の管理者(root)は削除できません"}',
                            media_type="application/json")
    uname = u.username
    db.delete(u)
    db.commit()
    A.audit(db, action="user.delete", user=actor, target=uname,
            ip=request.client.host if request.client else None)
    return {"ok": True}


# ---------------- 認証ON/OFF（admin専用） ----------------
@router.post("/auth/require")
def toggle_auth(body: AuthToggle, request: Request,
                actor: User | None = Depends(A.require_admin), db: Session = Depends(get_db)):
    # ON にするなら admin が最低1人必要（ロックアウト防止）
    if body.enabled:
        has_admin = db.execute(select(User.id).where(User.role == "admin", User.enabled == True)).first()  # noqa: E712
        if not has_admin:
            return Response(status_code=400,
                            content='{"error":"管理者(root)が存在しないため有効化できません"}',
                            media_type="application/json")
    A.set_auth_required(db, body.enabled)
    A.audit(db, action="auth.toggle", user=actor, detail=f"auth_required={body.enabled}",
            ip=request.client.host if request.client else None)
    return {"ok": True, "auth_required": body.enabled}


# ---------------- SSO 設定（admin専用・実接続は未実装） ----------------
@router.get("/sso")
def get_sso(_: User | None = Depends(A.require_admin), db: Session = Depends(get_db)):
    from .sso import sso_status
    return sso_status(db)


@router.put("/sso")
def save_sso(body: SSOConfig, request: Request,
             actor: User | None = Depends(A.require_admin), db: Session = Depends(get_db)):
    from .sso import save_sso_config
    save_sso_config(db, body.model_dump())
    A.audit(db, action="sso.config", user=actor, detail=f"enabled={body.enabled}, issuer={body.issuer}",
            ip=request.client.host if request.client else None)
    return {"ok": True, "note": "設定を保存しました（実接続は現バージョン未実装。設計・保管のみ）"}


# ---------------- 監査ログ（sysadmin以上） ----------------
@router.get("/audit")
def list_audit(_: User | None = Depends(A.require_sysadmin), db: Session = Depends(get_db),
               limit: int = 500):
    rows = db.execute(select(AuditLog).order_by(AuditLog.at.desc()).limit(min(limit, 2000))).scalars().all()
    return {
        "total": db.scalar(select(func.count()).select_from(AuditLog)),
        "items": [{
            "id": a.id, "at": a.at.isoformat() if a.at else None,
            "username": a.username, "role": a.role, "action": a.action,
            "method": a.method, "path": a.path, "status": a.status,
            "target": a.target, "detail": a.detail, "ip": a.ip,
        } for a in rows],
    }


@router.get("/audit.csv")
def audit_csv(request: Request, actor: User | None = Depends(A.require_sysadmin), db: Session = Depends(get_db)):
    rows = db.execute(select(AuditLog).order_by(AuditLog.at.desc())).scalars().all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["日時", "ユーザー", "ロール", "操作", "メソッド", "パス", "結果", "対象", "詳細", "IP"])
    for a in rows:
        w.writerow([a.at.isoformat() if a.at else "", a.username or "", a.role or "", a.action,
                    a.method or "", a.path or "", a.status or "", a.target or "", a.detail or "", a.ip or ""])
    A.audit(db, action="audit.download", user=actor, ip=request.client.host if request.client else None)
    data = "﻿" + buf.getvalue()
    return Response(content=data, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=logseeker_audit.csv"})
