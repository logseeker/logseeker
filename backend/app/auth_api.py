"""認証・ユーザー管理・監査ログのAPI。
ロール:
  viewer(user)   : 閲覧・ダウンロード
  editor         : + インシデント/コメントの作成・編集
  sysadmin(sudo) : + ライセンス/通知/IOC/API設定・監査閲覧・(viewer/editorの)ユーザー作成
  admin(root)    : + 全ユーザー管理・sudo/root への昇格・認証ON/OFF・SSO設定
"""
import csv
import io
import json

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import auth as A
from . import audit_log as L
from .db import get_db
from .models import AuditLog, User
from .schema import AuthToggle, IpRestrictSave, LoginRequest, SSOConfig, UserCreate, UserUpdate

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
    ip = A.client_ip(request)
    u = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    # ユーザー名の存在有無で応答時間に差が出ない（タイミングでの存在推測を防ぐ）よう、
    # 存在しない場合もverify_password自体は必ず呼ぶ（or の短絡評価をしない）。
    pw_ok = A.verify_password(body.password, u.password_hash if u else None)
    if not u or not u.enabled or not pw_ok:
        A.audit(db, action="login", status="failure", username=body.username,
                method="POST", path="/api/auth/login", ip=ip,
                detail="認証失敗（ユーザー名またはパスワード不一致）")
        return Response(status_code=401, content='{"error":"ユーザー名またはパスワードが違います"}',
                        media_type="application/json")
    token = A.create_session(db, u)
    A.audit(db, action="login", status="success", user=u, method="POST",
            path="/api/auth/login", ip=ip)
    return {"token": token, "user": _user_dict(u)}


@router.post("/auth/admin-login")
def admin_login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """通常ログインとは別の入口。管理者(admin)ロール以外は、パスワードが正しくてもここでは
    ログインさせない（『ログイン後の通常画面』とは分離した管理パネル専用の入口のため）。"""
    ip = A.client_ip(request)
    u = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    # ユーザー名の存在有無で応答時間に差が出ない（タイミングでの存在推測を防ぐ）よう、
    # 存在しない場合もverify_password自体は必ず呼ぶ（or の短絡評価をしない）。
    pw_ok = A.verify_password(body.password, u.password_hash if u else None)
    if not u or not u.enabled or not pw_ok:
        A.audit(db, action="login.admin", status="failure", username=body.username,
                method="POST", path="/api/auth/admin-login", ip=ip,
                detail="認証失敗（ユーザー名またはパスワード不一致）")
        return Response(status_code=401, content='{"error":"ユーザー名またはパスワードが違います"}',
                        media_type="application/json")
    if u.role != "admin":
        A.audit(db, action="login.admin", status="failure", user=u, method="POST",
                path="/api/auth/admin-login", ip=ip, detail="role不足（管理者(admin)以外は拒否）")
        return Response(status_code=403, content='{"error":"この画面は管理者(admin)アカウントのみ利用できます"}',
                        media_type="application/json")
    token = A.create_session(db, u)
    A.audit(db, action="login.admin", status="success", user=u, method="POST",
            path="/api/auth/admin-login", ip=ip)
    return {"token": token, "user": _user_dict(u)}


@router.get("/auth/admin-status")
def admin_status(user: User | None = Depends(A.get_current_user)):
    """管理パネル(?screen=administration)が「既存セッションがadminか」を確認する専用エンドポイント。

    /api/auth/status ではなくこれを使う理由: /api/auth/status はアプリ全体で使う汎用エンドポイントで
    IPアクセス制限の対象に出来ない（対象にすると通常アプリまで巻き込んでしまう）。この専用エンドポイントは
    ip_restrict.PROTECTED_PREFIXES に含めているため、IP制限が有効な時に許可外IPからは403になり、
    「既にadminセッションを持っているのでログイン試行を経由せず管理パネルに入れてしまう」抜け道を防ぐ。
    """
    if user and user.role == "admin":
        return {"user": _user_dict(user)}
    return {"user": None}


@router.post("/auth/logout")
def logout(request: Request, authorization: str | None = None,
           user: User | None = Depends(A.get_current_user), db: Session = Depends(get_db)):
    auth = request.headers.get("authorization")
    token = A._bearer(auth)
    if token:
        A.destroy_session(db, token)
    if user:
        A.audit(db, action="logout", status="success", user=user,
                ip=A.client_ip(request))
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

    from .notify import K_EMAIL_ENABLED, _get, send_email
    email_enabled = _get(db, K_EMAIL_ENABLED) == "true"

    email_sent = None
    if email_enabled:
        # メール通知が有効なサーバーでは、管理者はパスワードを一切知らない状態にする
        # （ランダム生成→本人のメールにのみ送信）。送信に失敗したらユーザー作成自体を中止する。
        if not body.email:
            return Response(status_code=400, content='{"error":"メール通知が有効なため、メールアドレスが必須です"}',
                            media_type="application/json")
        password = A.generate_temp_password()
        subject = "[LogSeeker] アカウントが作成されました"
        text = (f"LogSeekerのアカウントが作成されました。\n\n"
                f"ユーザー名: {body.username}\n"
                f"仮パスワード: {password}\n\n"
                f"ログイン後、パスワードの変更をおすすめします。\n")
        err = send_email([body.email], subject, text, db)
        if err:
            return Response(status_code=502, content=json.dumps({"error": f"メール送信に失敗しました: {err}"}),
                            media_type="application/json")
        email_sent = True
    else:
        # メール通知が無効なサーバーでは従来通り、管理者が初期パスワードを直接入力する。
        if not body.password:
            return Response(status_code=400, content='{"error":"パスワードを入力してください"}',
                            media_type="application/json")
        password = body.password

    u = User(username=body.username, display_name=body.display_name, role=body.role,
             password_hash=A.hash_password(password), enabled=True)
    db.add(u)
    db.commit()
    L.note(request, "user.create", target=body.username,
           detail=L.join([f"表示名: {L.fmt(body.display_name)}",
                          f"ロール: {A.ROLE_LABELS.get(body.role, body.role)}",
                          "初期パスワード: " + (f"本人のメール（{body.email}）へ送付" if email_sent else "管理者が設定")]))

    result = _user_dict(u)
    result["email_sent"] = email_sent
    return result


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
        changes.append(f"ロール: {A.ROLE_LABELS.get(u.role, u.role)} → {A.ROLE_LABELS.get(body.role, body.role)}")
        u.role = body.role
    if body.display_name is not None:
        if (body.display_name or None) != (u.display_name or None):
            changes.append(f"表示名: {L.fmt(u.display_name)} → {L.fmt(body.display_name)}")
        u.display_name = body.display_name
    if body.enabled is not None:
        # 自分自身は無効化させない（ロックアウト防止）
        if u.id == (actor.id if actor else None) and not body.enabled:
            return Response(status_code=400, content='{"error":"自分自身は無効化できません"}',
                            media_type="application/json")
        if u.enabled != body.enabled:
            changes.append("アカウントを有効化" if body.enabled else "アカウントを無効化")
        u.enabled = body.enabled
    if body.password:
        u.password_hash = A.hash_password(body.password)
        changes.append("パスワードを変更（本人が変更）" if actor and actor.id == u.id
                       else "パスワードを変更（再設定）")
    db.commit()
    only_pw = len(changes) == 1 and bool(body.password)
    L.note(request, "user.password" if only_pw else "user.update", target=u.username,
           detail=L.join(changes))
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
    L.note(request, "user.delete", target=u.username,
           detail=f"表示名: {L.fmt(u.display_name)} / ロール: {A.ROLE_LABELS.get(u.role, u.role)}")
    db.delete(u)
    db.commit()
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
    before = A.is_auth_required(db)
    A.set_auth_required(db, body.enabled)
    L.note(request, "auth.toggle",
           detail=("ログイン認証を有効化" if body.enabled else "ログイン認証を無効化")
           + ("（変更なし）" if before == body.enabled else ""))
    return {"ok": True, "auth_required": body.enabled}


# ---------------- SSO 設定（admin専用・実接続は未実装） ----------------
@router.get("/sso")
def get_sso(_: User | None = Depends(A.require_admin), db: Session = Depends(get_db)):
    from .sso import sso_status
    return sso_status(db)


@router.put("/sso")
def save_sso(body: SSOConfig, request: Request,
             actor: User | None = Depends(A.require_admin), db: Session = Depends(get_db)):
    from .sso import save_sso_config, sso_status
    before = sso_status(db)
    save_sso_config(db, body.model_dump())
    changes = L.diff({"enabled": "SSO", "issuer": "Issuer", "client_id": "クライアントID",
                      "redirect_uri": "リダイレクトURI", "allowed_domains": "許可ドメイン",
                      "auto_provision_role": "自動作成時のロール"},
                     before, body.model_dump(),
                     {"auto_provision_role": lambda r: A.ROLE_LABELS.get(r, L.fmt(r))})
    if body.client_secret:
        changes.append("クライアントシークレットを変更")
    L.note(request, "sso.config", detail=L.join(changes))
    return {"ok": True, "note": "設定を保存しました（実接続は現バージョン未実装。設計・保管のみ）"}


# ---------- IPアクセス制限（admin専用） ----------
@router.get("/admin/ip-restrict")
def get_ip_restrict(request: Request, _: User | None = Depends(A.require_admin), db: Session = Depends(get_db)):
    from . import ip_restrict as R
    result = R.status(db)
    result["your_ip"] = A.access_control_ip(request)
    return result


@router.put("/admin/ip-restrict")
def save_ip_restrict(body: IpRestrictSave, request: Request,
                     actor: User | None = Depends(A.require_admin), db: Session = Depends(get_db)):
    from . import ip_restrict as R
    requester_ip = A.access_control_ip(request)
    before = R.status(db)
    try:
        R.save(db, body.enabled, [e.model_dump() for e in body.allowlist], requester_ip)
    except R.IpRestrictSaveError as e:
        return Response(status_code=400, content=json.dumps({"error": e.message}), media_type="application/json")
    result = R.status(db)
    changes = []
    if before["enabled"] != result["enabled"]:
        changes.append("IP制限を有効化" if result["enabled"] else "IP制限を無効化")
    b = {e["cidr"]: e.get("label") or "" for e in before["allowlist"]}
    a = {e["cidr"]: e.get("label") or "" for e in result["allowlist"]}

    def _entry(cidr: str, labels: dict) -> str:
        return cidr + (f"（{labels[cidr]}）" if labels[cidr] else "")
    changes += [f"許可に追加: {_entry(c, a)}" for c in a if c not in b]
    changes += [f"許可から削除: {_entry(c, b)}" for c in b if c not in a]
    changes += [f"名前を変更: {c}（{b[c] or 'なし'} → {a[c] or 'なし'}）" for c in a if c in b and a[c] != b[c]]
    L.note(request, "ip_restrict.config", detail=f"{L.join(changes)}（許可リスト計{len(a)}件）")
    result["your_ip"] = requester_ip
    return result


# ---------------- 監査ログ（sysadmin以上） ----------------
def _audit_dict(a: AuditLog) -> dict:
    return {
        "id": a.id, "at": a.at.astimezone(L.JST).isoformat() if a.at else None,
        "username": a.username, "role": a.role, "action": a.action,
        "method": a.method, "path": a.path, "status": a.status,
        "target": a.target, "detail": a.detail, "ip": a.ip,
        "action_label": L.label_of(a.action, a.method, a.path),
    }


@router.get("/audit")
def list_audit(_: User | None = Depends(A.require_sysadmin), db: Session = Depends(get_db),
               limit: int = 500):
    rows = db.execute(select(AuditLog).order_by(AuditLog.at.desc()).limit(min(limit, 2000))).scalars().all()
    return {
        "total": db.scalar(select(func.count()).select_from(AuditLog)),
        "items": [_audit_dict(a) for a in rows],
    }


@router.get("/audit.csv")
def audit_csv(request: Request, actor: User | None = Depends(A.require_sysadmin), db: Session = Depends(get_db)):
    rows = db.execute(select(AuditLog).order_by(AuditLog.at.desc())).scalars().all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["日時(JST)", "ユーザー", "ロール", "操作", "対象", "内容", "結果", "IP", "操作ID", "メソッド", "パス"])
    for a in rows:
        w.writerow([a.at.astimezone(L.JST).strftime("%Y-%m-%d %H:%M:%S") if a.at else "", a.username or "", A.ROLE_LABELS.get(a.role, a.role or ""),
                    L.label_of(a.action, a.method, a.path), a.target or "", a.detail or "", a.status or "",
                    a.ip or "", a.action, a.method or "", a.path or ""])
    L.note(request, "audit.download", detail=f"CSV形式・{len(rows):,}件")
    data = "﻿" + buf.getvalue()
    return Response(content=data, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=logseeker_audit.csv"})


@router.get("/audit.json")
def audit_json(request: Request, actor: User | None = Depends(A.require_sysadmin), db: Session = Depends(get_db)):
    rows = db.execute(select(AuditLog).order_by(AuditLog.at.desc())).scalars().all()
    L.note(request, "audit.download", detail=f"JSON形式・{len(rows):,}件")
    data = json.dumps([_audit_dict(a) for a in rows], ensure_ascii=False, indent=2)
    return Response(content=data, media_type="application/json; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=logseeker_audit.json"})
