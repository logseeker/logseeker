"""認証・ユーザー管理・監査ログのAPI。
ロール:
  viewer(user)   : 閲覧・ダウンロード
  editor         : + インシデント/コメントの作成・編集
  sysadmin(sudo) : + ライセンス/通知/IOC/API設定・監査閲覧・(viewer/editorの)ユーザー作成
  admin(root)    : + 全ユーザー管理・sudo/root への昇格・認証ON/OFF・SSO設定
認証方式:
  管理者(admin)       : ID/パスワード + TOTP（MFA必須・mfa.py）。IdP障害時の非常口を兼ねる
  それ以外のロール      : SSO（Google Workspace / Microsoft 365）のみ・招待制（sso.py）
"""
import csv
import io
import json
import re

from fastapi import APIRouter, Cookie, Depends, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import auth as A
from . import audit_log as L
from . import mfa as M
from . import sso as S
from .db import get_db
from .models import AuditLog, User
from .schema import (AuthToggle, IpRestrictSave, LoginRequest, MfaCode, MfaToken, SSOConfig, SsoExchange,
                     UserCreate, UserUpdate)

router = APIRouter(prefix="/api")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _user_dict(u: User) -> dict:
    return {
        "id": u.id, "username": u.username, "display_name": u.display_name,
        "role": u.role, "role_label": A.ROLE_LABELS.get(u.role, u.role),
        "enabled": u.enabled, "auth_method": u.auth_method or "password",
        "is_sso": u.auth_method == "sso", "email": u.email,
        "sso_provider": u.sso_provider,  # None = SSOユーザーだがまだ一度もSSOログインしていない（未紐付け）
        "mfa_enabled": M.is_enabled(u),  # パスワード認証（管理者）のみ意味を持つ
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
    }


def _json_error(status: int, msg: str) -> Response:
    return Response(status_code=status, content=json.dumps({"error": msg}, ensure_ascii=False),
                    media_type="application/json")


def _sso_email_taken(db: Session, email: str, exclude_id: int | None = None) -> bool:
    q = select(User.id).where(func.lower(User.email) == email.lower())
    if exclude_id is not None:
        q = q.where(User.id != exclude_id)
    return db.execute(q).first() is not None


# ---------------- 認証状態 / ログイン ----------------
@router.get("/auth/status")
def auth_status(user: User | None = Depends(A.get_current_user), db: Session = Depends(get_db)):
    """フロント初期化用。認証要否と現在ユーザー、ログイン画面に出すSSOボタン（IdP一覧）を返す。"""
    return {
        "auth_required": A.is_auth_required(db),
        "user": _user_dict(user) if user else None,
        "roles": [{"value": k, "label": v} for k, v in A.ROLE_LABELS.items()],
        "sso": {"providers": S.login_providers(db)},
    }


# 入口ごとの監査ログの操作名とパス（MFAの段階でも同じ操作名で記録する）
_PURPOSE = {"login": ("login", "/api/auth/login"), "admin": ("login.admin", "/api/auth/admin-login")}


def _password_login(body: LoginRequest, request: Request, db: Session, purpose: str):
    """パスワード確認まで（1段階目）。成功してもセッションは出さず、MFAチャレンジを返す。"""
    action, path = _PURPOSE[purpose]
    ip = A.client_ip(request)
    u = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    # ユーザー名の存在有無で応答時間に差が出ない（タイミングでの存在推測を防ぐ）よう、
    # 存在しない場合もverify_password自体は必ず呼ぶ（or の短絡評価をしない）。
    pw_ok = A.verify_password(body.password, u.password_hash if u else None)
    if not u or not u.enabled or not pw_ok:
        A.audit(db, action=action, status="failure", username=body.username,
                method="POST", path=path, ip=ip,
                detail="認証失敗（ユーザー名またはパスワード不一致）")
        return _json_error(401, "ユーザー名またはパスワードが違います")
    if u.role != "admin":
        # パスワード認証は管理者専用。管理者以外（旧バージョンで作ったパスワードユーザー等）はSSOへ誘導する。
        A.audit(db, action=action, status="failure", user=u, method="POST", path=path, ip=ip,
                detail="role不足（パスワード認証は管理者(admin)のみ）")
        if purpose == "admin":
            return _json_error(403, "この画面は管理者(admin)アカウントのみ利用できます")
        return _json_error(403, "パスワードでログインできるのは管理者のみです。Google / Microsoft 365 でログインしてください")
    return M.start_challenge(db, u, purpose)


@router.post("/auth/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    return _password_login(body, request, db, "login")


@router.post("/auth/admin-login")
def admin_login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """通常ログインとは別の入口。管理者(admin)ロール以外は、パスワードが正しくてもここでは
    ログインさせない（『ログイン後の通常画面』とは分離した管理パネル専用の入口のため）。"""
    return _password_login(body, request, db, "admin")


# ---------------- MFA（2段階目。パスワード通過後の mfa_token で呼ぶ。ログイン前でも通す） ----------------
def _mfa_ctx(db: Session, token: str) -> tuple[str | None, str | None, str]:
    """監査ログ用に (ユーザー名, ロール, 入口) を先に控えておく（失敗時はチャレンジが消えることがあるため）。"""
    ch = M.peek(db, token)
    u = db.get(User, ch.user_id) if ch else None
    return (u.username if u else None, u.role if u else None, ch.purpose if ch else "login")


def _mfa_error(db: Session, request: Request, e: M.MfaError, ctx: tuple) -> Response:
    username, role, purpose = ctx
    A.audit(db, action=_PURPOSE[purpose][0], status="failure", username=username, role=role, method="POST",
            path=request.url.path, ip=A.client_ip(request), detail=f"MFA: {e.detail}")
    return _json_error(e.status, e.message)


def _mfa_success(db: Session, request: Request, u: User, purpose: str, how: str, extra: dict | None = None):
    action, path = _PURPOSE[purpose]
    token = A.create_session(db, u)
    A.audit(db, action=action, status="success", user=u, method="POST", path=path,
            ip=A.client_ip(request), detail=f"MFA: {how}")
    return {"token": token, "user": _user_dict(u), **(extra or {})}


@router.post("/auth/mfa/verify")
def mfa_verify(body: MfaCode, request: Request, db: Session = Depends(get_db)):
    ctx = _mfa_ctx(db, body.mfa_token)
    try:
        u, purpose, used_recovery = M.verify(db, body.mfa_token, body.code)
    except M.MfaError as e:
        return _mfa_error(db, request, e, ctx)
    left = M.remaining_recovery_codes(u)
    how = f"リカバリーコード（残り{left}個）" if used_recovery else "確認コード"
    return _mfa_success(db, request, u, purpose, how,
                        {"recovery_codes_left": left} if used_recovery else None)


@router.post("/auth/mfa/setup/start")
def mfa_setup_start(body: MfaToken, request: Request, db: Session = Depends(get_db)):
    ctx = _mfa_ctx(db, body.mfa_token)
    try:
        return M.setup_start(db, body.mfa_token)
    except M.MfaError as e:
        return _mfa_error(db, request, e, ctx)


@router.post("/auth/mfa/setup/confirm")
def mfa_setup_confirm(body: MfaCode, request: Request, db: Session = Depends(get_db)):
    ctx = _mfa_ctx(db, body.mfa_token)
    try:
        u, purpose, recovery = M.setup_confirm(db, body.mfa_token, body.code)
    except M.MfaError as e:
        return _mfa_error(db, request, e, ctx)
    # リカバリーコードの平文を返すのはこの1回だけ（DBにはハッシュのみ）
    return _mfa_success(db, request, u, purpose, "初回登録（認証アプリを設定）", {"recovery_codes": recovery})


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
    # 認証方式はロールで決まる（指定された auth_method は使わない）:
    # 管理者 → パスワード + MFA（非常口を兼ねる） / それ以外 → SSOのみ（招待制）
    if body.role != "admin":
        # SSO専用ユーザー: パスワードを持たない（LogSeeker側で本人確認しない）。
        # 初回SSOログイン時、IdPの確認済みメールアドレスがこの email と一致したら紐付ける（sso.py）。
        email = (body.email or "").strip().lower()
        if not _EMAIL_RE.match(email):
            return _json_error(400, "SSOユーザーには、IdP（Google / Microsoft 365）でログインするメールアドレスが必要です")
        if _sso_email_taken(db, email):
            return _json_error(409, "同じメールアドレスのユーザーが既に存在します")
        u = User(username=body.username, display_name=body.display_name, role=body.role,
                 auth_method="sso", email=email, password_hash=None, enabled=True)
        db.add(u)
        db.commit()
        L.note(request, "user.create", target=body.username,
               detail=L.join([f"表示名: {L.fmt(body.display_name)}",
                              f"ロール: {A.ROLE_LABELS.get(body.role, body.role)}",
                              f"認証方式: SSO（{email}）"]))
        result = _user_dict(u)
        result["email_sent"] = None
        return result

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
                f"初回ログイン時に、認証アプリ（Google Authenticator 等）の登録を求められます。\n"
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
        # 認証方式はロールで決まるため、方式をまたぐロール変更はできない（作り直してもらう）
        if u.auth_method == "sso" and body.role == "admin":
            return _json_error(400, "SSOユーザーは管理者にできません。管理者はパスワード＋MFAのアカウントとして別に作成してください")
        if u.auth_method != "sso" and body.role != "admin":
            return _json_error(400, "パスワード認証のアカウントは管理者専用です。管理者以外にする場合はSSOユーザーとして作成し直してください")
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
        if u.auth_method == "sso":
            return _json_error(400, "SSOユーザーにはパスワードを設定できません")
        u.password_hash = A.hash_password(body.password)
        changes.append("パスワードを変更（本人が変更）" if actor and actor.id == u.id
                       else "パスワードを変更（再設定）")
    if body.email is not None and u.auth_method == "sso":
        email = body.email.strip().lower()
        if email != (u.email or ""):
            if not _EMAIL_RE.match(email):
                return _json_error(400, "メールアドレスの形式が不正です")
            if _sso_email_taken(db, email, exclude_id=u.id):
                return _json_error(409, "同じメールアドレスのユーザーが既に存在します")
            changes.append(f"メールアドレス: {L.fmt(u.email)} → {email}")
            u.email = email
            body.sso_unlink = True  # 別人のIdPアカウントに紐付いたままにしない
    if body.sso_unlink and u.sso_subject:
        changes.append(f"SSOの紐付けを解除（{S.PROVIDERS.get(u.sso_provider or '', {}).get('label', u.sso_provider)}）")
        u.sso_provider = None
        u.sso_subject = None
    if body.mfa_reset:
        # 端末の紛失・機種変更時。次回ログイン時に認証アプリの再登録を求める。管理者だけが行える。
        if A.is_auth_required(db) and (not actor or actor.role != "admin"):
            return _json_error(403, "MFAのリセットは管理者のみ行えます")
        if u.auth_method == "sso":
            return _json_error(400, "SSOユーザーのMFAはGoogle / Microsoft 365 側で管理します")
        if M.is_enabled(u):
            changes.append("MFAをリセット（次回ログイン時に再登録）")
        M.reset(u)
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


# ---------------- SSO 設定（admin専用・管理パネル。IP制限の対象） ----------------
@router.get("/admin/sso")
def get_sso(_: User | None = Depends(A.require_admin), db: Session = Depends(get_db)):
    return S.admin_status(db)


@router.put("/admin/sso")
def save_sso(body: SSOConfig, request: Request,
             actor: User | None = Depends(A.require_admin), db: Session = Depends(get_db)):
    before = S.admin_status(db)
    cfg = body.model_dump()
    errors = S.validate_and_save(db, cfg)
    if errors:
        return _json_error(400, " / ".join(errors))
    after = S.admin_status(db)
    changes = L.diff({"public_url": "公開URL"}, before, after)
    for p, meta in S.PROVIDERS.items():
        changes += [f"{meta['label']} {c}" for c in L.diff(
            {"enabled": "SSO", "client_id": "クライアントID", "domains": "許可ドメイン", "tenant": "テナント"},
            before["providers"][p], after["providers"][p])]
        if (cfg["providers"].get(p) or {}).get("client_secret"):
            changes.append(f"{meta['label']} クライアントシークレットを変更")
    L.note(request, "sso.config", detail=L.join(changes))
    return after


# ---------------- SSO ログイン（ブラウザの画面遷移で呼ばれる。ログイン前でも通す） ----------------
def _sso_fail(db: Session, request: Request, provider: str, e: S.SsoError) -> RedirectResponse:
    A.audit(db, action="login.sso", status="failure", username=e.username, method="GET",
            path=request.url.path, ip=A.client_ip(request),
            detail=f"{S.PROVIDERS.get(provider, {}).get('label', provider)}: {e.detail}"[:1000])
    resp = RedirectResponse(f"/?sso_error={e.reason}", status_code=302)
    resp.delete_cookie(S.COOKIE_NAME, path=S.COOKIE_PATH)
    return resp


@router.get("/sso/{provider}/login")
def sso_login(provider: str, request: Request, db: Session = Depends(get_db)):
    try:
        url, binding = S.begin_login(db, provider)
    except S.SsoError as e:
        return _sso_fail(db, request, provider, e)
    resp = RedirectResponse(url, status_code=302)
    # SameSite=Lax: IdPからのトップレベルGETリダイレクトでは送られ、他サイトからのPOST等では送られない。
    resp.set_cookie(S.COOKIE_NAME, binding, max_age=int(S.AUTH_TTL.total_seconds()), path=S.COOKIE_PATH,
                    httponly=True, secure=S.public_url(db).startswith("https://"), samesite="lax")
    return resp


@router.get("/sso/{provider}/callback")
def sso_callback(provider: str, request: Request, code: str = "", state: str = "", error: str = "",
                 ls_sso_bind: str | None = Cookie(default=None), db: Session = Depends(get_db)):
    if error:
        # 利用者がIdPの画面でキャンセルした、IdP側で同意・ポリシーに弾かれた等
        desc = request.query_params.get("error_description", "")
        return _sso_fail(db, request, provider, S.SsoError("idp", f"IdPがエラーを返しました: {error} {desc}"))
    try:
        user = S.finish_login(db, provider, code, state, ls_sso_bind)
        xcode = S.issue_exchange_code(db, user, ls_sso_bind or "")
    except S.SsoError as e:
        return _sso_fail(db, request, provider, e)
    return RedirectResponse(f"/?sso_code={xcode}", status_code=302)


@router.post("/sso/exchange")
def sso_exchange(body: SsoExchange, request: Request, response: Response,
                 ls_sso_bind: str | None = Cookie(default=None), db: Session = Depends(get_db)):
    ip = A.client_ip(request)
    try:
        user = S.redeem_exchange_code(db, body.code, ls_sso_bind)
    except S.SsoError as e:
        A.audit(db, action="login.sso", status="failure", method="POST", path="/api/sso/exchange",
                ip=ip, detail=e.detail)
        return _json_error(401, "SSOログインの有効期限が切れました。もう一度ログインしてください")
    token = A.create_session(db, user)
    A.audit(db, action="login.sso", status="success", user=user, method="POST", path="/api/sso/exchange",
            ip=ip, detail=S.PROVIDERS.get(user.sso_provider or "", {}).get("label", user.sso_provider))
    response.delete_cookie(S.COOKIE_NAME, path=S.COOKIE_PATH)
    return {"token": token, "user": _user_dict(user)}


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
