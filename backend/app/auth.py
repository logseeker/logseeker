"""認証・認可（RBAC）・監査の中核。
- ローカル認証は pbkdf2_hmac（標準ライブラリ・依存追加なし）＋ソルト。
- セッションは Bearer トークン（DBには sha256 のみ保存）。
- ロール: viewer < editor < sysadmin < admin（Linux の user/sudo/root に対応）。
- 認証は既定OFF（デモ）。Setting(auth_required) か env で必須化＝『任意ON』。
  OFF の間は誰でも全操作可（従来どおり）。ON の間はロールで制御する。
"""
import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import get_db
from .models import AuditLog, AuthSession, Setting, User

# ロール順位（大きいほど強い）
ROLES = {"viewer": 1, "editor": 2, "sysadmin": 3, "admin": 4}
ROLE_LABELS = {"viewer": "閲覧者", "editor": "編集者", "sysadmin": "システム管理者", "admin": "管理者"}


# ---------- パスワード（pbkdf2_sha256） ----------
def hash_password(pw: str, iterations: int = 200_000) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def generate_temp_password(length: int = 12) -> str:
    return secrets.token_urlsafe(length)


_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))  # 起動時に1回だけ生成。存在しないユーザー名でも
# 実在ユーザーと同じだけPBKDF2を回すためのダミー（比較は必ず不一致になる）。


def verify_password(pw: str, stored: str | None) -> bool:
    """`stored`がNoneでも同じ計算コストのダミーハッシュと比較する。
    早期returnすると「ユーザー名が存在しない場合だけ応答が速い」という
    タイミングサイドチャネルでユーザー名の存在を推測されてしまうため。"""
    stored = stored or _DUMMY_HASH
    try:
        algo, iters, salt_b64, dk_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, int(iters))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# ---------- トークン/セッション ----------
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(db: Session, user: User) -> str:
    token = secrets.token_urlsafe(32)
    db.add(AuthSession(
        user_id=user.id, token_hash=_token_hash(token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.SESSION_HOURS),
    ))
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    return token


def destroy_session(db: Session, token: str) -> None:
    th = _token_hash(token)
    db.query(AuthSession).filter(AuthSession.token_hash == th).delete()
    db.commit()


# ---------- 認証状態 ----------
def is_auth_required(db: Session) -> bool:
    """Setting(auth_required) が最優先。無ければ env 既定。"""
    row = db.get(Setting, "auth_required")
    if row and row.value is not None:
        return row.value == "true"
    return settings.AUTH_REQUIRED


def set_auth_required(db: Session, value: bool) -> None:
    row = db.get(Setting, "auth_required")
    if not row:
        row = Setting(key="auth_required")
        db.add(row)
    row.value = "true" if value else "false"
    db.commit()


def _bearer(authorization: str | None) -> str | None:
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:].strip()
    return None


def get_current_user(authorization: str | None = Header(default=None),
                     db: Session = Depends(get_db)) -> User | None:
    """トークンから現在ユーザーを返す（無効/未ログインは None）。"""
    token = _bearer(authorization)
    if not token:
        return None
    sess = db.execute(select(AuthSession).where(AuthSession.token_hash == _token_hash(token))).scalar_one_or_none()
    if not sess:
        return None
    exp = sess.expires_at if sess.expires_at.tzinfo else sess.expires_at.replace(tzinfo=timezone.utc)
    if exp < datetime.now(timezone.utc):
        return None
    user = db.get(User, sess.user_id)
    if not user or not user.enabled:
        return None
    return user


def require_role(min_role: str):
    """min_role 以上を要求する依存。認証OFF時は素通り（デモ＝全権）。"""
    need = ROLES[min_role]

    def dep(user: User | None = Depends(get_current_user), db: Session = Depends(get_db)) -> User | None:
        if not is_auth_required(db):
            return user  # OFF: 誰でも許可（従来動作）
        if not user:
            raise HTTPException(status_code=401, detail="ログインが必要です")
        if ROLES.get(user.role, 0) < need:
            raise HTTPException(status_code=403, detail="権限がありません")
        return user
    return dep


# 依存の別名（読みやすさ用）
require_login = require_role("viewer")
require_editor = require_role("editor")
require_sysadmin = require_role("sysadmin")
require_admin = require_role("admin")


# ---------- 送信元IP取得 ----------
def client_ip(request: Request) -> str | None:
    """監査ログ等に記録する送信元IPを取得する。

    リバースプロキシ経由だと request.client.host は直前のプロキシ自身のIP
    （Apache/nginxの場合は127.0.0.1、Cloudflare Full/厳格の場合はCloudflareの
    エッジサーバーIP）になり、実際のアクセス元ではない。以下の優先順で本来の
    送信元を探す:
      1. CF-Connecting-IP（Cloudflare使用時。Cloudflareが上書き不可能な形で
         付与する真の接続元IPなので最優先）
      2. X-Forwarded-For の「末尾」（＝直前の信頼できるリバースプロキシが実際に
         観測した接続元。nginx/Apache/OpenLiteSpeedいずれも、自分が観測した
         接続元IPを末尾に追記する。先頭はクライアントが`X-Forwarded-For: 偽装IP`
         を自分で送りつけるだけで詐称できるため、監査ログの信頼性のために
         末尾を使う。access_control_ip()と同じ考え方 — そちらのdocstring参照）
      3. request.client.host（プロキシを介さない直接アクセス時。§CLAUDE.mdの
         とおりDocker構成を変えない前提のため、この経路も残す）
    """
    cf = request.headers.get("cf-connecting-ip")
    if cf:
        return cf.strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return request.client.host if request.client else None


def access_control_ip(request: Request) -> str | None:
    """アクセス制御（IP許可リスト）専用の送信元IP判定。client_ip()とはフォールバックが異なるため別関数。

    IPの取り方自体（CF-Connecting-IP優先、次にX-Forwarded-Forの「末尾」）はclient_ip()と同じロジック
    （client_ip()のdocstring参照）。末尾追記の挙動は nginx
    （`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`）・Apache
    （mod_proxy_httpの既定 `ProxyAddHeaders On`）・OpenLiteSpeed のいずれもリバースプロキシ
    として動作する際の標準動作なので、プロキシの種類を問わず同じロジックで安全に判定できる。

    client_ip()との違いはフォールバックのみ: ヘッダが全く無い場合、access_control_ip()は
    request.client.host にフォールバックしない（backendは127.0.0.1でのみ待ち受け＝直前のプロキシ
    自身のIPしか見えないため、フォールバックすると全員が同じアドレスに見えてしまい、許可リストが
    実質無意味化する）。None を返し、呼び出し側で「判定不能＝拒否」として扱う（fail-closed）。
    client_ip()は監査ログ表示用で「何かは表示したい」ため request.client.host にフォールバックする
    （Docker直結等プロキシが無い環境でも動作させるため）。
    """
    cf = request.headers.get("cf-connecting-ip")
    if cf:
        return cf.strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[-1]
    xri = request.headers.get("x-real-ip")
    if xri:
        return xri.strip()
    return None


# ---------- 監査ログ ----------
def audit(db: Session, *, action: str, user: User | None = None,
          method: str | None = None, path: str | None = None,
          status: str | None = None, target: str | None = None,
          detail: str | None = None, ip: str | None = None,
          username: str | None = None, role: str | None = None) -> None:
    try:
        db.add(AuditLog(
            action=action, method=method, path=path, status=status,
            target=target, detail=detail, ip=ip,
            username=username or (user.username if user else None),
            role=role or (user.role if user else None),
        ))
        db.commit()
    except Exception:
        db.rollback()


# ---------- 起動時 seed ----------
def bootstrap_root(db: Session) -> None:
    """ユーザーが1人もいなければ root を作成（env の ROOT_USERNAME/ROOT_PASSWORD）。"""
    if db.execute(select(User.id).limit(1)).first():
        return
    db.add(User(
        username=settings.ROOT_USERNAME, display_name="管理者",
        role="admin", password_hash=hash_password(settings.ROOT_PASSWORD), enabled=True,
    ))
    db.commit()
