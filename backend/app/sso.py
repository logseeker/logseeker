"""SSO（OpenID Connect / Authorization Code + PKCE）。対応IdPは Google と Microsoft 365（Entra ID）。

設計方針（docs/sso.md 参照）:
- **本人確認・MFA・パスワード管理はIdPに任せる**（LogSeekerはSSOユーザーのパスワードを持たない）。
  MFAの強制は利用者側のIdP設定（Google Workspaceの2段階認証の強制 / Entraのセキュリティの既定値群・
  条件付きアクセス）で行う。
- **個人アカウントは対象外**。Googleは許可ドメイン（Workspaceの `hd` クレーム）必須、
  Microsoftは特定テナント必須（common/organizations/consumers は受け付けない）。
- **自動プロビジョニングはしない**。管理者が事前に「SSOユーザー」をメールアドレス付きで作成しておき、
  初回ログイン時にIdPの確認済みメールアドレスと一致したユーザーへ IdP の `sub` を紐付ける。
  2回目以降は (sso_provider, sso_subject) で照合する（メールアドレスの変更に影響されない）。
- 管理パネルの入口（/api/auth/admin-login）はSSOの対象外。IdP障害時の非常口としてローカル認証を残す。

フロー:
  1) GET /api/sso/{provider}/login     … state/nonce/PKCE を作ってIdPへリダイレクト。
     ブラウザ束縛用のランダム値を HttpOnly Cookie に入れ、DBにはそのハッシュを保存する
     （他人に自分のログイン結果を踏ませる login CSRF を防ぐため）。
  2) GET /api/sso/{provider}/callback  … state照合→トークン交換→id_token検証→ユーザー照合。
     成功したら一回限り・60秒有効の交換コードを付けて `/?sso_code=...` へ戻す。
     （セッショントークン自体をURLに載せない。履歴・Referer・アクセスログに残さないため）
  3) POST /api/sso/exchange            … フロントが交換コード＋同じCookieでセッショントークンを受け取る。
"""
import base64
import hashlib
import json
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import jwt
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .models import Setting, SsoLoginState, User

PROVIDERS = {
    "google": {"label": "Google"},
    "microsoft": {"label": "Microsoft 365"},
}

COOKIE_NAME = "ls_sso_bind"
COOKIE_PATH = "/api/sso"
AUTH_TTL = timedelta(minutes=10)      # IdPでのログイン操作（MFA含む）に使える時間
EXCHANGE_TTL = timedelta(seconds=60)  # 交換コードはリダイレクト直後に使うだけ
HTTP_TIMEOUT = 10

# Microsoftのマルチテナント用エンドポイント。個人アカウント・他組織を通してしまうため受け付けない。
_MS_MULTI_TENANT = {"common", "organizations", "consumers"}
_TENANT_RE = re.compile(r"^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
                        r"|[A-Za-z0-9.-]+\.[A-Za-z]{2,})$")
_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$")


class SsoError(Exception):
    """reason はフロントへ返す理由コード（メッセージはフロント側で日本語化）。detail は監査ログ用。"""
    def __init__(self, reason: str, detail: str = "", username: str | None = None):
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail or reason
        self.username = username


# ---------------- 設定（Setting KV） ----------------
def _get(db: Session, key: str, default: str = "") -> str:
    row = db.get(Setting, key)
    return row.value if (row and row.value is not None) else default


def _set(db: Session, key: str, value: str) -> None:
    row = db.get(Setting, key)
    if not row:
        row = Setting(key=key)
        db.add(row)
    row.value = value


def _domains(raw: str) -> list[str]:
    return [d.strip().lower() for d in re.split(r"[,\s]+", raw or "") if d.strip()]


def public_url(db: Session) -> str:
    return _get(db, "sso_public_url").rstrip("/")


def redirect_uri(db: Session, provider: str) -> str:
    base = public_url(db)
    return f"{base}/api/sso/{provider}/callback" if base else ""


def _provider_cfg(db: Session, provider: str) -> dict:
    p = f"sso_{provider}_"
    cfg = {
        "enabled": _get(db, p + "enabled", "false") == "true",
        "client_id": _get(db, p + "client_id"),
        "client_secret": _get(db, p + "client_secret"),
    }
    if provider == "google":
        cfg["domains"] = _domains(_get(db, p + "domains"))
    else:
        cfg["tenant"] = _get(db, p + "tenant").strip()
    return cfg


def _is_ready(db: Session, provider: str, cfg: dict) -> bool:
    if not (cfg["enabled"] and cfg["client_id"] and cfg["client_secret"] and public_url(db)):
        return False
    if provider == "google":
        return bool(cfg["domains"])
    return bool(cfg["tenant"])


def login_providers(db: Session) -> list[dict]:
    """ログイン画面用。使える（有効かつ設定が揃った）IdPだけを返す。秘密情報は含めない。"""
    return [{"id": p, "label": meta["label"]} for p, meta in PROVIDERS.items()
            if _is_ready(db, p, _provider_cfg(db, p))]


def admin_status(db: Session) -> dict:
    """管理パネル用。client_secret は返さず「設定済みか」だけを返す。"""
    out = {"public_url": public_url(db), "providers": {}}
    for p, meta in PROVIDERS.items():
        cfg = _provider_cfg(db, p)
        item = {
            "label": meta["label"], "enabled": cfg["enabled"], "client_id": cfg["client_id"],
            "has_secret": bool(cfg["client_secret"]), "redirect_uri": redirect_uri(db, p),
            "ready": _is_ready(db, p, cfg),
        }
        if p == "google":
            item["domains"] = ", ".join(cfg["domains"])
        else:
            item["tenant"] = cfg["tenant"]
        out["providers"][p] = item
    return out


def validate_and_save(db: Session, body: dict) -> list[str]:
    """設定を検証して保存する。問題があればエラーメッセージのリストを返し、何も保存しない。"""
    errors: list[str] = []
    url = (body.get("public_url") or "").strip().rstrip("/")
    if url and not re.match(r"^https?://[^/\s]+$", url):
        errors.append("公開URLは https://ホスト名 の形式で入力してください（パスは付けない）")
    provs = body.get("providers") or {}
    g = provs.get("google") or {}
    m = provs.get("microsoft") or {}
    g_domains = _domains(g.get("domains") or "")
    for d in g_domains:
        if not _DOMAIN_RE.match(d):
            errors.append(f"Googleの許可ドメインが不正です: {d}")
        if d in ("gmail.com", "googlemail.com"):
            errors.append("個人のGoogleアカウント（gmail.com）は許可できません。Google Workspaceのドメインを指定してください")
    tenant = (m.get("tenant") or "").strip()
    if tenant and (tenant.lower() in _MS_MULTI_TENANT or not _TENANT_RE.match(tenant)):
        errors.append("MicrosoftのテナントはテナントID（GUID）か xxx.onmicrosoft.com 等のドメインを指定してください"
                      "（common / organizations / consumers は不可）")
    if (g.get("enabled") or m.get("enabled")) and not url:
        errors.append("SSOを有効にするには公開URLが必要です")
    if g.get("enabled") and not g_domains:
        errors.append("Googleを有効にするには許可ドメインが必要です")
    if m.get("enabled") and not tenant:
        errors.append("Microsoft 365を有効にするにはテナントが必要です")
    for key, cfg in (("google", g), ("microsoft", m)):
        if cfg.get("enabled"):
            has_secret = bool(cfg.get("client_secret")) or bool(_get(db, f"sso_{key}_client_secret"))
            if not (cfg.get("client_id") or "").strip() or not has_secret:
                errors.append(f"{PROVIDERS[key]['label']}を有効にするにはクライアントIDとシークレットが必要です")
    if errors:
        return errors

    _set(db, "sso_public_url", url)
    for key, cfg in (("google", g), ("microsoft", m)):
        p = f"sso_{key}_"
        _set(db, p + "enabled", "true" if cfg.get("enabled") else "false")
        _set(db, p + "client_id", (cfg.get("client_id") or "").strip())
        if cfg.get("client_secret"):  # 空なら既存維持
            _set(db, p + "client_secret", cfg["client_secret"].strip())
    _set(db, "sso_google_domains", ", ".join(g_domains))
    _set(db, "sso_microsoft_tenant", tenant)
    db.commit()
    return []


# ---------------- IdPのメタデータ（discovery / JWKS） ----------------
def _discovery_url(provider: str, cfg: dict) -> str:
    if provider == "google":
        return "https://accounts.google.com/.well-known/openid-configuration"
    return f"https://login.microsoftonline.com/{urllib.parse.quote(cfg['tenant'])}/v2.0/.well-known/openid-configuration"


_discovery_cache: dict[str, tuple[float, dict]] = {}
_jwk_clients: dict[str, jwt.PyJWKClient] = {}


def _discovery(provider: str, cfg: dict) -> dict:
    url = _discovery_url(provider, cfg)
    hit = _discovery_cache.get(url)
    if hit and hit[0] > time.time():
        return hit[1]
    try:
        with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT) as r:
            doc = json.loads(r.read())
    except (urllib.error.URLError, ValueError) as e:
        raise SsoError("config", f"IdPのメタデータを取得できません: {url} ({e})")
    for k in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not doc.get(k):
            raise SsoError("config", f"IdPのメタデータに {k} がありません: {url}")
    _discovery_cache[url] = (time.time() + 3600, doc)
    return doc


def _signing_key(jwks_uri: str, id_token: str):
    client = _jwk_clients.get(jwks_uri)
    if client is None:
        client = jwt.PyJWKClient(jwks_uri, cache_keys=True, timeout=HTTP_TIMEOUT)
        _jwk_clients[jwks_uri] = client
    return client.get_signing_key_from_jwt(id_token).key


# ---------------- ワンタイム状態（sso_login_states） ----------------
def _h(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _purge_expired(db: Session) -> None:
    db.execute(delete(SsoLoginState).where(SsoLoginState.expires_at < _now()))


def _take(db: Session, kind: str, value: str, binding: str | None) -> SsoLoginState:
    """state/交換コードを1回だけ取り出す（取り出した時点で削除＝再利用不可）。"""
    if not value or not binding:
        raise SsoError("state", f"{kind}: state/コードまたはブラウザ束縛Cookieがありません")
    row = db.execute(select(SsoLoginState).where(
        SsoLoginState.kind == kind, SsoLoginState.state_hash == _h(value))).scalar_one_or_none()
    if row is None:
        raise SsoError("state", f"{kind}: 不明または使用済みのstate/コード")
    db.delete(row)
    db.commit()
    exp = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    if exp < _now():
        raise SsoError("state", f"{kind}: 有効期限切れ")
    if not secrets.compare_digest(row.binding_hash, _h(binding)):
        raise SsoError("state", f"{kind}: ブラウザ束縛Cookieが一致しません")
    return row


# ---------------- フロー ----------------
def begin_login(db: Session, provider: str) -> tuple[str, str]:
    """(IdPの認可URL, ブラウザ束縛Cookieの値) を返す。"""
    if provider not in PROVIDERS:
        raise SsoError("config", f"未対応のIdP: {provider}")
    cfg = _provider_cfg(db, provider)
    if not _is_ready(db, provider, cfg):
        raise SsoError("config", f"{provider}: 無効または設定不足")
    disc = _discovery(provider, cfg)

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    binding = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

    _purge_expired(db)
    db.add(SsoLoginState(kind="auth", state_hash=_h(state), binding_hash=_h(binding), provider=provider,
                         nonce=nonce, code_verifier=verifier, expires_at=_now() + AUTH_TTL))
    db.commit()

    params = {
        "response_type": "code", "client_id": cfg["client_id"], "redirect_uri": redirect_uri(db, provider),
        "scope": "openid email profile", "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "select_account",
    }
    if provider == "google" and len(cfg["domains"]) == 1:
        params["hd"] = cfg["domains"][0]  # アカウント選択画面の絞り込み（表示用。検証はid_token側で行う）
    return f"{disc['authorization_endpoint']}?{urllib.parse.urlencode(params)}", binding


def _exchange_code(disc: dict, cfg: dict, code: str, redirect: str, verifier: str) -> dict:
    data = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect,
        "client_id": cfg["client_id"], "client_secret": cfg["client_secret"], "code_verifier": verifier,
    }).encode()
    req = urllib.request.Request(disc["token_endpoint"], data=data, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        raise SsoError("token", f"トークン交換に失敗: HTTP {e.code} {body}")
    except (urllib.error.URLError, ValueError) as e:
        raise SsoError("token", f"トークン交換に失敗: {e}")


def _verify_id_token(provider: str, cfg: dict, disc: dict, id_token: str, nonce: str) -> dict:
    issuers = [disc["issuer"]]
    if provider == "google":
        issuers.append("accounts.google.com")  # Googleは https:// 無しの iss も発行する（仕様上どちらも正）
    try:
        key = _signing_key(disc["jwks_uri"], id_token)
        claims = jwt.decode(id_token, key, algorithms=["RS256"], audience=cfg["client_id"], issuer=issuers,
                            leeway=60, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
    except jwt.PyJWTError as e:
        raise SsoError("token", f"id_tokenの検証に失敗: {e}")
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise SsoError("token", "id_tokenのnonceが一致しません")
    return claims


def _identity(provider: str, cfg: dict, claims: dict) -> tuple[str, list[str]]:
    """(sub, 照合に使うメールアドレス候補) を返す。許可外のアカウントはここで弾く。"""
    sub = str(claims["sub"])
    if provider == "google":
        email = str(claims.get("email") or "").lower()
        if claims.get("email_verified") is not True or not email:
            raise SsoError("email", "Googleアカウントのメールアドレスが未確認です", email or None)
        hd = str(claims.get("hd") or "").lower()
        if hd not in cfg["domains"]:
            raise SsoError("domain", f"許可外のドメイン: hd={hd or '(なし=個人アカウント)'}", email)
        return sub, [email]
    # Microsoft: テナントはissuer検証で担保済み（特定テナントのissuerしか受け付けない）。
    # email クレームは任意・未検証のことがあるため、テナント管理者が管理する UPN(preferred_username) も候補にする。
    cands = [str(claims.get(k) or "").lower() for k in ("preferred_username", "email", "upn")]
    cands = list(dict.fromkeys(c for c in cands if "@" in c))
    if not cands:
        raise SsoError("email", "Microsoftアカウントからメールアドレス(UPN)を取得できません")
    return sub, cands


def _match_user(db: Session, provider: str, sub: str, emails: list[str]) -> User:
    u = db.execute(select(User).where(User.sso_provider == provider, User.sso_subject == sub)).scalar_one_or_none()
    if u is None:
        cands = db.execute(select(User).where(
            User.auth_method == "sso", User.sso_subject.is_(None),
            func.lower(User.email).in_(emails))).scalars().all()
        if len(cands) != 1:
            reason = "not_registered" if not cands else "ambiguous"
            raise SsoError(reason, f"SSOユーザー未登録または重複: {', '.join(emails)}（該当{len(cands)}件）", emails[0])
        u = cands[0]
        u.sso_provider = provider
        u.sso_subject = sub
        db.commit()
    if u.auth_method != "sso":
        raise SsoError("not_registered", "SSOユーザーではありません", u.username)
    if not u.enabled:
        raise SsoError("disabled", "無効化されたユーザー", u.username)
    return u


def finish_login(db: Session, provider: str, code: str, state: str, binding: str | None) -> User:
    row = _take(db, "auth", state, binding)
    if row.provider != provider:
        raise SsoError("state", "stateのIdPが一致しません")
    cfg = _provider_cfg(db, provider)
    if not _is_ready(db, provider, cfg):
        raise SsoError("config", f"{provider}: 無効または設定不足")
    if not code:
        raise SsoError("token", "認可コードがありません")
    disc = _discovery(provider, cfg)
    tokens = _exchange_code(disc, cfg, code, redirect_uri(db, provider), row.code_verifier)
    id_token = tokens.get("id_token")
    if not id_token:
        raise SsoError("token", "トークン応答に id_token がありません")
    claims = _verify_id_token(provider, cfg, disc, id_token, row.nonce)
    sub, emails = _identity(provider, cfg, claims)
    return _match_user(db, provider, sub, emails)


def issue_exchange_code(db: Session, user: User, binding: str) -> str:
    code = secrets.token_urlsafe(32)
    db.add(SsoLoginState(kind="exchange", state_hash=_h(code), binding_hash=_h(binding),
                         provider=user.sso_provider or "", user_id=user.id, expires_at=_now() + EXCHANGE_TTL))
    db.commit()
    return code


def redeem_exchange_code(db: Session, code: str, binding: str | None) -> User:
    row = _take(db, "exchange", code, binding)
    u = db.get(User, row.user_id) if row.user_id else None
    if u is None or not u.enabled or u.auth_method != "sso":
        raise SsoError("disabled", "交換時点でユーザーが無効")
    return u
