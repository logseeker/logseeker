"""SSO（OIDC）— 現状は『設計・受け口』のみ。実接続は未実装（将来 Authlib 等で実装）。

設計方針（docs/sso.md 参照）:
- 方式は OpenID Connect (Authorization Code)。IdP は Google / Azure AD(Entra) / Keycloak / Okta 等。
- 必要設定: issuer(discovery URL) / client_id / client_secret / redirect_uri / 許可ドメイン。
- ログイン成功時、OIDC の `sub` を User.sso_subject に紐付け（初回は自動プロビジョニング可否を選択）。
- Docker でもアプリ単体配布でも動作可能（IdP へ到達できるネットワークがあればよい）。
  “アプリだけ配布”でも、利用者が自分の IdP 情報を管理画面で設定すれば成立する。

ここでは設定の保存/参照と状態通知のみ提供し、実際の認可コードフローは未配線。
"""
from sqlalchemy.orm import Session

from .models import Setting

_KEYS = ["sso_enabled", "sso_issuer", "sso_client_id", "sso_client_secret",
         "sso_redirect_uri", "sso_allowed_domains", "sso_auto_provision_role"]


def _get(db: Session, key: str, default: str = "") -> str:
    row = db.get(Setting, key)
    return row.value if (row and row.value is not None) else default


def _set(db: Session, key: str, value: str) -> None:
    row = db.get(Setting, key)
    if not row:
        row = Setting(key=key)
        db.add(row)
    row.value = value
    db.commit()


def sso_status(db: Session) -> dict:
    """フロント表示用。秘密情報(client_secret)は返さない。"""
    return {
        "enabled": _get(db, "sso_enabled", "false") == "true",
        "configured": bool(_get(db, "sso_issuer") and _get(db, "sso_client_id")),
        "issuer": _get(db, "sso_issuer"),
        "client_id": _get(db, "sso_client_id"),
        "has_secret": bool(_get(db, "sso_client_secret")),
        "redirect_uri": _get(db, "sso_redirect_uri"),
        "allowed_domains": _get(db, "sso_allowed_domains"),
        "auto_provision_role": _get(db, "sso_auto_provision_role", "viewer"),
        "implemented": False,  # 実接続は未実装（設計のみ）
    }


def save_sso_config(db: Session, cfg: dict) -> None:
    for k in _KEYS:
        if k == "sso_client_secret":
            if cfg.get("client_secret"):  # 空なら既存維持
                _set(db, k, cfg["client_secret"])
            continue
        short = k[len("sso_"):]
        if short in cfg and cfg[short] is not None:
            v = cfg[short]
            _set(db, k, "true" if isinstance(v, bool) and v else ("false" if isinstance(v, bool) else str(v)))
