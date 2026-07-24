"""IPアクセス制限（アプリ層）。管理系の画面ごとに、許可されたIP/CIDRからのみ
アクセスできるように設定できる（既定は全画面OFF＝無効。有効化はAdmin画面から）。

設定はSSO設定（sso.py）と同じパターンで Setting(KV) に保存する。新しいテーブルは追加しない。

判定に使う送信元IPは auth.access_control_ip() を使う（監査ログ用の client_ip() とは別。
理由はそちらのdocstring参照）。
"""
import ipaddress
import json

from sqlalchemy.orm import Session

from .models import Setting

# scope key -> (画面ラベル, 対象パスprefix群)
# ここに挙げたprefixへの /api リクエストがIP制限の対象になる。
SCOPES: dict[str, tuple[str, list[str]]] = {
    "admin": ("システム状態・セキュリティ設定", ["/api/admin", "/api/auth/require", "/api/sso"]),
    "users": ("ユーザー管理", ["/api/users"]),
    "audit": ("監査ログ", ["/api/audit"]),
    "license": ("ライセンス", ["/api/license"]),
    "notifications": ("通知設定", ["/api/notifications"]),
    "threatintel": ("脅威インテリ", ["/api/ioc"]),
}

_K_SCOPES = "ip_restrict_scopes"
_K_ALLOWLIST = "ip_restrict_allowlist"


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


def enabled_scopes(db: Session) -> set[str]:
    try:
        return {s for s in json.loads(_get(db, _K_SCOPES, "[]")) if s in SCOPES}
    except (json.JSONDecodeError, TypeError):
        return set()


def allowlist(db: Session) -> list[dict]:
    try:
        return json.loads(_get(db, _K_ALLOWLIST, "[]"))
    except (json.JSONDecodeError, TypeError):
        return []


def status(db: Session) -> dict:
    scopes = enabled_scopes(db)
    return {
        "scopes": [{"key": k, "label": v[0], "enabled": k in scopes} for k, v in SCOPES.items()],
        "allowlist": allowlist(db),
    }


def ip_in_allowlist(db: Session, ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in allowlist(db):
        try:
            if addr in ipaddress.ip_network(entry.get("cidr", ""), strict=False):
                return True
        except ValueError:
            continue
    return False


def scope_for_path(path: str) -> str | None:
    for key, (_, prefixes) in SCOPES.items():
        for p in prefixes:
            if path.startswith(p):
                return key
    return None


class IpRestrictSaveError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def save(db: Session, scopes: list[str], entries: list[dict], requester_ip: str | None) -> None:
    """CIDRを検証して保存する。有効化しようとしているscopeがあるのに、リクエスト元のIPが
    許可リストに含まれない場合は保存を拒否する（自分自身がロックアウトされるのを防ぐため）。
    """
    valid_scopes = [s for s in scopes if s in SCOPES]

    cleaned: list[dict] = []
    for e in entries:
        cidr = (e.get("cidr") or "").strip()
        if not cidr:
            continue
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise IpRestrictSaveError(f"'{cidr}' はIP/CIDR形式として不正です")
        cleaned.append({"cidr": cidr, "label": (e.get("label") or "").strip()})

    if valid_scopes:
        if not requester_ip:
            raise IpRestrictSaveError(
                "あなたの送信元IPを判定できませんでした（リバースプロキシがX-Forwarded-Forを"
                "転送していない可能性があります）。安全のため、この状態では制限を有効化できません。"
            )
        try:
            addr = ipaddress.ip_address(requester_ip)
        except ValueError:
            raise IpRestrictSaveError(
                f"あなたの送信元IP（{requester_ip}）の形式が不正なため判定できません。"
                "安全のため、この状態では制限を有効化できません。"
            )
        covered = any(
            _safe_network_contains(e.get("cidr", ""), addr) for e in cleaned
        )
        if not covered:
            raise IpRestrictSaveError(
                f"あなたの現在のIP（{requester_ip}）が許可リストに含まれていません。"
                "自分自身がロックアウトされるのを防ぐため、先にこのIPを許可リストへ追加してください。"
            )

    _set(db, _K_SCOPES, json.dumps(valid_scopes))
    _set(db, _K_ALLOWLIST, json.dumps(cleaned))


def _safe_network_contains(cidr: str, addr: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> bool:
    try:
        return addr in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
