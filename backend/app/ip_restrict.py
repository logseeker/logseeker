"""IPアクセス制限（アプリ層）。管理パネル（?screen=administration、admin専用の別ログイン）への
アクセスそのものを、許可したIP/CIDRだけに絞れる（既定はOFF＝無効）。SSHのAllowUsers/送信元制限や
WordPress管理画面のIP制限などと同じ発想＝「そもそもログイン試行自体をそのIP以外弾く」もの。

通常のログイン後画面（ユーザー管理・監査ログ・ライセンス・通知設定・脅威インテリ等）はこの対象外。
それらは今まで通りロール(sysadmin以上)だけで守る。

設定はSSO設定（sso.py）と同じパターンでSetting(KV)に保存する。新しいテーブルは追加しない。

判定に使う送信元IPは auth.access_control_ip() を使う（監査ログ用の client_ip() とは別。
理由はそちらのdocstring参照）。
"""
import ipaddress
import json

from sqlalchemy.orm import Session

from .models import Setting

# 管理パネル自身のAPI（ログイン試行そのものを含む）。
# システム状態の読み取り専用統計（/api/admin/overview 等）はここに含めない＝対象外。
PROTECTED_PREFIXES = ["/api/auth/admin-login", "/api/auth/require", "/api/sso", "/api/admin/ip-restrict"]

_K_ENABLED = "ip_restrict_enabled"
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


def is_enabled(db: Session) -> bool:
    return _get(db, _K_ENABLED, "false") == "true"


def allowlist(db: Session) -> list[dict]:
    try:
        return json.loads(_get(db, _K_ALLOWLIST, "[]"))
    except (json.JSONDecodeError, TypeError):
        return []


def status(db: Session) -> dict:
    return {"enabled": is_enabled(db), "allowlist": allowlist(db)}


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


def is_protected_path(path: str) -> bool:
    return any(path.startswith(p) for p in PROTECTED_PREFIXES)


class IpRestrictSaveError(Exception):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def save(db: Session, enabled: bool, entries: list[dict], requester_ip: str | None) -> None:
    """CIDRを検証して保存する。有効化しようとしているのに、リクエスト元のIPが
    許可リストに含まれない場合は保存を拒否する（自分自身がロックアウトされるのを防ぐため）。
    """
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

    if enabled:
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

    _set(db, _K_ENABLED, "true" if enabled else "false")
    _set(db, _K_ALLOWLIST, json.dumps(cleaned))


def _safe_network_contains(cidr: str, addr: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> bool:
    try:
        return addr in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
