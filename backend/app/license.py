"""ライセンス制御。tier(1-4)＋APIオプションで「取り込める/使えるログ種別＝機能」を制御。
ライセンスキーは HMAC 署名付き（オフライン検証可）。発行は tools/issue_license。"""
import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import License

# ティア定義（カテゴリ＝source_type を段階的に解放）
TIERS = {
    1: {"name": "Web", "desc": "Webアクセス/エラーログ"},
    2: {"name": "Web + 監査", "desc": "+ セキュア(認証)/メッセージ(syslog)/メール"},
    3: {"name": "+ SMB/Windows/資産管理", "desc": "+ SMB(Windows Server/NAS)/Windowsイベント/資産管理(SKYSEA等)"},
    4: {"name": "制限なし", "desc": "+ ルーター/ファイアウォール等ネットワーク機器すべて"},
}

# source_type → 必要ティア
CATEGORY_TIER: dict[str, int] = {
    "web_access": 1, "web_error": 1,
    "auth": 2, "system": 2, "nas": 2, "mail": 2, "application": 2, "linux": 2,
    "smb": 3, "windows_event": 3, "asset": 3,
    "router": 4, "firewall": 4, "dns": 4, "dhcp": 4,
}
# APIオプションでのみ許可（M365/Google Workspace等のコネクタ取得）
CONNECTOR_TYPES = {"google_workspace_audit", "m365_audit", "entra_signin"}

# データ保持期間（DB上のイベントを自動削除するまでの日数）。
# Tierに関係なく全ライセンス共通の既定＝90日。延長は「拡張ライセンス」（tierとは独立）で行う。
DEFAULT_RETENTION_DAYS = 90
RETENTION_PRESETS = {
    "default": DEFAULT_RETENTION_DAYS,
    "1y": 365,
    "3y": 365 * 3,
    "unlimited": -1,  # 削除しない
}


@dataclass
class Lic:
    licensee: str | None
    tier: int
    api_enabled: bool
    expires_at: float | None  # epoch秒
    source: str               # "applied" / "default"
    retention_days: int | None = None  # None=未指定(既定90日) / -1=無制限


def retention_days(lic: Lic) -> int:
    """有効な保持日数。ライセンスで上書きされていなければ既定90日。"""
    if lic.retention_days is None:
        return DEFAULT_RETENTION_DAYS
    return lic.retention_days


def required_tier(source_type: str | None) -> int:
    if not source_type:
        return 4
    return CATEGORY_TIER.get(source_type, 4)  # 未知は最上位扱い（制限なしでのみ）


def is_connector(source_type: str | None) -> bool:
    return (source_type or "") in CONNECTOR_TYPES


def is_allowed(source_type: str | None, lic: Lic) -> bool:
    if is_connector(source_type):
        return lic.api_enabled
    return required_tier(source_type) <= lic.tier


def blocked_source_types(lic: Lic) -> set[str]:
    """このライセンスで『使えない』source_type 集合（画面/検索から除外する）。
    受信は拒否しない（送られたものは保存する）。表示・選択のみ制限。"""
    blocked = {st for st, t in CATEGORY_TIER.items() if t > lic.tier}
    if not lic.api_enabled:
        blocked |= CONNECTOR_TYPES
    return blocked


# ---- 署名キー（base64(json).hexsig）----
def _sign(body: str) -> str:
    return hmac.new(settings.LICENSE_SECRET.encode(), body.encode(), hashlib.sha256).hexdigest()


def issue_key(payload: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
    return f"{body}.{_sign(body)}"


def verify_key(key: str) -> dict | None:
    try:
        body, sig = key.strip().split(".", 1)
        if not hmac.compare_digest(sig, _sign(body)):
            return None
        data = json.loads(base64.urlsafe_b64decode(body.encode()).decode())
        if data.get("exp") and time.time() > float(data["exp"]):
            return None  # 期限切れ
        return data
    except Exception:
        return None


_cache: dict = {"lic": None, "ts": 0.0}


def current_license(db: Session, force: bool = False) -> Lic:
    """適用中ライセンス（最新1件）。無ければ既定（env）。30秒キャッシュ。"""
    now = time.time()
    if not force and _cache["lic"] and now - _cache["ts"] < 30:
        return _cache["lic"]
    row = db.execute(select(License).order_by(License.id.desc()).limit(1)).scalar_one_or_none()
    if row and (row.expires_at is None or row.expires_at.timestamp() > now):
        lic = Lic(row.licensee, row.tier, row.api_enabled,
                  row.expires_at.timestamp() if row.expires_at else None, "applied",
                  row.retention_days)
    else:
        lic = Lic(None, settings.LICENSE_DEFAULT_TIER, settings.LICENSE_DEFAULT_API, None, "default", None)
    _cache["lic"], _cache["ts"] = lic, now
    return lic


def invalidate_cache() -> None:
    _cache["ts"] = 0.0


def days_left(lic: Lic) -> int | None:
    if not lic.expires_at:
        return None
    return max(0, int((lic.expires_at - time.time()) // 86400))


def apply_license_key(db: Session, key: str) -> dict | None:
    """キーを検証して licenses テーブルへ保存（最新が有効）。戻り: payload or None。
    キーは tier/api/retention_days をすべて含む「完全な状態」として発行される
    （最新1件のみを参照するため。拡張ライセンスも tier/api を引き継いで再発行する）。"""
    data = verify_key(key)
    if not data:
        return None
    iat, exp = data.get("iat"), data.get("exp")
    db.add(License(
        licensee=data.get("name"), tier=int(data.get("tier", 1)), api_enabled=bool(data.get("api", False)),
        retention_days=data.get("retention_days"),
        issued_at=datetime.fromtimestamp(iat) if iat else None,
        expires_at=datetime.fromtimestamp(exp) if exp else None, key=key,
    ))
    db.commit()
    invalidate_cache()
    return data


def seed_env_key(db: Session, key: str | None) -> bool:
    """env の LICENSE_KEY は『初回の種まき』専用。DBに既にライセンスがあれば何もしない
    （利用者はWeb UIで管理＝DB優先。envが再起動でUI設定を上書きしない）。"""
    if not key:
        return False
    if db.execute(select(License).limit(1)).first():
        return False
    return apply_license_key(db, key) is not None
