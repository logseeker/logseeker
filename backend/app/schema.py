"""APIスキーマ。
入力(生JSON)は構造を問わずそのまま受ける方針なので、入力用の固定スキーマは持たない。
ここでは応答用の型だけ定義する。"""
from pydantic import BaseModel, Field


class IngestResponse(BaseModel):
    accepted: int
    stored: int
    skipped: int
    detail: list[str] = Field(default_factory=list)


class IncidentCreate(BaseModel):
    title: str
    severity: str | None = None
    summary: str | None = None
    owner: str | None = None


class IncidentEventAdd(BaseModel):
    event_id: int
    note: str | None = None


class AnnotationCreate(BaseModel):
    comment: str | None = None
    tags: str | None = None
    created_by: str | None = None


class LicenseApply(BaseModel):
    key: str


class FeedUpdate(BaseModel):
    name: str                       # abuseipdb / otx
    api_key: str | None = None      # 空/未指定なら既存キー維持
    enabled: bool = False


class SyncSettings(BaseModel):
    sync_hours: int = 6


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str
    display_name: str | None = None
    role: str = "viewer"          # viewer/editor/sysadmin/admin
    # メール通知が有効なサーバーでは email 必須・ランダム仮パスワードを送信（password は無視）。
    # 無効なサーバーでは password 必須（従来通り管理者が手入力）。どちらが必須かは実行時に判定。
    email: str | None = None
    password: str | None = None


class UserUpdate(BaseModel):
    display_name: str | None = None
    role: str | None = None
    enabled: bool | None = None
    password: str | None = None   # 指定時のみ変更


class AuthToggle(BaseModel):
    enabled: bool


class CustomRuleCreate(BaseModel):
    name: str
    description: str | None = None
    severity: str = "warning"          # critical/high/warning
    match_field: str
    match_op: str = "contains"         # contains/equals
    match_value: str
    group_by: str | None = None
    min_count: int = 1
    recommendation: str | None = None
    enabled: bool = True


class CustomRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    severity: str | None = None
    match_field: str | None = None
    match_op: str | None = None
    match_value: str | None = None
    group_by: str | None = None
    min_count: int | None = None
    recommendation: str | None = None
    enabled: bool | None = None


class AssetCreate(BaseModel):
    ip: str
    label: str | None = None
    description: str | None = None


class AssetUpdate(BaseModel):
    label: str | None = None
    description: str | None = None


class SilenceSettings(BaseModel):
    hours: int = 24


class SSOConfig(BaseModel):
    enabled: bool = False
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""       # 空なら既存維持
    redirect_uri: str = ""
    allowed_domains: str = ""
    auto_provision_role: str = "viewer"


class DismissedRelease(BaseModel):
    tag_name: str


class NotificationConfig(BaseModel):
    email_enabled:  bool        = False
    email_host:     str         = ""
    email_port:     int         = 587
    email_user:     str         = ""
    email_pass:     str         = ""    # "***" のまま送信で既存パスワード維持
    email_from:     str         = ""
    email_to:       str         = ""    # カンマ区切り
    slack_enabled:  bool        = False
    slack_webhook:  str         = ""
    min_severity:   str         = "high"  # critical/high/warning
