"""DBスキーマ（PROJECT.md §9）。
payload は受信JSONを無改変で保存し、その外側に正規化(normalized_events)を派生生成する。
MVP1/2 範囲: events / normalized_events / dead_letters。
（event_entities / annotations / incidents / rule_hits などは後続MVPで追加）
"""
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _now() -> datetime:
    return datetime.now().astimezone()


class Event(Base):
    """受信イベント本体。payload は無改変。"""
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    ingest_channel: Mapped[str] = mapped_column(String(16), default="api")  # api / tcp / connector / file
    source: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    source_type: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    receiver_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)

    payload: Mapped[dict] = mapped_column(JSONB)             # 受信JSONそのもの
    parser_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parser_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    parse_status: Mapped[str] = mapped_column(String(16), default="success")  # success/partial/failed
    parse_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)  # 対応済み/未対応（ケース紐付けとは独立）

    normalized: Mapped["NormalizedEvent"] = relationship(
        back_populates="event", uselist=False, cascade="all, delete-orphan"
    )


class NormalizedEvent(Base):
    """検索・集計・相関に使う正規化済みフィールド（軽量タクソノミー §8）。不明は null。"""
    __tablename__ = "normalized_events"

    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)

    # event 系
    event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True, nullable=True)
    event_time_original: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_time_confidence: Mapped[str | None] = mapped_column(String(8), nullable=True)  # high/medium/low/none
    event_category: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    event_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    event_action: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    event_result: Mapped[str | None] = mapped_column(String(16), index=True, nullable=True)
    event_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    event_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # source/observer 系
    source_name: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)  # 表示用ログソース名
    device_name: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)  # 機器/ホスト（推定しない）
    observer_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    observer_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    service_name: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # actor/user 系
    actor_user: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    actor_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_user: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # network 系
    source_ip: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    source_country: Mapped[str | None] = mapped_column(String(4), index=True, nullable=True)  # ISO国コード（GeoIP mmdb 未設定時は null）
    source_asn: Mapped[int | None] = mapped_column(BigInteger, nullable=True)  # AS番号（GeoIP ASN mmdb 未設定時は null）
    source_as_org: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)  # AS組織名（同上）
    source_port: Mapped[str | None] = mapped_column(String(16), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_port: Mapped[str | None] = mapped_column(String(16), nullable=True)
    network_protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    network_transport: Mapped[str | None] = mapped_column(String(8), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # host 系
    host_name: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    target_host: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # web 系
    url_domain: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    url_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    url_query: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    http_status_code: Mapped[str | None] = mapped_column(String(8), index=True, nullable=True)
    http_user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_referer: Mapped[str | None] = mapped_column(Text, nullable=True)
    request: Mapped[str | None] = mapped_column(Text, nullable=True)

    # resource/file 系
    target_resource: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    event: Mapped["Event"] = relationship(back_populates="normalized")


class DeadLetter(Base):
    """不正JSON・処理失敗イベント（§9.8）。"""
    __tablename__ = "dead_letters"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    ingest_channel: Mapped[str | None] = mapped_column(String(16), nullable=True)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    receiver_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class IngestStat(Base):
    """受信ペイロードのバイト数記録（転送量集計用。件数だけでなくMB/GB規模を把握するため）。
    非圧縮JSON前提：受信バイト数 ≒ 実ログ量。将来gzip等の圧縮転送を導入する場合は、
    展開後サイズ用に uncompressed_bytes 等を後から追加できる（このテーブルはそのための
    拡張余地として bytes 以外の詳細を持たせず単純にしてある）。"""
    __tablename__ = "ingest_stats"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)


class SourceTypeDetector(Base):
    """payloadのキー構成からsource_typeを自動判定するルール（§7.8補足）。
    source_type が未指定のイベントにのみ使う。値の推定（device_name等）とは別物。"""
    __tablename__ = "source_type_detectors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_type: Mapped[str] = mapped_column(String(64), index=True)
    required_keys: Mapped[list] = mapped_column(JSONB, default=list)   # 全て存在すれば候補になる(AND)
    optional_keys: Mapped[list] = mapped_column(JSONB, default=list)   # 存在する分だけ加点
    key_value_hints: Mapped[dict] = mapped_column(JSONB, default=dict)  # {key: [期待値...]} 一致で加点
    priority: Mapped[int] = mapped_column(Integer, default=100)         # 同点時、小さい方を優先
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class EventEntity(Base):
    """相関調査用エンティティ（§9.3）。IP/ユーザー/ホスト/ドメイン/MAC/URL等。"""
    __tablename__ = "event_entities"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    entity_type: Mapped[str] = mapped_column(String(32), index=True)
    entity_value: Mapped[str] = mapped_column(String(512), index=True)
    role: Mapped[str | None] = mapped_column(String(16), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Asset(Base):
    """ユーザー登録のグローバルIP資産（§7.10）。ローカル(プライベート)IPはipaddress.is_private
    で自動判定するため登録(label/description)は不要だが、表示名(display_name)のみは
    ローカルIPにも軽量に付与できる（api.py の /assets/local/{ip} 参照）。"""
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    ip_version: Mapped[str] = mapped_column(String(2))  # v4 / v6
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class Case(Base):
    """ケース＝複数イベントを束ねる調査ワークスペース（設計書v4 3章）。ステータス・判定結果・
    担当者を持たない。インシデントに「昇格」する概念も無い（ケースとインシデントは完全に独立）。"""
    __tablename__ = "cases"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class CaseEvent(Base):
    """ケースとイベントの紐付け（v1の IncidentEvent をリネーム）。「注目」以外のイベントも
    自由に追加できる（設計書v4 3章：v3までの注目イベント限定制限は撤廃）。
    同一ペアの多重登録を防ぐUNIQUE制約付き。"""
    __tablename__ = "case_events"
    __table_args__ = (UniqueConstraint("case_id", "event_id", name="uq_case_event"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CaseComment(Base):
    """ケースへの調査メモ（v1の IncidentComment をリネーム）。ケース側は監査ログを持たず
    コメントのみで調査記録を残す（設計書v2 3章）。"""
    __tablename__ = "case_comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    body: Mapped[str] = mapped_column(Text)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, onupdate=_now)


class Incident(Base):
    """インシデント＝確定した事案（設計書v4 4章）。「1つの注目アラート(event_id)」に対して直接
    生成される、アラートと1:1の対応記録。ケースには一切依存しない（case_idは持たない）。
    1アラートにつき最大1件（event_id にUNIQUE制約）。

    event_id は ON DELETE SET NULL（NOT NULLではない）: インシデントは「確定した事案の記録」
    であり、ステータス履歴・監査ログ・コメント・対応アクションを含む対応記録そのもの。
    保持期間切れで元イベント(生ログ)がretention.pyにより自動削除されても、インシデント本体と
    その対応記録は失われるべきではないため、CASCADEではなくSET NULLを採用する
    （2026-08-09、コードレビューで発見・ユーザー確認の上で対応。以前はNOT NULL+ON DELETE無指定
    (NO ACTION)だったため、インシデント化済みイベントが1件でもあると保持期間の一括削除が
    外部キー違反で丸ごと失敗する不具合があった）。"""
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id", ondelete="SET NULL"),
                                                  unique=True, index=True, nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    status_id: Mapped[int | None] = mapped_column(ForeignKey("incident_statuses.id"), nullable=True, index=True)
    assignee_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    verdict: Mapped[str] = mapped_column(String(24), default="unjudged")  # unjudged/true_positive/false_positive/over_detection/other
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class IncidentStatus(Base):
    """インシデントのステータスマスタ（指示書3-3節→設計書v2 4-2節でインシデント側に移設）。
    special_type で未対応/完了/再オープンを識別し、名称変更・追加があっても遷移ルールの骨格が
    崩れないようにする（incident_status.py参照）。"""
    __tablename__ = "incident_statuses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64))
    special_type: Mapped[str | None] = mapped_column(String(16), nullable=True)  # unassigned/done/reopened/None
    is_visible: Mapped[bool] = mapped_column(Boolean, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=100)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class IncidentStatusHistory(Base):
    """インシデントのステータス遷移履歴（指示書2章→設計書v2 4-2節）。"""
    __tablename__ = "incident_status_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    from_status_id: Mapped[int | None] = mapped_column(ForeignKey("incident_statuses.id"), nullable=True)
    to_status_id: Mapped[int] = mapped_column(ForeignKey("incident_statuses.id"))
    changed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class IncidentAuditLog(Base):
    """インシデント管理機能の監査ログ（指示書4-2節→設計書v2 4-3節）。システム生成のみ（コメントは
    含まない。コメントは IncidentComment）。記録対象はインシデント側の操作のみ（ケース側の操作は
    記録しない）。incident_id は null 可＝ステータスマスタ管理操作など単一インシデントに
    紐付かない操作も記録できるようにするため。"""
    __tablename__ = "incident_audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    action_type: Mapped[str] = mapped_column(String(32), index=True)
    before_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    after_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class IncidentComment(Base):
    """インシデント自身の調査コメント（設計書v2 4-1節。ケースのコメントとは別物＝複製しない。
    ケースのコメント履歴は「元ケースへのリンク」から参照する）。"""
    __tablename__ = "incident_comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    body: Mapped[str] = mapped_column(Text)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, onupdate=_now)


class IncidentResponseActionType(Base):
    """対応アクションの種別マスタ（設計書v2 4-4節）。ステータスマスタと同様、sysadmin以上が
    追加・非表示化できる。既定5種は migrations.py でseedする。"""
    __tablename__ = "incident_response_action_types"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64))
    is_visible: Mapped[bool] = mapped_column(Boolean, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, default=100)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)


class IncidentResponseAction(Base):
    """構造化された対応記録（種別＋詳細メモ＋実施者＋実施日時。設計書v2 4-4節）。"""
    __tablename__ = "incident_response_actions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    action_type_id: Mapped[int] = mapped_column(ForeignKey("incident_response_action_types.id"))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class License(Base):
    """適用中のライセンス（最新1件を有効とみなす）。tier と APIオプションで機能を制御。
    retention_days: データ保持日数の上書き（null=既定90日 / -1=無制限）。Tierとは独立した「拡張ライセンス」。"""
    __tablename__ = "licenses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    licensee: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tier: Mapped[int] = mapped_column(Integer, default=1)
    api_enabled: Mapped[bool] = mapped_column(default=False)
    retention_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    key: Mapped[str | None] = mapped_column(Text, nullable=True)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class IOC(Base):
    """脅威情報（Indicator of Compromise）。既知の不正IP/ドメイン等。
    外部フィード（abuse.ch等）や手元の観測値を load_ioc で取り込む。オフライン運用可。"""
    __tablename__ = "ioc"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    indicator_type: Mapped[str] = mapped_column(String(16), index=True)  # ip / domain
    value: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class IocFeed(Base):
    """脅威インテリフィード設定（AbuseIPDB / OTX 等）。APIキーは画面から登録。"""
    __tablename__ = "ioc_feeds"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(32), unique=True, index=True)  # abuseipdb / otx
    api_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    enabled: Mapped[bool] = mapped_column(default=False)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_count: Mapped[int] = mapped_column(Integer, default=0)


class Setting(Base):
    """汎用キーバリュー設定（同期間隔など）。changelogキャッシュのような大きめの値も
    入るため Text（255文字制限だと changelog_cache_json 等が入りきらずエラーになる）。"""
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)


class User(Base):
    """ログインユーザー。role: viewer/editor/sysadmin/admin（Linuxのuser/sudo/rootに対応）。
    ローカル認証は password_hash(pbkdf2)。SSOユーザーは sso_subject を持ち password_hash は空。"""
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # viewer/editor/sysadmin/admin
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sso_subject: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)  # OIDC sub
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UserSettings(Base):
    """ユーザーごとの画面設定（お知らせの既読状態など）。ログイン中のみ使う
    （認証OFF時はユーザーが定まらないため、フロント側はlocalStorageにフォールバックする）。"""
    __tablename__ = "user_settings"
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    last_dismissed_release: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Events一覧のClass別追加列設定。JSON文字列: {source_type: [payloadキー, ...]}（表示順）。
    # 未設定のClassはキー無し＝追加列なし（固定共通列のみ表示）。
    events_columns: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuthSession(Base):
    """ログインセッション（Bearerトークン）。token_hash のみ保存（平文は保持しない）。"""
    __tablename__ = "auth_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    """監査ログ：ログイン後にユーザーが行った操作（変更系・ログイン・ダウンロード等）。"""
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    username: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    role: Mapped[str | None] = mapped_column(String(16), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)          # login/logout/user.create 等
    method: Mapped[str | None] = mapped_column(String(8), nullable=True)
    path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str | None] = mapped_column(String(16), nullable=True)  # success/failure/HTTPコード
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)


class CustomRule(Base):
    """ユーザー定義の検知ルール（画面から作成）。固定の正規化フィールドに対する
    部分一致/完全一致＋件数しきい値のみ（任意コード実行はしない＝安全）。"""
    __tablename__ = "custom_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="warning")  # critical/high/warning
    enabled: Mapped[bool] = mapped_column(default=True)
    match_field: Mapped[str] = mapped_column(String(32))   # 許可済みフィールド名（rules.FIELD_MAP参照）
    match_op: Mapped[str] = mapped_column(String(16), default="contains")  # contains/equals
    match_value: Mapped[str] = mapped_column(String(512))
    group_by: Mapped[str | None] = mapped_column(String(32), nullable=True)  # 集計軸（未指定なら総数のみ）
    min_count: Mapped[int] = mapped_column(Integer, default=1)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Annotation(Base):
    """イベントへのコメント・タグ（§9.4）。"""
    __tablename__ = "annotations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[str | None] = mapped_column(String(512), nullable=True)  # カンマ区切り
    created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


# よく使う正規化軸の複合インデックス
from sqlalchemy import Index  # noqa: E402

Index("ix_norm_cat_time", NormalizedEvent.event_category, NormalizedEvent.event_time)
Index("ix_norm_result_time", NormalizedEvent.event_result, NormalizedEvent.event_time)
Index("ix_entity_type_value", EventEntity.entity_type, EventEntity.entity_value)
Index("ix_ioc_type_value", IOC.indicator_type, IOC.value)
