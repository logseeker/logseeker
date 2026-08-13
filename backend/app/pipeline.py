"""ingest pipeline（PROJECT.md §6）。REST/TCP/connector/file すべてここを通る。
受信 → payload保存 → 時刻解決/分類/GeoIP → events の導出列へ保存。payload は無改変。"""
import logging

from sqlalchemy.orm import Session

from .detectors import detect_source_type
from .geoip import asn_of, country_of
from .models import DeadLetter, Event, EventEntity
from .normalize import PARSER_VERSION, normalize

log = logging.getLogger("pipeline")
# normalize() が返した値のうち、events の列として持っているものだけを書き戻す。
_EVENT_DERIVED_COLS = {
    "event_time", "event_time_original", "event_time_confidence", "event_category",
    "event_action", "event_result", "event_severity", "source_name", "device_name",
    "source_country", "source_asn", "source_as_org", "source_ip", "actor_user",
    "url_domain", "url_path", "url_query", "http_method", "http_status_code", "host_name",
    "observer_name", "service_name", "network_protocol", "message",
}

# syslogのファシリティ/ログファイル名（secure, messages等）はPROJECT.mdの方針により
# source_type として使わない。NXLog経由のLinuxログは source_type="linux" に一本化する
# （どのログファイル由来かは payload の SourceModuleName 等、他フィールドで判別する）。
# audit（auditd由来、type=USER_LOGIN等）は、nxlog側でtype/res/acct/exe/SourceIPAddressを
# フィールド化して送るようになったため、2026-08-09以降はlinuxに寄せず独立source_typeとして
# 扱う（Taxonomy KEY の audit_type / audit_res / audit_acct を直接読む）。
_SOURCE_TYPE_ALIASES = {"secure": "linux", "messages": "linux"}

# 正規化フィールド → 相関エンティティ (entity_type, role)
# エンティティ＝相関・調査の対象になる「資産／主体／観測可能な指標」だけを持つ。
# URLパスやリクエストIDは“リクエストの属性”であって資産ではないのでここには入れない
# （それらは Events / レコード詳細で見る）。
_ENTITY_MAP = [
    ("source_ip", "ip", "source"),
    ("actor_user", "user", "actor"),
    ("target_user", "user", "target"),
    ("device_name", "host", "observer"),
    ("host_name", "host", "target"),
    ("url_domain", "domain", None),
    ("mac_address", "mac", None),
]


def _entities(norm: dict) -> list[tuple[str, str, str | None]]:
    seen, out = set(), []

    def add(etype: str, value, role=None):
        if not value:
            return
        val = str(value)[:512]
        if (etype, val) in seen:
            return
        seen.add((etype, val))
        out.append((etype, val, role))

    for field, etype, role in _ENTITY_MAP:
        add(etype, norm.get(field), role)
    # メールアドレスはユーザーとは別軸でも引けるように email としても登録
    for field, role in (("actor_user", "actor"), ("target_user", "target")):
        v = norm.get(field)
        if v and "@" in str(v):
            add("email", v, role)
    return out


def ingest_one(
    db: Session,
    payload: dict,
    source: str | None = None,
    source_type: str | None = None,
    channel: str = "api",
    receiver_ip: str | None = None,
) -> Event:
    """1イベントを保存＋正規化。受信は常に保存する（ライセンスは表示/選択側で制限）。commit は呼び出し側。
    source_type が明示されていれば常にそれを信頼する（既存ロジック維持）。未指定の場合のみ、
    payload のキー構成を source_type_detectors と照合して自動判定する（§7.8補足）。
    どれにもマッチしなければ None のまま（従来通り Event.source_type=NULL → UI "Unknown" 表示）。"""
    if not source_type:
        source_type = detect_source_type(db, payload)
    source_type = _SOURCE_TYPE_ALIASES.get(source_type, source_type)

    ev = Event(
        payload=payload,
        source=source,
        source_type=source_type,
        ingest_channel=channel,
        receiver_ip=receiver_ip,
        parser_name=f"{source_type}_parser" if source_type else "generic_json_parser",
        parser_version=PARSER_VERSION,
    )
    try:
        norm, status = normalize(payload, source, source_type)
        ev.parse_status = status
        # GeoIP: mmdb があれば国コード・ASNを付与（無ければ null のまま。オフライン・ローカル処理のみ）
        if norm.get("source_ip"):
            country = country_of(norm["source_ip"])
            if country:
                norm["source_country"] = country
            asn, as_org = asn_of(norm["source_ip"])
            if asn:
                norm["source_asn"] = asn
            if as_org:
                norm["source_as_org"] = as_org
    except Exception as e:  # 正規化に失敗しても payload は保存する（§19.1）
        log.warning("normalize failed: %s", e)
        norm, ev.parse_status, ev.parse_error = {}, "failed", str(e)

    # 導出値は events 自身の列に持つ（旧 normalized_events は廃止）。
    for k, v in norm.items():
        if k in _EVENT_DERIVED_COLS:
            setattr(ev, k, v)
    db.add(ev)
    db.flush()  # ev.id を確定
    for etype, evalue, role in _entities(norm):
        db.add(EventEntity(event_id=ev.id, entity_type=etype, entity_value=evalue, role=role))
    return ev


def dead_letter(
    db: Session,
    raw_text: str,
    error_type: str,
    error_message: str,
    channel: str = "api",
    source: str | None = None,
    source_type: str | None = None,
    receiver_ip: str | None = None,
) -> None:
    db.add(DeadLetter(
        raw_text=raw_text, error_type=error_type, error_message=error_message,
        ingest_channel=channel, source=source, source_type=source_type, receiver_ip=receiver_ip,
    ))
