"""ingest pipeline（PROJECT.md §6）。REST/TCP/connector/file すべてここを通る。
受信 → payload保存 → timestamp/parser/taxonomy → normalized_events 保存。payload は無改変。"""
import logging

from sqlalchemy.orm import Session

from .detectors import detect_source_type
from .geoip import asn_of, country_of
from .models import DeadLetter, Event, EventEntity, NormalizedEvent
from .normalize import PARSER_VERSION, normalize

log = logging.getLogger("pipeline")
_NORM_COLS = set(NormalizedEvent.__table__.columns.keys()) - {"event_id"}

# syslogのファシリティ/ログファイル名（secure, messages等）はPROJECT.mdの方針により
# source_type として使わない。NXLog経由のLinuxログは source_type="linux" に一本化する
# （どのログファイル由来かは payload の SourceModuleName 等、他フィールドで判別する）。
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

    db.add(ev)
    db.flush()  # ev.id を確定
    ne = NormalizedEvent(event_id=ev.id, **{k: v for k, v in norm.items() if k in _NORM_COLS})
    db.add(ne)
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
