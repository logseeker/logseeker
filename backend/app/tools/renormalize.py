"""【運用・修復用】既に取り込み済みの Event を source_type のエイリアス修正後の
ロジックで再正規化する（pipeline.ingest_one の _SOURCE_TYPE_ALIASES 修正に追随）。

対象: source_type が "secure" / "messages" のまま保存されている Event
（本来は "linux" に統一される想定。§ CLAUDE.md「syslogを分類として使わない」）。
payload は無改変。source_type / normalized_events / event_entities のみ更新する。

  docker compose exec backend python -m app.tools.renormalize
"""
import argparse

from ..db import SessionLocal
from ..geoip import country_of
from ..models import Event, EventEntity, NormalizedEvent
from ..normalize import normalize
from ..pipeline import _NORM_COLS, _entities

TARGET_SOURCE_TYPES = ("secure", "messages")


def main() -> None:
    ap = argparse.ArgumentParser(description="旧 source_type(secure/messages) の Event を再正規化")
    ap.add_argument("--dry-run", action="store_true", help="更新件数のみ表示し、実際には書き込まない")
    args = ap.parse_args()

    db = SessionLocal()
    q = db.query(Event).filter(Event.source_type.in_(TARGET_SOURCE_TYPES))
    total = q.count()
    print(f"対象: {total} 件 (source_type in {TARGET_SOURCE_TYPES})")

    if args.dry_run:
        db.close()
        return

    fixed = 0
    for ev in q:
        ev.source_type = "linux"
        ev.parser_name = "linux_parser"

        norm, status = normalize(ev.payload, ev.source, ev.source_type)
        ev.parse_status = status
        if norm.get("source_ip"):
            country = country_of(norm["source_ip"])
            if country:
                norm["source_country"] = country

        db.query(NormalizedEvent).filter(NormalizedEvent.event_id == ev.id).delete()
        db.query(EventEntity).filter(EventEntity.event_id == ev.id).delete()
        db.flush()

        ne = NormalizedEvent(event_id=ev.id, **{k: v for k, v in norm.items() if k in _NORM_COLS})
        db.add(ne)
        for etype, evalue, role in _entities(norm):
            db.add(EventEntity(event_id=ev.id, entity_type=etype, entity_value=evalue, role=role))

        fixed += 1
        if fixed % 500 == 0:
            db.commit()
            print(f"  ...{fixed}/{total}")

    db.commit()
    db.close()
    print(f"完了: {fixed} 件を source_type=linux で再正規化しました")


if __name__ == "__main__":
    main()
