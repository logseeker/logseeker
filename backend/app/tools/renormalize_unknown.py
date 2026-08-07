"""【運用・修復用】source_type が未確定(NULL)のまま保存されている Event を、
現在の SourceTypeDetector ルールで再判定し、マッチすれば再正規化する。
detectors.py に windows_event ルールを追加した際の遡及適用のために作成したが、
今後同種のルール追加時にも使い回せる汎用ツール。
payload は無改変。source_type / normalized_events / event_entities のみ更新する。
どのルールにもマッチしなければ何もしない（従来通りNULL・Unknown表示のまま）。

  docker compose exec backend python -m app.tools.renormalize_unknown [--dry-run]
"""
import argparse

from ..db import SessionLocal
from ..detectors import detect_source_type
from ..geoip import asn_of, country_of
from ..models import Event, EventEntity, NormalizedEvent
from ..normalize import PARSER_VERSION, normalize
from ..pipeline import _NORM_COLS, _entities


def main() -> None:
    ap = argparse.ArgumentParser(description="source_type未確定(NULL)のEventを現行ルールで再判定・再正規化")
    ap.add_argument("--dry-run", action="store_true", help="対象件数のみ表示し、実際には書き込まない")
    args = ap.parse_args()

    db = SessionLocal()
    q = db.query(Event).filter(Event.source_type.is_(None))
    total = q.count()
    print(f"対象(source_type未確定): {total} 件")

    matched = 0
    for ev in q:
        st = detect_source_type(db, ev.payload)
        if not st:
            continue
        matched += 1
        if args.dry_run:
            continue

        ev.source_type = st
        ev.parser_name = f"{st}_parser"
        ev.parser_version = PARSER_VERSION

        norm, status = normalize(ev.payload, ev.source, st)
        ev.parse_status = status
        if norm.get("source_ip"):
            country = country_of(norm["source_ip"])
            if country:
                norm["source_country"] = country
            asn, as_org = asn_of(norm["source_ip"])
            if asn:
                norm["source_asn"] = asn
            if as_org:
                norm["source_as_org"] = as_org

        db.query(NormalizedEvent).filter(NormalizedEvent.event_id == ev.id).delete()
        db.query(EventEntity).filter(EventEntity.event_id == ev.id).delete()
        db.flush()

        ne = NormalizedEvent(event_id=ev.id, **{k: v for k, v in norm.items() if k in _NORM_COLS})
        db.add(ne)
        for etype, evalue, role in _entities(norm):
            db.add(EventEntity(event_id=ev.id, entity_type=etype, entity_value=evalue, role=role))

        if matched % 500 == 0:
            db.commit()
            print(f"  ...{matched}/{total}")

    if not args.dry_run:
        db.commit()
    db.close()
    prefix = "(dry-run) " if args.dry_run else ""
    print(f"{prefix}完了: {matched} 件が現行ルールにマッチし再判定・再正規化されました"
          f"（{total - matched} 件は引き続き未判定のまま）")


if __name__ == "__main__":
    main()
