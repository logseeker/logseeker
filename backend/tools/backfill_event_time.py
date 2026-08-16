# -*- coding: utf-8 -*-
"""既存イベントの event_time を現在の解決ロジックで再計算する（payload は無改変）。

2026-08-16、時刻解決の優先順を EventReceivedTime → EventTime から
EventTime → EventReceivedTime へ変更した（発生時刻を受信時刻より優先）。
その変更を既存行へ反映するための一度きりの補正。

安全のための設計:
  - payload は一切書き換えない。event_time / event_time_original /
    event_time_confidence の3列だけを更新する
  - id順に --batch 件ずつ処理し、バッチごとにcommitする。
    メモリ常駐は1バッチ分だけなので、2GBの本番でも安全に流せる
  - --dry-run で件数だけを数える（更新しない）
  - --sleep でバッチ間に待ちを入れ、I/Oを譲る

使い方:
    # 開発(Docker)
    docker exec logseeker-backend-1 python /app/tools/backfill_event_time.py --dry-run
    # 本番(ネイティブ)
    cd /opt/logseeker/backend && sudo -u logseeker env $(grep -h '^DATABASE_URL' .env | xargs)         ../venv/bin/python tools/backfill_event_time.py --dry-run
"""
import argparse
import sys
import time
from pathlib import Path

# 実行環境によっては backend/ が sys.path に無いので通す（check_unused_tables.py と同じ）
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sqlalchemy import select, func
from app.db import SessionLocal
from app.models import Event
from app.timeparse import resolve_time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--batch', type=int, default=5000, help='1バッチの件数')
    ap.add_argument('--sleep', type=float, default=0.0, help='バッチ間の待ち秒数')
    ap.add_argument('--dry-run', action='store_true', help='件数を数えるだけで更新しない')
    ap.add_argument('--limit', type=int, default=0, help='処理する最大件数（0=全件。動作確認用）')
    a = ap.parse_args()

    db = SessionLocal()
    total = db.execute(select(func.count()).select_from(Event)).scalar() or 0
    print('対象イベント: %d件 / batch=%d / dry-run=%s' % (total, a.batch, a.dry_run))

    last_id, seen, changed, to_null, from_null = 0, 0, 0, 0, 0
    t0 = time.time()
    while True:
        rows = db.execute(
            select(Event.id, Event.payload, Event.event_time)
            .where(Event.id > last_id).order_by(Event.id).limit(a.batch)
        ).all()
        if not rows:
            break
        updates = []
        for eid, payload, old in rows:
            last_id = eid
            seen += 1
            new, original, conf = resolve_time(payload or {})
            if new == old:
                continue
            changed += 1
            if old is not None and new is None:
                to_null += 1
            if old is None and new is not None:
                from_null += 1
            updates.append({'b_id': eid, 'event_time': new,
                            'event_time_original': original, 'event_time_confidence': conf})
        if updates and not a.dry_run:
            db.connection().execute(
                Event.__table__.update()
                .where(Event.__table__.c.id == __import__('sqlalchemy').bindparam('b_id')),
                updates,
            )
            db.commit()
        else:
            db.rollback()
        if a.limit and seen >= a.limit:
            break
        if a.sleep:
            time.sleep(a.sleep)

    print('走査 %d件 / 変化 %d件 (%.2f%%) / NULLになった %d件 / NULLから復活 %d件 / %.1f秒'
          % (seen, changed, (changed * 100.0 / seen) if seen else 0.0, to_null, from_null, time.time() - t0))
    if to_null:
        print('警告: event_time がNULLになった行がある。解決できなくなったキーがないか確認すること。')
    db.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
