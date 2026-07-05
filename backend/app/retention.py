"""データ保持期間（DB上のイベントの自動削除）。
※ あくまで「このアプリのDBから消す」だけ。送信元機器・外部システムのログには一切触れない（自己ホスト前提）。
既定は全ライセンス共通90日。延長（1年/3年/無制限）は拡張ライセンスで行う（license.py の retention_days）。
"""
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select

from .db import SessionLocal
from .license import current_license, retention_days
from .models import DeadLetter, Event

log = logging.getLogger("retention")

CHECK_INTERVAL_SEC = 6 * 3600  # 6時間おきに判定（削除自体は保持日数を跨いだ分だけ）


def cleanup_once(db) -> dict:
    """保持期間を過ぎたイベント/取り込み失敗を削除。戻り値: 削除件数など。
    無制限(-1)なら何もしない。"""
    lic = current_license(db, force=True)
    days = retention_days(lic)
    if days < 0:
        return {"enabled": False, "retention_days": -1, "deleted_events": 0, "deleted_dead_letters": 0}

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    # normalized_events / event_entities は ondelete=CASCADE なので Event 削除で連動して消える
    ev_count = db.scalar(select(func.count()).select_from(Event).where(Event.received_at < cutoff)) or 0
    if ev_count:
        db.execute(delete(Event).where(Event.received_at < cutoff))
    dl_count = db.scalar(select(func.count()).select_from(DeadLetter).where(DeadLetter.received_at < cutoff)) or 0
    if dl_count:
        db.execute(delete(DeadLetter).where(DeadLetter.received_at < cutoff))
    db.commit()
    if ev_count or dl_count:
        log.info("retention cleanup: deleted %d events, %d dead_letters (cutoff=%s, retention=%d days)",
                 ev_count, dl_count, cutoff.isoformat(), days)
    return {"enabled": True, "retention_days": days, "cutoff": cutoff.isoformat(),
            "deleted_events": ev_count, "deleted_dead_letters": dl_count}


def _loop() -> None:
    time.sleep(120)  # 起動直後はDB準備待ち
    while True:
        db = SessionLocal()
        try:
            cleanup_once(db)
        except Exception as e:  # noqa
            log.warning("retention cleanup error: %s", e)
        finally:
            db.close()
        time.sleep(CHECK_INTERVAL_SEC)


def start() -> None:
    threading.Thread(target=_loop, daemon=True).start()
