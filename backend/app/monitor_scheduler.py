"""定期監視スケジューラ：ルール評価（攻撃兆候・ログ未達・カスタムルール）→通知。
IOC同期の有無に関わらず、一定間隔（既定1時間）で必ず動く。"""
import logging
import threading
import time

from .db import SessionLocal

log = logging.getLogger("monitor_scheduler")

CHECK_INTERVAL_SEC = 3600  # 1時間おき。silence_hours(既定24h)を十分な粒度で捕捉できる間隔。


def _loop() -> None:
    time.sleep(180)  # 起動直後はDB準備待ち
    while True:
        db = SessionLocal()
        try:
            from .notify import notify_hits
            from .rules import evaluate
            hits = evaluate(db)
            res = notify_hits(db, hits)
            if not res.get("skipped"):
                log.info("定期監視 通知送信: %s", res)
        except Exception as e:  # noqa
            log.warning("monitor scheduler error: %s", e)
        finally:
            db.close()
        time.sleep(CHECK_INTERVAL_SEC)


def start() -> None:
    threading.Thread(target=_loop, daemon=True).start()
