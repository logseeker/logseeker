"""脅威インテリ自動同期スケジューラ。設定間隔（既定6h、画面で3/6/12/24h）ごとに sync_all。"""
import logging
import threading
import time

from .db import SessionLocal
from .ioc_sync import get_sync_hours, sync_all

log = logging.getLogger("ioc_scheduler")


def _loop() -> None:
    next_run = time.time() + 120  # 起動2分後に初回（DB準備待ち）
    while True:
        time.sleep(60)  # 1分ごとに判定
        if time.time() < next_run:
            continue
        hours = 6
        db = SessionLocal()
        try:
            hours = get_sync_hours(db)
            res = sync_all(db)
            if res:
                log.info("IOC自動同期: %s", res)
            # 通知は monitor_scheduler が一元的に定期実行する（IOC同期の有無に関わらず動くように分離）
        except Exception as e:  # noqa
            log.warning("ioc scheduler error: %s", e)
        finally:
            db.close()
        next_run = time.time() + max(1, hours) * 3600


def start() -> None:
    threading.Thread(target=_loop, daemon=True).start()
