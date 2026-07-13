"""受信ペイロードのバイト数記録・集計（転送量把握用。件数ベースの既存統計を補う）。
記録は本来のログ取り込みとは独立した別セッションで行い、失敗しても例外を外へ投げない
（バイト数記録の失敗が本来のログ取り込みを止めてはならないため）。
時間別/日別の区切りはJST基準（運用者向け表示に合わせる。timeparse.pyのJST定数と同じ+9:00固定、
DST無し）。received_at自体はTIMESTAMPTZ=絶対時刻のままで、集計時の境界だけJSTで区切る。"""
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import IngestStat

log = logging.getLogger("ingest_stats")

JST = timezone(timedelta(hours=9))


def record_bytes(nbytes: int, source: str | None = None) -> None:
    db = SessionLocal()
    try:
        db.add(IngestStat(bytes=nbytes, source=source))
        db.commit()
    except Exception as e:  # noqa: 記録失敗で本来の取り込みを止めない
        db.rollback()
        log.warning("failed to record ingest_stats (bytes=%d, source=%s): %s", nbytes, source, e)
    finally:
        db.close()


def bytes_yesterday(db: Session) -> int:
    """前日(JST)の合計転送バイト数。"""
    now_jst = datetime.now(JST)
    today_start = now_jst.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)
    total = db.scalar(
        select(func.coalesce(func.sum(IngestStat.bytes), 0))
        .where(IngestStat.received_at >= yesterday_start, IngestStat.received_at < today_start)
    )
    return int(total or 0)


def total_bytes(db: Session) -> int:
    """記録開始以降の累計転送バイト数。"""
    total = db.scalar(select(func.coalesce(func.sum(IngestStat.bytes), 0)))
    return int(total or 0)


def avg_bytes(db: Session) -> float:
    """1件あたりの平均ログサイズ（バイト）。記録が無ければ0。"""
    avg = db.scalar(select(func.coalesce(func.avg(IngestStat.bytes), 0)))
    return float(avg or 0)


def bytes_recent_minutes(db: Session, minutes: int = 5) -> int:
    """直近N分間の合計転送バイト数（受信ペースの把握用）。"""
    since = datetime.now(JST) - timedelta(minutes=minutes)
    total = db.scalar(
        select(func.coalesce(func.sum(IngestStat.bytes), 0)).where(IngestStat.received_at >= since)
    )
    return int(total or 0)


def bytes_daily(db: Session, days: int = 31) -> list[dict]:
    """直近days日分の日別(JST)合計転送バイト数。"""
    since = datetime.now(JST) - timedelta(days=days)
    # date_trunc の区切りはPostgresセッションのTimeZone設定に依存するため、
    # 環境差でずれないよう明示的にJST(Asia/Tokyo)で区切る。
    day = func.date_trunc("day", IngestStat.received_at, "Asia/Tokyo")
    rows = db.execute(
        select(day.label("day"), func.sum(IngestStat.bytes))
        .where(IngestStat.received_at >= since)
        .group_by(day.label("day"))
        .order_by(day.label("day"))
    ).all()
    return [{"day": d.isoformat(), "bytes": int(b or 0)} for d, b in rows]


def bytes_hourly_today(db: Session) -> list[dict]:
    """本日(JST, 0時スタート)の時間別合計転送バイト数。データが無い時間帯も0で埋める。"""
    now_jst = datetime.now(JST)
    today_start = now_jst.replace(hour=0, minute=0, second=0, microsecond=0)
    hour = func.date_trunc("hour", IngestStat.received_at, "Asia/Tokyo")
    rows = db.execute(
        select(hour.label("hour"), func.sum(IngestStat.bytes))
        .where(IngestStat.received_at >= today_start)
        .group_by(hour.label("hour"))
    ).all()
    by_hour = {h.hour: int(b or 0) for h, b in rows}
    return [{"hour": (today_start + timedelta(hours=i)).isoformat(), "bytes": by_hour.get(i, 0)}
            for i in range(now_jst.hour + 1)]
