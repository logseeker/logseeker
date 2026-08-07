"""受信ペイロードのバイト数記録・集計（転送量把握用。件数ベースの既存統計を補う）。
記録は本来のログ取り込みとは独立した別セッションで行い、失敗しても例外を外へ投げない
（バイト数記録の失敗が本来のログ取り込みを止めてはならないため）。
時間別/日別の区切りはJST基準（運用者向け表示に合わせる。timeparse.pyのJST定数と同じ+9:00固定、
DST無し）。received_at自体はTIMESTAMPTZ=絶対時刻のままで、集計時の境界だけJSTで区切る。"""
import logging
from datetime import date, datetime, timedelta, timezone

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


def bytes_daily(db: Session, start: date | None = None, end: date | None = None, days: int = 31) -> list[dict]:
    """指定期間(JST日付、両端含む)の日別合計転送バイト数。start/end省略時は直近days日分（従来動作）。
    データが無い日も0で埋める。"""
    today = datetime.now(JST).date()
    if end is None:
        end = today
    if start is None:
        start = end - timedelta(days=days - 1)
    if start > end:
        start, end = end, start
    range_start = datetime.combine(start, datetime.min.time(), tzinfo=JST)
    range_end = datetime.combine(end, datetime.min.time(), tzinfo=JST) + timedelta(days=1)
    # date_trunc の区切りはPostgresセッションのTimeZone設定に依存するため、
    # 環境差でずれないよう明示的にJST(Asia/Tokyo)で区切る。
    day = func.date_trunc("day", IngestStat.received_at, "Asia/Tokyo")
    rows = db.execute(
        select(day.label("day"), func.sum(IngestStat.bytes))
        .where(IngestStat.received_at >= range_start, IngestStat.received_at < range_end)
        .group_by(day.label("day"))
    ).all()
    by_day = {d.date(): int(b or 0) for d, b in rows}
    n_days = (end - start).days + 1
    return [{"day": (start + timedelta(days=i)).isoformat(), "bytes": by_day.get(start + timedelta(days=i), 0)}
            for i in range(n_days)]


def bytes_hourly(db: Session, day: date | None = None) -> list[dict]:
    """指定日(JST, 0時スタート)の時間別合計転送バイト数。day省略時は本日（従来動作）。
    本日分は現在時刻までの時間帯のみ、過去日は0時〜23時まで全て返す（データが無い時間帯も0で埋める）。
    未来日はデータが存在し得ないため空配列を返す。"""
    now_jst = datetime.now(JST)
    today = now_jst.date()
    if day is None:
        day = today
    if day > today:
        return []
    day_start = datetime.combine(day, datetime.min.time(), tzinfo=JST)
    day_end = day_start + timedelta(days=1)
    hour = func.date_trunc("hour", IngestStat.received_at, "Asia/Tokyo")
    rows = db.execute(
        select(hour.label("hour"), func.sum(IngestStat.bytes))
        .where(IngestStat.received_at >= day_start, IngestStat.received_at < day_end)
        .group_by(hour.label("hour"))
    ).all()
    by_hour = {h.hour: int(b or 0) for h, b in rows}
    last_hour = now_jst.hour if day == today else 23
    return [{"hour": (day_start + timedelta(hours=i)).isoformat(), "bytes": by_hour.get(i, 0)}
            for i in range(last_hour + 1)]
