"""検索・集計・ダッシュボードAPI（PROJECT.md §11）。events と normalized_events を結合して扱う。"""
import ipaddress
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import String, and_, case, cast, func, nulls_last, or_, select, text
from sqlalchemy.orm import Session

from .auth import get_current_user, require_editor, require_login, require_sysadmin
from .config import settings
from .db import get_db
from .models import Annotation, Asset, CustomRule, DeadLetter, Event, EventEntity, IOC, Incident, IncidentEvent
from .models import IocFeed, License, Setting, User, UserSettings
from .models import NormalizedEvent as N
from .schema import (AnnotationCreate, AssetCreate, AssetUpdate, CustomRuleCreate, CustomRuleUpdate,
                     DismissedRelease, FeedUpdate, IncidentCreate, IncidentEventAdd, LicenseApply,
                     NotificationConfig, SilenceSettings, SyncSettings)

router = APIRouter(prefix="/api")

# 絞り込みに使えるタクソノミー列（クエリ名 → カラム）
TAX_COLS = {
    "source": Event.source,
    "source_type": Event.source_type,
    "parse_status": Event.parse_status,
    "event_category": N.event_category,
    "event_action": N.event_action,
    "event_result": N.event_result,
    "event_severity": N.event_severity,
    "source_name": N.source_name,
    "device_name": N.device_name,
    "source_ip": N.source_ip,
    "source_country": N.source_country,
    "source_asn": N.source_asn,
    "source_as_org": N.source_as_org,
    "actor_user": N.actor_user,
    "url_domain": N.url_domain,
    "url_path": N.url_path,
    "http_status_code": N.http_status_code,
    "host_name": N.host_name,
    "observer_name": N.observer_name,
    "service_name": N.service_name,
    "network_protocol": N.network_protocol,
}
CONTROL = {"q", "start", "end", "limit", "offset", "interval", "groupby", "field", "top", "attention", "threat", "format"}


def _threat_clause(threat: str):
    """脅威フィルタ → where条件。攻撃/危ない系イベントだけに絞る。"""
    ioc_ids = select(EventEntity.event_id).join(
        IOC, (IOC.value == EventEntity.entity_value) & (IOC.indicator_type == EventEntity.entity_type))
    from .rules import SENSITIVE_PATHS
    sens = or_(*[N.url_path.ilike(f"%{p}%") for p in SENSITIVE_PATHS])
    web4xx = and_(N.event_category == "web", N.event_result == "failure")
    authfail = and_(N.event_category.in_(["authentication", "security"]), N.event_result == "failure")
    root_ssh = and_(N.event_category == "authentication", N.event_result == "failure", N.actor_user == "root")
    if threat == "ioc":
        return Event.id.in_(ioc_ids)
    if threat == "sensitive_path":
        return sens
    if threat == "web_scan":
        return web4xx
    if threat == "auth_fail":
        return authfail
    if threat == "root_ssh":
        return root_ssh
    if threat == "any":
        return or_(Event.id.in_(ioc_ids), sens, web4xx, authfail)
    return None

ATTENTION_KEYWORDS = ["fail", "error", "deny", "denied", "invalid", "unauthor", "refused",
                      "reject", "lock", "warn", "attack", "violat", "critical", "alert", "404"]


def filters(request: Request, db: Session = Depends(get_db), q: str | None = None,
            start: datetime | None = None, end: datetime | None = None):
    tax, payload_kv = [], []
    for k, v in request.query_params.multi_items():
        if k in CONTROL:
            continue
        (tax if k in TAX_COLS else payload_kv).append((k, v))
    return {"q": q, "start": start, "end": end, "tax": tax, "payload_kv": payload_kv,
            "blocked": _blocked(db)}


def _blocked(db: Session) -> set[str]:
    """ライセンスで非表示にする source_type 集合。"""
    from .license import blocked_source_types, current_license
    return blocked_source_types(current_license(db))


def _license_clause(blocked: set[str]):
    """非表示種別を除外（source_type が NULL のものは常に許可）。"""
    if not blocked:
        return None
    return or_(Event.source_type.is_(None), Event.source_type.notin_(blocked))


def apply_filters(stmt, f: dict):
    for k, v in f["tax"]:
        stmt = stmt.where(TAX_COLS[k] == v)
    for k, v in f["payload_kv"]:
        stmt = stmt.where(Event.payload[k].astext == v)
    if f["start"]:
        stmt = stmt.where(N.event_time >= f["start"])
    if f["end"]:
        stmt = stmt.where(N.event_time <= f["end"])
    if f["q"]:
        stmt = stmt.where(cast(Event.payload, String).ilike(f"%{f['q']}%"))
    clause = _license_clause(f.get("blocked") or set())
    if clause is not None:
        stmt = stmt.where(clause)
    return stmt


def _joined():
    return select(Event, N).join(N, Event.id == N.event_id)


def _agg(*cols):
    return select(*cols).select_from(Event).join(N, Event.id == N.event_id)


def _row(ev: Event, n: N) -> dict:
    return {
        "id": ev.id, "source": ev.source, "source_type": ev.source_type,
        "parse_status": ev.parse_status,
        "received_at": ev.received_at.isoformat() if ev.received_at else None,
        "event_time": n.event_time.isoformat() if n.event_time else None,
        "event_time_confidence": n.event_time_confidence,
        "event_category": n.event_category, "event_action": n.event_action,
        "event_result": n.event_result, "event_severity": n.event_severity,
        "source_name": n.source_name, "device_name": n.device_name,
        "source_ip": n.source_ip, "source_country": n.source_country,
        "source_asn": n.source_asn, "source_as_org": n.source_as_org, "actor_user": n.actor_user,
        "url_domain": n.url_domain, "url_path": n.url_path,
        "http_method": n.http_method, "http_status_code": n.http_status_code,
        "service_name": n.service_name,
        "message": n.message,
    }


@router.get("/events")
def list_events(db: Session = Depends(get_db), f: dict = Depends(filters), attention: bool = False,
                threat: str | None = None,
                limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    stmt = apply_filters(_joined(), f)
    if attention:
        # payloadキーワード OR 正規化済みの失敗/高重大度（[preauth]等キーワードなしのSSH攻撃も捕捉）
        payload_match = or_(*[cast(Event.payload, String).ilike(f"%{k}%") for k in ATTENTION_KEYWORDS])
        norm_match = or_(
            N.event_result == "failure",
            N.event_severity.in_(["warning", "error", "critical", "crit", "alert", "emerg"]),
        )
        stmt = stmt.where(or_(payload_match, norm_match))
    if threat:
        clause = _threat_clause(threat)
        if clause is not None:
            stmt = stmt.where(clause)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    stmt = stmt.order_by(nulls_last(N.event_time.desc()), Event.id.desc()).limit(limit).offset(offset)
    items = [_row(ev, n) for ev, n in db.execute(stmt).all()]
    return {"total": total, "limit": limit, "offset": offset, "items": items}


EXPORT_MAX_ROWS = 20000  # 一括ダウンロードの上限（メモリ/応答時間の保護）


@router.get("/events/export")
def export_events(db: Session = Depends(get_db), f: dict = Depends(filters),
                  attention: bool = False, threat: str | None = None,
                  format: str = Query("csv", pattern="^(csv|json)$"),
                  actor=Depends(require_login)):
    """現在の絞り込みに従ってイベントをCSV/JSONで一括ダウンロード（最大 EXPORT_MAX_ROWS 件）。"""
    stmt = apply_filters(_joined(), f)
    if attention:
        payload_match = or_(*[cast(Event.payload, String).ilike(f"%{k}%") for k in ATTENTION_KEYWORDS])
        norm_match = or_(N.event_result == "failure",
                         N.event_severity.in_(["warning", "error", "critical", "crit", "alert", "emerg"]))
        stmt = stmt.where(or_(payload_match, norm_match))
    if threat:
        clause = _threat_clause(threat)
        if clause is not None:
            stmt = stmt.where(clause)
    stmt = stmt.order_by(nulls_last(N.event_time.desc()), Event.id.desc()).limit(EXPORT_MAX_ROWS)
    items = [_row(ev, n) for ev, n in db.execute(stmt).all()]

    from .auth import audit
    audit(db, action="events.export", user=actor, detail=f"format={format}, rows={len(items)}")

    if format == "json":
        import json
        data = json.dumps(items, ensure_ascii=False, indent=2)
        return Response(content=data, media_type="application/json; charset=utf-8",
                        headers={"Content-Disposition": "attachment; filename=logseeker_events.json"})

    import csv
    import io
    buf = io.StringIO()
    cols = ["id", "event_time", "source_name", "source_type", "device_name", "url_domain",
            "source_ip", "source_country", "source_asn", "source_as_org", "actor_user",
            "event_action", "event_result",
            "event_severity", "service_name", "url_path", "http_status_code", "message"]
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for it in items:
        w.writerow(it)
    data = "﻿" + buf.getvalue()
    return Response(content=data, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=logseeker_events.csv"})


@router.get("/events/{event_id}")
def event_detail(event_id: int, db: Session = Depends(get_db)):
    row = db.execute(_joined().where(Event.id == event_id)).first()
    if not row:
        return {"error": "not found"}
    ev, n = row
    norm = {c: getattr(n, c) for c in N.__table__.columns.keys()}
    for k, v in norm.items():
        if isinstance(v, datetime):
            norm[k] = v.isoformat()
    return {
        "id": ev.id, "source": ev.source, "source_type": ev.source_type,
        "ingest_channel": ev.ingest_channel, "receiver_ip": ev.receiver_ip,
        "received_at": ev.received_at.isoformat() if ev.received_at else None,
        "parser_name": ev.parser_name, "parser_version": ev.parser_version,
        "parse_status": ev.parse_status, "parse_error": ev.parse_error,
        "payload": ev.payload, "normalized": norm,
    }


@router.get("/events/{event_id}/payload")
def event_payload(event_id: int, db: Session = Depends(get_db)):
    ev = db.get(Event, event_id)
    return ev.payload if ev else {"error": "not found"}


@router.get("/sources")
def sources(db: Session = Depends(get_db), f: dict = Depends(filters)):
    stmt = apply_filters(_agg(Event.source, func.count()).group_by(Event.source), f)
    return [{"source": s, "count": c} for s, c in db.execute(stmt.order_by(func.count().desc())).all()]


@router.get("/source-types")
def source_types(db: Session = Depends(get_db), f: dict = Depends(filters)):
    stmt = apply_filters(_agg(Event.source_type, func.count()).group_by(Event.source_type), f)
    return [{"source_type": s, "count": c} for s, c in db.execute(stmt.order_by(func.count().desc())).all()]


@router.get("/timeline")
def timeline(db: Session = Depends(get_db), f: dict = Depends(filters),
             interval: str = Query("day", pattern="^(minute|hour|day|month|year)$"),
             groupby: str | None = None):
    bucket = func.date_trunc(interval, N.event_time)
    if groupby and groupby in TAX_COLS:
        stmt = apply_filters(_agg(bucket, TAX_COLS[groupby], func.count())
                             .where(N.event_time.isnot(None)).group_by(text("1"), text("2")), f).order_by(text("1"))
        rows = [(b, g, c) for b, g, c in db.execute(stmt).all()]
    else:
        stmt = apply_filters(_agg(bucket, func.count())
                             .where(N.event_time.isnot(None)).group_by(text("1")), f).order_by(text("1"))
        rows = [(b, "count", c) for b, c in db.execute(stmt).all()]
    buckets, series = [], {}
    for b, g, c in rows:
        key = b.isoformat()
        if key not in series:
            series[key] = {}
            buckets.append(key)
        series[key][g if g is not None else "(none)"] = c
    names = sorted({g for v in series.values() for g in v})
    return {"buckets": buckets, "series": {nm: [series.get(b, {}).get(nm, 0) for b in buckets] for nm in names}}


@router.get("/groupby")
def groupby(field: str, db: Session = Depends(get_db), f: dict = Depends(filters),
            top: int = Query(20, ge=1, le=200)):
    col = TAX_COLS[field] if field in TAX_COLS else Event.payload[field].astext
    stmt = apply_filters(_agg(col, func.count()).where(col.isnot(None)).group_by(text("1")), f)
    return [{"value": v, "count": c} for v, c in db.execute(stmt.order_by(func.count().desc()).limit(top)).all()]


@router.get("/fields")
def fields(db: Session = Depends(get_db), f: dict = Depends(filters), top: int = Query(8, ge=1, le=50)):
    """payload に実在するキー一覧＋代表値（フィールド探索 §12.4 / 動的ファセット）。"""
    sub = apply_filters(_agg(Event.payload.label("p")), f).subquery()
    keys = [k for (k,) in db.execute(select(func.jsonb_object_keys(sub.c.p)).distinct()).all()]
    out = []
    for key in sorted(keys)[:40]:
        col = Event.payload[key].astext
        vstmt = apply_filters(_agg(col, func.count()).where(col.isnot(None)).group_by(text("1")), f)
        vals = db.execute(vstmt.order_by(func.count().desc()).limit(top)).all()
        distinct = db.scalar(apply_filters(_agg(func.count(func.distinct(col))).where(col.isnot(None)), f))
        out.append({"field": key, "distinct": distinct, "values": [{"value": v, "count": c} for v, c in vals]})
    out.sort(key=lambda x: (x["distinct"] or 0))
    return out


@router.get("/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db), f: dict = Depends(filters)):
    """ログソース/ホスト/ドメイン中心の概要（§6,§17）。source_type は主役にしない。"""
    def grp(col, limit=12):
        stmt = apply_filters(_agg(col, func.count()).where(col.isnot(None)).group_by(text("1")), f)
        return [{"value": v, "count": c} for v, c in db.execute(stmt.order_by(func.count().desc()).limit(limit)).all()]

    def ndistinct(col):
        return db.scalar(apply_filters(_agg(func.count(func.distinct(col))).where(col.isnot(None)), f)) or 0

    total = db.scalar(apply_filters(_agg(func.count()), f))
    since = datetime.now().astimezone() - timedelta(hours=24)
    recent = db.scalar(apply_filters(_agg(func.count()).where(N.event_time >= since), f))
    return {
        "total": total,
        "recent_24h": recent,
        "ingest_failed": db.scalar(apply_filters(_agg(func.count()).where(Event.parse_status == "failed"), f)),
        "dead_letters": db.scalar(select(func.count()).select_from(DeadLetter)),
        "source_count": ndistinct(N.source_name),
        "host_domain_count": ndistinct(N.device_name) + ndistinct(N.url_domain),
        "by_source_name": grp(N.source_name),
        "by_device": grp(N.device_name),
        "by_domain": grp(N.url_domain),
        "top_source_ip": grp(N.source_ip),
        "top_actor_user": grp(N.actor_user),
        "top_url_path": grp(N.url_path),
        "by_http_status": grp(N.http_status_code),
        "by_event_action": grp(N.event_action),
    }


# ============================ MVP3: エンティティ & 相関 ============================
@router.get("/entities")
def entities(db: Session = Depends(get_db), type: str | None = None, q: str | None = None,
             limit: int = Query(100, ge=1, le=500)):
    stmt = (select(EventEntity.entity_type, EventEntity.entity_value, func.count(),
                   func.min(N.event_time), func.max(N.event_time))
            .join(N, N.event_id == EventEntity.event_id)
            .join(Event, Event.id == EventEntity.event_id)
            .group_by(EventEntity.entity_type, EventEntity.entity_value))
    lc = _license_clause(_blocked(db))
    if lc is not None:
        stmt = stmt.where(lc)
    if type:
        stmt = stmt.where(EventEntity.entity_type == type)
    if q:
        stmt = stmt.where(EventEntity.entity_value.ilike(f"%{q}%"))
    stmt = stmt.order_by(func.count().desc()).limit(limit)
    return [{"entity_type": t, "entity_value": v, "count": c,
             "first_seen": fs.isoformat() if fs else None, "last_seen": ls.isoformat() if ls else None}
            for t, v, c, fs, ls in db.execute(stmt).all()]


def _entity_event_ids(db: Session, etype: str, evalue: str):
    return select(EventEntity.event_id).where(
        EventEntity.entity_type == etype, EventEntity.entity_value == evalue)


@router.get("/entity")
def entity_detail(type: str, value: str, db: Session = Depends(get_db)):
    ids = _entity_event_ids(db, type, value).subquery()
    base = select(Event, N).join(N, Event.id == N.event_id).where(Event.id.in_(select(ids.c.event_id)))
    rows = db.execute(base).all()
    times = [n.event_time for _, n in rows if n.event_time]
    return {
        "entity_type": type, "entity_value": value, "count": len(rows),
        "first_seen": min(times).isoformat() if times else None,
        "last_seen": max(times).isoformat() if times else None,
        "source_names": sorted({n.source_name for _, n in rows if n.source_name}),
        "source_types": sorted({e.source_type for e, _ in rows if e.source_type}),
    }


@router.get("/entity/events")
def entity_events(type: str, value: str, db: Session = Depends(get_db),
                  limit: int = Query(200, ge=1, le=1000)):
    ids = _entity_event_ids(db, type, value).subquery()
    stmt = (select(Event, N).join(N, Event.id == N.event_id)
            .where(Event.id.in_(select(ids.c.event_id)))
            .order_by(nulls_last(N.event_time.desc()), Event.id.desc()).limit(limit))
    return [_row(e, n) for e, n in db.execute(stmt).all()]


# ============================ Assets（資産） §10.7 ============================
# 「エンティティ」は観測された全IPの調査用一覧、「資産」は自社が保有するIPの一覧、という
# 別概念（PROJECT.md 10.7/10.8）。ローカルIPは登録不要で自動判定、グローバルIPは
# assets テーブルへの手動登録があるものだけを資産として扱う。
def _classify_ip(ip: str) -> tuple[str, str] | None:
    """IPを (ip_version, scope) に分類する。scope は private/global。パース不能は None。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return ("v4" if addr.version == 4 else "v6", "private" if addr.is_private else "global")


def _asset_dict(ip: str, ip_version: str, scope: str, label: str | None, description: str | None,
                asset_id: int | None, count: int, first_seen, last_seen) -> dict:
    return {
        "id": asset_id, "ip": ip, "ip_version": ip_version, "scope": scope,
        "label": label, "description": description, "count": count,
        "first_seen": first_seen.isoformat() if first_seen else None,
        "last_seen": last_seen.isoformat() if last_seen else None,
    }


def _asset_reg_dict(a: Asset) -> dict:
    return {"id": a.id, "ip": a.ip, "ip_version": a.ip_version, "label": a.label,
            "description": a.description,
            "created_at": a.created_at.isoformat() if a.created_at else None}


@router.get("/assets")
def list_assets(db: Session = Depends(get_db)):
    stmt = (select(EventEntity.entity_value, func.count(), func.min(N.event_time), func.max(N.event_time))
            .join(N, N.event_id == EventEntity.event_id)
            .join(Event, Event.id == EventEntity.event_id)
            .where(EventEntity.entity_type == "ip")
            .group_by(EventEntity.entity_value))
    lc = _license_clause(_blocked(db))
    if lc is not None:
        stmt = stmt.where(lc)
    stats = {v: (c, fs, ls) for v, c, fs, ls in db.execute(stmt).all()}

    out = []
    for ip, (count, fs, ls) in stats.items():
        cls = _classify_ip(ip)
        if not cls or cls[1] != "private":
            continue
        out.append(_asset_dict(ip, cls[0], "local", None, None, None, count, fs, ls))

    registered = db.execute(select(Asset).order_by(Asset.created_at.desc())).scalars().all()
    for a in registered:
        count, fs, ls = stats.get(a.ip, (0, None, None))
        out.append(_asset_dict(a.ip, a.ip_version, "registered_global", a.label, a.description,
                                a.id, count, fs, ls))

    out.sort(key=lambda r: (r["scope"] != "local", -(r["count"] or 0)))
    return out


@router.post("/assets")
def create_asset(body: AssetCreate, db: Session = Depends(get_db), actor=Depends(require_editor)):
    cls = _classify_ip(body.ip)
    if not cls:
        return Response(status_code=400, content='{"error":"不正なIPアドレス"}', media_type="application/json")
    ip_version, scope = cls
    if scope == "private":
        return Response(status_code=400,
                        content='{"error":"ローカルIPは自動判定されるため登録不要です"}',
                        media_type="application/json")
    if db.execute(select(Asset).where(Asset.ip == body.ip)).scalar_one_or_none():
        return Response(status_code=400, content='{"error":"既に登録済みです"}', media_type="application/json")
    a = Asset(ip=body.ip, ip_version=ip_version, label=body.label, description=body.description,
             created_by=getattr(actor, "username", None))
    db.add(a)
    db.commit()
    return _asset_reg_dict(a)


@router.put("/assets/{asset_id}")
def update_asset(asset_id: int, body: AssetUpdate, db: Session = Depends(get_db), _a=Depends(require_editor)):
    a = db.get(Asset, asset_id)
    if not a:
        return Response(status_code=404, content='{"error":"not found"}', media_type="application/json")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(a, k, v)
    db.commit()
    return _asset_reg_dict(a)


@router.delete("/assets/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db), _a=Depends(require_editor)):
    a = db.get(Asset, asset_id)
    if not a:
        return Response(status_code=404, content='{"error":"not found"}', media_type="application/json")
    db.delete(a)
    db.commit()
    return {"ok": True}


@router.get("/events/{event_id}/related")
def related_events(event_id: int, db: Session = Depends(get_db), limit: int = Query(200, ge=1, le=1000)):
    """このイベントと同じ IP / ユーザー / ホスト等を共有する他イベント（相関）。"""
    my = db.execute(select(EventEntity.entity_type, EventEntity.entity_value)
                    .where(EventEntity.event_id == event_id)).all()
    if not my:
        return {"keys": [], "items": []}
    conds = [(EventEntity.entity_type == t) & (EventEntity.entity_value == v) for t, v in my]
    peer_ids = select(EventEntity.event_id).where(or_(*conds)).where(EventEntity.event_id != event_id)
    stmt = (select(Event, N).join(N, Event.id == N.event_id)
            .where(Event.id.in_(peer_ids))
            .order_by(nulls_last(N.event_time.desc()), Event.id.desc()).limit(limit))
    return {"keys": [{"entity_type": t, "entity_value": v} for t, v in my],
            "items": [_row(e, n) for e, n in db.execute(stmt).all()]}


# ============================ 相関分析（AI不要・SQL結合ベース）============================
@router.get("/correlations")
def correlations(db: Session = Depends(get_db), entity_type: str = "ip",
                 min_sources: int = Query(1, ge=1, le=5),
                 limit: int = Query(100, ge=1, le=500)):
    """同一の資産/主体（IP・ユーザー等）が「複数のログソース種別にまたがって出現」する度合いで
    相関を出す。例: あるIPが web_access と linux(SSH) の両方に出れば“複数システムを触った攻撃者”。
    AIは使わない。EventEntity を軸に SQL 集計するだけ。ライセンスで非表示の種別は除外。"""
    blocked = _blocked(db)
    stc = func.count(func.distinct(Event.source_type))
    evc = func.count(func.distinct(EventEntity.event_id))
    fails = func.sum(case((N.event_result == "failure", 1), else_=0))
    stmt = (
        select(EventEntity.entity_value, evc.label("ev"), stc.label("stc"),
               func.array_agg(func.distinct(Event.source_type)),
               func.array_agg(func.distinct(N.source_name)),
               func.min(N.event_time), func.max(N.event_time), fails.label("fails"))
        .select_from(EventEntity)
        .join(Event, Event.id == EventEntity.event_id)
        .join(N, N.event_id == EventEntity.event_id)
        .where(EventEntity.entity_type == entity_type)
    )
    if blocked:
        stmt = stmt.where(or_(Event.source_type.is_(None), Event.source_type.notin_(blocked)))
    stmt = (stmt.group_by(EventEntity.entity_value)
                .having(stc >= min_sources)
                .order_by(stc.desc(), evc.desc()).limit(limit))
    rows = db.execute(stmt).all()
    ioc_type = "ip" if entity_type == "ip" else "domain"
    ioc_vals = set(db.execute(
        select(IOC.value).where(IOC.indicator_type == ioc_type)).scalars().all())
    items = [{
        "value": value, "event_count": ev, "source_type_count": stcnt,
        "source_types": sorted([s for s in (stypes or []) if s]),
        "source_names": sorted([s for s in (snames or []) if s])[:8],
        "first_seen": first.isoformat() if first else None,
        "last_seen": last.isoformat() if last else None,
        "failure_count": int(f or 0), "is_ioc": value in ioc_vals,
    } for value, ev, stcnt, stypes, snames, first, last, f in rows]
    return {"entity_type": entity_type, "min_sources": min_sources, "items": items}


# ============================ MVP5: インシデント & コメント ============================
@router.get("/incidents")
def list_incidents(db: Session = Depends(get_db)):
    cnt = (select(IncidentEvent.incident_id, func.count().label("c"))
           .group_by(IncidentEvent.incident_id)).subquery()
    rows = db.execute(
        select(Incident, cnt.c.c).outerjoin(cnt, cnt.c.incident_id == Incident.id)
        .order_by(Incident.updated_at.desc())
    ).all()
    return [{"id": i.id, "title": i.title, "status": i.status, "severity": i.severity,
             "owner": i.owner, "summary": i.summary,
             "updated_at": i.updated_at.isoformat() if i.updated_at else None,
             "event_count": c or 0} for i, c in rows]


@router.post("/incidents")
def create_incident(body: IncidentCreate, db: Session = Depends(get_db), _a=Depends(require_editor)):
    inc = Incident(title=body.title, severity=body.severity, summary=body.summary, owner=body.owner)
    db.add(inc)
    db.commit()
    return {"id": inc.id}


@router.get("/incidents/{incident_id}")
def incident_detail(incident_id: int, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        return {"error": "not found"}
    links = db.execute(
        select(IncidentEvent, Event, N)
        .join(Event, Event.id == IncidentEvent.event_id)
        .join(N, N.event_id == Event.id)
        .where(IncidentEvent.incident_id == incident_id)
        .order_by(nulls_last(N.event_time.desc()))
    ).all()
    events = [{**_row(e, n), "note": le.note} for le, e, n in links]
    return {"id": inc.id, "title": inc.title, "status": inc.status, "severity": inc.severity,
            "owner": inc.owner, "summary": inc.summary,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "events": events}


@router.post("/incidents/{incident_id}/events")
def add_incident_event(incident_id: int, body: IncidentEventAdd, db: Session = Depends(get_db),
                       _a=Depends(require_editor)):
    inc = db.get(Incident, incident_id)
    if not inc:
        return Response(status_code=404, content='{"error":"インシデントが見つかりません"}',
                        media_type="application/json")
    if not db.get(Event, body.event_id):
        return Response(status_code=404, content='{"error":"イベントが見つかりません"}',
                        media_type="application/json")
    db.add(IncidentEvent(incident_id=incident_id, event_id=body.event_id, note=body.note))
    inc.updated_at = datetime.now().astimezone()
    db.commit()
    return {"ok": True}


@router.get("/events/{event_id}/annotations")
def list_annotations(event_id: int, db: Session = Depends(get_db)):
    rows = db.execute(select(Annotation).where(Annotation.event_id == event_id)
                      .order_by(Annotation.created_at.desc())).scalars().all()
    return [{"id": a.id, "comment": a.comment, "tags": a.tags, "created_by": a.created_by,
             "created_at": a.created_at.isoformat() if a.created_at else None} for a in rows]


@router.post("/events/{event_id}/annotations")
def add_annotation(event_id: int, body: AnnotationCreate, db: Session = Depends(get_db),
                   actor=Depends(require_editor)):
    created_by = body.created_by or getattr(actor, "username", None)
    a = Annotation(event_id=event_id, comment=body.comment, tags=body.tags, created_by=created_by)
    db.add(a)
    db.commit()
    return {"id": a.id}


@router.get("/rules")
def rules_list():
    from .rules import RULE_DEFS
    return RULE_DEFS


def _conds(f: dict) -> list:
    """現在の絞り込み(f) を rules.evaluate 用の where 条件リストに変換。"""
    c = []
    for k, v in f["tax"]:
        c.append(TAX_COLS[k] == v)
    for k, v in f["payload_kv"]:
        c.append(Event.payload[k].astext == v)
    if f["start"]:
        c.append(N.event_time >= f["start"])
    if f["end"]:
        c.append(N.event_time <= f["end"])
    if f["q"]:
        c.append(cast(Event.payload, String).ilike(f"%{f['q']}%"))
    lc = _license_clause(f.get("blocked") or set())
    if lc is not None:
        c.append(lc)
    return c


@router.get("/rule-hits")
def rule_hits(db: Session = Depends(get_db), f: dict = Depends(filters)):
    from .rules import evaluate
    return {"hits": evaluate(db, _conds(f))}


# ---- カスタムルール（ユーザー定義） ----
def _custom_rule_dict(r: CustomRule) -> dict:
    return {
        "id": r.id, "name": r.name, "description": r.description, "severity": r.severity,
        "enabled": r.enabled, "match_field": r.match_field, "match_op": r.match_op,
        "match_value": r.match_value, "group_by": r.group_by, "min_count": r.min_count,
        "recommendation": r.recommendation, "created_by": r.created_by,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


@router.get("/custom-rules")
def list_custom_rules(db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    from .rules import FIELD_MAP, GROUPBY_FIELDS
    rows = db.execute(select(CustomRule).order_by(CustomRule.id.desc())).scalars().all()
    return {
        "items": [_custom_rule_dict(r) for r in rows],
        "match_fields": sorted(FIELD_MAP.keys()),
        "groupby_fields": GROUPBY_FIELDS,
    }


@router.post("/custom-rules")
def create_custom_rule(body: CustomRuleCreate, db: Session = Depends(get_db),
                       actor=Depends(require_sysadmin)):
    from .rules import FIELD_MAP, GROUPBY_FIELDS
    if body.match_field not in FIELD_MAP:
        return Response(status_code=400, content='{"error":"不正な対象フィールド"}', media_type="application/json")
    if body.group_by and body.group_by not in GROUPBY_FIELDS:
        return Response(status_code=400, content='{"error":"不正な集計軸"}', media_type="application/json")
    if body.severity not in ("critical", "high", "warning"):
        return Response(status_code=400, content='{"error":"不正な重大度"}', media_type="application/json")
    r = CustomRule(
        name=body.name, description=body.description, severity=body.severity,
        match_field=body.match_field, match_op=body.match_op, match_value=body.match_value,
        group_by=body.group_by, min_count=max(1, body.min_count),
        recommendation=body.recommendation, enabled=body.enabled,
        created_by=getattr(actor, "username", None),
    )
    db.add(r)
    db.commit()
    return _custom_rule_dict(r)


@router.put("/custom-rules/{rule_id}")
def update_custom_rule(rule_id: int, body: CustomRuleUpdate, db: Session = Depends(get_db),
                       _a=Depends(require_sysadmin)):
    from .rules import FIELD_MAP, GROUPBY_FIELDS
    r = db.get(CustomRule, rule_id)
    if not r:
        return Response(status_code=404, content='{"error":"not found"}', media_type="application/json")
    data = body.model_dump(exclude_unset=True)
    if "match_field" in data and data["match_field"] not in FIELD_MAP:
        return Response(status_code=400, content='{"error":"不正な対象フィールド"}', media_type="application/json")
    if data.get("group_by") and data["group_by"] not in GROUPBY_FIELDS:
        return Response(status_code=400, content='{"error":"不正な集計軸"}', media_type="application/json")
    for k, v in data.items():
        setattr(r, k, v)
    db.commit()
    return _custom_rule_dict(r)


@router.delete("/custom-rules/{rule_id}")
def delete_custom_rule(rule_id: int, db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    r = db.get(CustomRule, rule_id)
    if not r:
        return Response(status_code=404, content='{"error":"not found"}', media_type="application/json")
    db.delete(r)
    db.commit()
    return {"ok": True}


# ---- ログ未達監視のしきい値 ----
@router.get("/monitor/silence")
def get_silence_settings(db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    from .rules import get_silence_hours
    return {"hours": get_silence_hours(db)}


@router.post("/monitor/silence")
def save_silence_settings(body: SilenceSettings, db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    from .rules import set_silence_hours
    set_silence_hours(db, max(1, body.hours))
    return {"ok": True}


@router.get("/license")
def get_license(db: Session = Depends(get_db)):
    """Tier一覧・カテゴリ別可否は撤廃済み（全ログ種別・APIオプションは常に利用可）。
    データ保持期間の情報のみ返す。"""
    from .license import current_license, days_left, retention_days
    lic = current_license(db, force=True)
    ret = retention_days(lic)
    return {
        "licensee": lic.licensee,
        "source": lic.source,  # applied / default
        "expires_at": (datetime.fromtimestamp(lic.expires_at).isoformat() if lic.expires_at else None),
        "days_left": days_left(lic),
        "retention_days": ret, "retention_unlimited": ret < 0,
    }


@router.post("/license")
def apply_license(body: LicenseApply, db: Session = Depends(get_db),
                  _a=Depends(require_sysadmin)):
    from .license import apply_license_key
    data = apply_license_key(db, body.key)  # DBへ保存（真実源はDB）
    if not data:
        return {"error": "無効なライセンスキー（署名不一致または期限切れ）"}
    return {"ok": True, "licensee": data.get("name"), "tier": data.get("tier"), "api": data.get("api")}


@router.get("/ioc/feeds")
def ioc_feeds(db: Session = Depends(get_db)):
    from .ioc_sync import ensure_feed_rows, get_sync_hours
    ensure_feed_rows(db)
    feeds = db.execute(select(IocFeed)).scalars().all()
    by_src = dict(db.execute(select(IOC.source, func.count()).group_by(IOC.source)).all())
    return {
        "sync_hours": get_sync_hours(db),
        "total_ioc": db.scalar(select(func.count()).select_from(IOC)),
        "feeds": [{
            "name": f.name, "enabled": f.enabled, "has_key": bool(f.api_key),
            "last_synced_at": f.last_synced_at.isoformat() if f.last_synced_at else None,
            "last_status": f.last_status, "last_count": f.last_count,
            "ioc_count": by_src.get(f.name, 0),
        } for f in feeds],
    }


@router.post("/ioc/feeds")
def update_feed(body: FeedUpdate, db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    feed = db.execute(select(IocFeed).where(IocFeed.name == body.name)).scalar_one_or_none()
    if not feed:
        feed = IocFeed(name=body.name)
        db.add(feed)
    feed.enabled = body.enabled
    if body.api_key:  # 非空のときだけ更新（空は既存維持）
        feed.api_key = body.api_key
    db.commit()
    return {"ok": True}


@router.post("/ioc/settings")
def ioc_settings(body: SyncSettings, db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    row = db.get(Setting, "ioc_sync_hours")
    if not row:
        row = Setting(key="ioc_sync_hours")
        db.add(row)
    row.value = str(body.sync_hours)
    db.commit()
    return {"ok": True}


@router.post("/ioc/sync")
def ioc_sync_now(db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    from .ioc_sync import sync_all
    return {"results": sync_all(db)}


@router.get("/notifications")
def get_notifications(db: Session = Depends(get_db)):
    from .notify import get_config
    return get_config(db)


@router.put("/notifications")
def save_notifications(body: NotificationConfig, db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    from .notify import save_config
    save_config(db, body.model_dump())
    return {"ok": True}


@router.post("/notifications/test/email")
def test_email(db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    from .notify import _get, K_EMAIL_TO, send_email
    to_raw = _get(db, K_EMAIL_TO)
    to_list = [a.strip() for a in to_raw.split(",") if a.strip()]
    if not to_list:
        return {"ok": False, "error": "送信先メールアドレスが未設定です"}
    err = send_email(to_list, "[LogSeeker] テスト通知", "LogSeekerのメール通知設定が正常に動作しています。", db)
    return {"ok": err is None, "error": err}


@router.post("/notifications/test/slack")
def test_slack(db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    from .notify import _get, K_SLACK_WEBHOOK, send_slack
    webhook = _get(db, K_SLACK_WEBHOOK)
    err = send_slack("✅ [LogSeeker] Slack通知テスト：設定が正常に動作しています。", webhook)
    return {"ok": err is None, "error": err}


@router.post("/notifications/send-now")
def notify_now(db: Session = Depends(get_db), _a=Depends(require_sysadmin)):
    """現在の全ルールヒットを即時通知（手動トリガー）。"""
    from .notify import notify_hits
    from .rules import evaluate
    hits = evaluate(db)
    result = notify_hits(db, hits)
    return {"hits": len(hits), "result": result}


@router.get("/admin/ingest-status")
def ingest_status(db: Session = Depends(get_db)):
    by_channel = db.execute(
        select(Event.ingest_channel, func.count(), func.max(Event.received_at)).group_by(Event.ingest_channel)
    ).all()
    return {
        "total": db.scalar(select(func.count()).select_from(Event)),
        "dead_letters": db.scalar(select(func.count()).select_from(DeadLetter)),
        "by_channel": [{"channel": ch, "count": c, "last_received": lr.isoformat() if lr else None}
                       for ch, c, lr in by_channel],
        "tcp_port": settings.TCP_INGEST_PORT,
    }


# ============================ 運用（転送量・ログ量） ============================
@router.get("/admin/ingest-volume")
def ingest_volume(db: Session = Depends(get_db)):
    """転送量（バイト）の運用向け集計（JST基準）。総量・平均ログサイズ・直近の受信ペース・時間別/日別推移。"""
    from .ingest_stats import avg_bytes, bytes_daily, bytes_hourly_today, bytes_recent_minutes, bytes_yesterday, total_bytes

    recent_5min = bytes_recent_minutes(db, 5)
    return {
        "total_bytes": total_bytes(db),
        "avg_bytes_per_event": avg_bytes(db),
        "bytes_yesterday": bytes_yesterday(db),
        "bytes_last_5min": recent_5min,
        "avg_bytes_per_minute_last_5min": recent_5min / 5,
        "bytes_hourly_today": bytes_hourly_today(db),
        "bytes_daily": bytes_daily(db, 31),
    }


# ============================ 取り込み失敗（Dead Letter）============================
@router.get("/dead-letters")
def dead_letters(db: Session = Depends(get_db), limit: int = Query(200, ge=1, le=1000)):
    """不正JSON・処理失敗で正規化できなかった受信。原文と失敗理由を保持（監査/再処理用）。"""
    rows = db.execute(select(DeadLetter).order_by(DeadLetter.received_at.desc()).limit(limit)).scalars().all()
    return {
        "total": db.scalar(select(func.count()).select_from(DeadLetter)),
        "items": [{
            "id": d.id,
            "received_at": d.received_at.isoformat() if d.received_at else None,
            "ingest_channel": d.ingest_channel, "source": d.source, "source_type": d.source_type,
            "receiver_ip": d.receiver_ip, "error_type": d.error_type, "error_message": d.error_message,
            "raw_text": (d.raw_text or "")[:2000],
        } for d in rows],
    }


# ============================ マッピング（正規化のキー対応表）============================
# 正規化フィールドの日本語ラベル（画面/CSV表示用）
_FIELD_LABEL = {
    "source_ip": "送信元IP", "destination_ip": "宛先IP", "source_port": "送信元ポート",
    "url_domain": "ドメイン(vhost)", "url_path": "URLパス", "url_query": "URLクエリ",
    "request": "リクエスト行", "http_method": "HTTPメソッド", "http_status_code": "HTTPステータス",
    "http_user_agent": "User-Agent", "http_referer": "Referer",
    "actor_user": "ユーザー(主体)", "target_user": "対象ユーザー",
    "observer_name": "観測ホスト名", "host_name": "ホスト名", "device_name": "機器名",
    "service_name": "サービス/プロセス", "message": "メッセージ", "event_severity": "重大度",
    "event_action": "アクション", "target_resource": "対象リソース", "request_id": "リクエストID",
    "mac_address": "MACアドレス", "network_protocol": "プロトコル",
}


def _mapping_rows() -> list[dict]:
    from .normalize import MAPPINGS
    from .labels_backend import ST_LABEL
    out = []
    for st, fields in MAPPINGS.items():
        for field, keys in fields.items():
            out.append({
                "source_type": st, "source_type_label": ST_LABEL.get(st, st),
                "field": field, "field_label": _FIELD_LABEL.get(field, field),
                "candidate_keys": keys,
            })
    return out


@router.get("/mappings")
def mappings(db: Session = Depends(get_db)):
    """NXLog等のJSONキー → 正規化フィールドの対応表（source_type別）。
    受信JSONの当該キーを見つけて正規化フィールドへ“コピー”するだけ（値は改変しない）。"""
    from .normalize import MAPPINGS
    from .labels_backend import ST_LABEL
    groups = []
    for st, fields in MAPPINGS.items():
        groups.append({
            "source_type": st, "source_type_label": ST_LABEL.get(st, st),
            "fields": [{"field": f, "field_label": _FIELD_LABEL.get(f, f), "candidate_keys": k}
                       for f, k in fields.items()],
        })
    return {
        "note": "候補キーは先頭から順に探索し、最初に見つかった値を採用（値は無改変でコピー）。"
                "event_category/result/severity 等はメッセージ本文からの分類で導出（キー直写しではない）。",
        "groups": groups,
    }


@router.get("/mappings.csv")
def mappings_csv():
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["source_type", "種別(表示名)", "正規化フィールド", "フィールド(表示名)", "候補キー(優先順)"])
    for r in _mapping_rows():
        w.writerow([r["source_type"], r["source_type_label"], r["field"],
                    r["field_label"], " | ".join(r["candidate_keys"])])
    data = "﻿" + buf.getvalue()  # BOM付きでExcel文字化け回避
    return Response(content=data, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=logseeker_mappings.csv"})


# ============================ お知らせ・更新履歴 ============================
@router.get("/changelog")
def changelog(db: Session = Depends(get_db)):
    """GitHub Releasesをキャッシュ経由で返す（お知らせ一覧・ダッシュボードバナー共通）。"""
    from .changelog import get_releases
    return get_releases(db)


@router.get("/changelog/dismissed")
def get_dismissed_release(user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    """ログイン中ユーザーが最後に閉じたお知らせのタグ名。未ログイン（認証OFF等）ならnull
    （フロント側はその場合localStorageにフォールバックする）。"""
    if not user:
        return {"last_dismissed_release": None}
    row = db.get(UserSettings, user.id)
    return {"last_dismissed_release": row.last_dismissed_release if row else None}


@router.put("/changelog/dismissed")
def set_dismissed_release(body: DismissedRelease, user: User | None = Depends(get_current_user),
                          db: Session = Depends(get_db)):
    if not user:
        return {"ok": True}  # 未ログイン時はDBに保存しない（フロントはlocalStorageを使う）
    row = db.get(UserSettings, user.id)
    if not row:
        row = UserSettings(user_id=user.id)
        db.add(row)
    row.last_dismissed_release = body.tag_name
    db.commit()
    return {"ok": True}


# ============================ 管理（システム状態）============================
@router.get("/admin/overview")
def admin_overview(db: Session = Depends(get_db)):
    from .ioc_sync import get_sync_hours
    from .license import current_license, days_left, retention_days
    from .rules import get_silence_hours
    lic = current_license(db, force=True)
    ret = retention_days(lic)
    oldest = db.scalar(select(func.min(Event.received_at)))
    by_st = db.execute(
        select(Event.source_type, func.count()).group_by(Event.source_type)
        .order_by(func.count().desc())).all()
    by_channel = db.execute(
        select(Event.ingest_channel, func.count(), func.max(Event.received_at))
        .group_by(Event.ingest_channel)).all()
    parse_stats = dict(db.execute(
        select(Event.parse_status, func.count()).group_by(Event.parse_status)).all())
    return {
        "counts": {
            "events": db.scalar(select(func.count()).select_from(Event)),
            "normalized": db.scalar(select(func.count()).select_from(N)),
            "entities": db.scalar(select(func.count()).select_from(EventEntity)),
            "incidents": db.scalar(select(func.count()).select_from(Incident)),
            "ioc": db.scalar(select(func.count()).select_from(IOC)),
            "dead_letters": db.scalar(select(func.count()).select_from(DeadLetter)),
        },
        "parse_status": parse_stats,
        "by_source_type": [{"source_type": st, "count": c} for st, c in by_st],
        "by_channel": [{"channel": ch, "count": c, "last_received": lr.isoformat() if lr else None}
                       for ch, c, lr in by_channel],
        "license": {
            "licensee": lic.licensee,
            "source": lic.source, "days_left": days_left(lic),
        },
        "ingest": {"tcp_port": settings.TCP_INGEST_PORT, "auth_enabled": settings.auth_enabled},
        "ioc_sync_hours": get_sync_hours(db),
        "retention": {
            "days": ret, "unlimited": ret < 0,
            "oldest_event_at": oldest.isoformat() if oldest else None,
        },
        "silence_hours": get_silence_hours(db),
    }
