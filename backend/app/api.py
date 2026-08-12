"""検索・集計・ダッシュボードAPI（PROJECT.md §11）。events と normalized_events を結合して扱う。"""
import ipaddress
from datetime import date, datetime

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import String, case, cast, func, nulls_last, or_, select, text
from sqlalchemy.orm import Session

from .auth import get_current_user, require_editor, require_login, require_sysadmin
from .config import settings
from .db import get_db
from .incident_status import can_transition
from .models import Asset, Case, CaseComment, CaseEvent, CustomRule, DeadLetter, Event, EventEntity, IOC
from .models import Incident, IncidentAuditLog, IncidentComment, IncidentResponseAction, IncidentResponseActionType
from .models import IncidentStatus, IncidentStatusHistory
from .models import IocFeed, Setting, User, UserSettings
from .models import NormalizedEvent as N
from .schema import (AssetCreate, AssetDisplayNameUpdate, AssetUpdate, CustomRuleCreate,
                     CustomRuleUpdate, DismissedRelease, FeedUpdate,
                     LicenseApply, NotificationConfig, SilenceSettings, SyncSettings)

from .incident_schema import (CaseCommentCreate, CaseCreate, CaseEventAdd, CaseEventNoteUpdate,
                              CaseTitleUpdate, EventResolvedUpdate, IncidentAssigneeUpdate,
                              IncidentCommentCreate, IncidentResponseActionCreate, IncidentResponseActionTypeCreate,
                              IncidentResponseActionTypeVisibilityUpdate, IncidentStatusCreate, IncidentStatusUpdate,
                              IncidentStatusVisibilityUpdate, IncidentVerdictUpdate)

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


ATTENTION_KEYWORDS = ["fail", "error", "deny", "denied", "invalid", "unauthor", "refused",
                      "reject", "lock", "warn", "attack", "violat", "critical", "alert", "404"]


def _attention_clause():
    """「注目」＝ルール合致相当の動的判定（payloadキーワード一致 or 失敗/高重大度）。
    list_events の attention フィルタと、ケースへ追加できるイベントの判定
    （is_event_attention。ケース管理機能設計書v2 2章）の両方から使う共通ロジック。"""
    payload_match = or_(*[cast(Event.payload, String).ilike(f"%{k}%") for k in ATTENTION_KEYWORDS])
    norm_match = or_(
        N.event_result == "failure",
        N.event_severity.in_(["warning", "error", "critical", "crit", "alert", "emerg"]),
    )
    return or_(payload_match, norm_match)


def is_event_attention(db: Session, event_id: int) -> bool:
    # _joined() は完成済みの select(Event, N).join(...) を返すため、select_from() で包まず
    # そのまま .where() を重ねる（list_events/export_events と同じ使い方）。select_from(_joined())
    # は Select を素の FROM 要素として扱おうとして events×normalized_events のカルテシアン積を
    # 生んでしまい、実運用データで検証した際にバックエンド全体が長時間ハングする実害が出た。
    stmt = _joined().where(Event.id == event_id, _attention_clause())
    return db.execute(stmt).first() is not None

# イベント一覧（/api/events, /api/events/export）専用のデフォルト期間。
# 期間未指定のまま455,503件規模の全表スキャンが走っていたため、期間指定なし時は
# 直近24時間に絞る（フロント側でも同じデフォルトを画面表示するが、APIを直接叩く
# 経路の保護としてサーバー側にも入れる）。他エンドポイント（/api/sources 等）が使う
# 共有の filters() には手を入れず、イベント一覧のみに限定する。
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
        "url_domain": n.url_domain, "url_path": n.url_path, "url_query": n.url_query,
        "http_method": n.http_method, "http_status_code": n.http_status_code,
        "service_name": n.service_name,
        "message": n.message,
        "resolved": ev.resolved,
        "payload": ev.payload,
    }


@router.put("/events/{event_id}/resolved")
def update_event_resolved(event_id: int, body: EventResolvedUpdate, db: Session = Depends(get_db),
                          _a=Depends(require_login)):
    """イベント単体の対応済み/未対応フラグ。ケースへの追加有無とは独立して切り替え可能
    （設計書v2 2章。単発のアラートをケース化せずに処理できるようにするため）。"""
    ev = db.get(Event, event_id)
    if not ev:
        return _err(404, "イベントが見つかりません")
    ev.resolved = body.resolved
    db.commit()
    return {"ok": True, "resolved": ev.resolved}


def _auto_incident_title(ev: Event, n: N) -> str:
    """インシデントのタイトルを起因イベントから自動生成する（設計書v4 4.1節。手動編集は今回スコープ外）。"""
    base = n.event_action or n.message or n.source_name or ev.source or f"イベント #{ev.id}"
    base = base.strip().splitlines()[0] if base else f"イベント #{ev.id}"
    return base[:255]


@router.post("/events/{event_id}/incident")
def create_incident_from_event(event_id: int, db: Session = Depends(get_db), user=Depends(require_editor)):
    """「注目」アラートに対して直接インシデントを生成する（設計書v4 4章。ケースには依存しない）。
    1アラートにつき最大1件（event_id にUNIQUE制約。事前チェック＋DB制約の二重防御）。"""
    row = db.execute(_joined().where(Event.id == event_id)).first()
    if not row:
        return _err(404, "イベントが見つかりません")
    ev, n = row
    if not is_event_attention(db, event_id):
        return _err(400, "「注目」イベントのみインシデント化できます")
    existing = db.execute(select(Incident.id).where(Incident.event_id == event_id)).scalar_one_or_none()
    if existing:
        return _err(409, "このイベントは既にインシデント化されています")
    default_status = _default_status(db)
    inc = Incident(event_id=event_id, title=_auto_incident_title(ev, n),
                   status_id=default_status.id if default_status else None)
    db.add(inc)
    db.flush()
    _incident_audit(db, incident_id=inc.id, action_type="incident.create",
                    before=None, after=f"イベント #{event_id} から生成", user=user)
    db.commit()
    return {"id": inc.id}


@router.get("/sources")
def sources(db: Session = Depends(get_db), f: dict = Depends(filters)):
    stmt = apply_filters(_agg(Event.source, func.count()).group_by(Event.source), f)
    return [{"source": s, "count": c} for s, c in db.execute(stmt.order_by(func.count().desc())).all()]


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



# ============================ MVP3: エンティティ & 相関 ============================
@router.get("/entities")
def entities(db: Session = Depends(get_db), type: str | None = None, q: str | None = None,
             limit: int = Query(100, ge=1, le=500)):
    """観測された全識別子の調査・相関用一覧。ローカルIP・登録済みグローバルIPは
    「アセット」画面の対象であり自社資産一覧ではないため、ここでは除外する
    （個別調査は引き続き「アセット」画面の「詳細」から可能）。
    除外後にlimit件になるよう、SQL側ではlimitせずPython側でフィルタしてから切り詰める。"""
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
    stmt = stmt.order_by(func.count().desc())

    registered_ips: set[str] = set()
    if not type or type == "ip":
        registered_ips = set(db.execute(select(Asset.ip)).scalars().all())

    out = []
    for t, v, c, fs, ls in db.execute(stmt).all():
        if t == "ip":
            cls = _classify_ip(v)
            if cls and (cls[1] == "private" or v in registered_ips):
                continue
        out.append({"entity_type": t, "entity_value": v, "count": c,
                     "first_seen": fs.isoformat() if fs else None, "last_seen": ls.isoformat() if ls else None})
        if len(out) >= limit:
            break
    return out


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
                display_name: str | None, asset_id: int | None, count: int, first_seen, last_seen) -> dict:
    return {
        "id": asset_id, "ip": ip, "ip_version": ip_version, "scope": scope,
        "label": label, "description": description, "display_name": display_name, "count": count,
        "first_seen": first_seen.isoformat() if first_seen else None,
        "last_seen": last_seen.isoformat() if last_seen else None,
    }


def _asset_reg_dict(a: Asset) -> dict:
    return {"id": a.id, "ip": a.ip, "ip_version": a.ip_version, "label": a.label,
            "description": a.description, "display_name": a.display_name,
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

    # ip単位のメタ情報(表示名等)。ローカルIPも表示名だけは軽量に持てるため、
    # scopeの判定はip_version等の保存値に頼らずその場でis_privateを再判定する。
    asset_by_ip = {a.ip: a for a in db.execute(select(Asset)).scalars().all()}

    out = []
    for ip, (count, fs, ls) in stats.items():
        cls = _classify_ip(ip)
        if not cls or cls[1] != "private":
            continue
        a = asset_by_ip.get(ip)
        out.append(_asset_dict(ip, cls[0], "local", None, None, a.display_name if a else None,
                                a.id if a else None, count, fs, ls))

    for a in sorted(asset_by_ip.values(), key=lambda a: a.created_at, reverse=True):
        cls = _classify_ip(a.ip)
        if not cls or cls[1] != "global":
            continue
        count, fs, ls = stats.get(a.ip, (0, None, None))
        out.append(_asset_dict(a.ip, a.ip_version, "registered_global", a.label, a.description,
                                a.display_name, a.id, count, fs, ls))

    out.sort(key=lambda r: (r["scope"] != "local", -(r["count"] or 0)))
    return out


@router.put("/assets/local/{ip}")
def set_local_asset_display_name(ip: str, body: AssetDisplayNameUpdate, db: Session = Depends(get_db),
                                  actor=Depends(require_editor)):
    """ローカル(プライベート)IPは登録不要で自動判定される資産だが、表示名だけは
    軽量に付与できるようにする（label/descriptionを持つ「登録」とは別の軽量な経路）。"""
    cls = _classify_ip(ip)
    if not cls or cls[1] != "private":
        return Response(status_code=400, content='{"error":"ローカル(プライベート)IPのみ指定できます"}',
                        media_type="application/json")
    a = db.execute(select(Asset).where(Asset.ip == ip)).scalar_one_or_none()
    if a is None:
        a = Asset(ip=ip, ip_version=cls[0], display_name=body.display_name,
                  created_by=getattr(actor, "username", None))
        db.add(a)
    else:
        a.display_name = body.display_name
    db.commit()
    return _asset_reg_dict(a)


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
             display_name=body.display_name, created_by=getattr(actor, "username", None))
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


# ============================ ケース／インシデント管理機能（設計書v2） ============================
def _err(status: int, message: str) -> Response:
    import json
    return Response(status_code=status, content=json.dumps({"error": message}, ensure_ascii=False),
                    media_type="application/json")


def _incident_audit(db: Session, *, incident_id: int | None, action_type: str,
                    before: str | None, after: str | None, user: User | None) -> None:
    """記録対象はインシデント側の操作のみ（ケース側の操作は記録しない。設計書v2 3章/4-3節）。"""
    db.add(IncidentAuditLog(incident_id=incident_id, action_type=action_type,
                            before_value=before, after_value=after,
                            actor=user.id if user else None))


def _status_row(s: IncidentStatus) -> dict:
    return {"id": s.id, "name": s.name, "special_type": s.special_type,
            "is_visible": s.is_visible, "sort_order": s.sort_order}


def _response_action_type_row(t: IncidentResponseActionType) -> dict:
    return {"id": t.id, "name": t.name, "is_visible": t.is_visible, "sort_order": t.sort_order}


def _default_status(db: Session) -> IncidentStatus | None:
    return db.execute(select(IncidentStatus).where(IncidentStatus.special_type == "unassigned")).scalars().first()


def _case_row(c: Case, event_count: int) -> dict:
    return {
        "id": c.id, "title": c.title,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
        "event_count": event_count,
    }


# ---------------------------- ケース（複数イベントの調査ワークスペース。設計書v4 3章） ----------------------------
# ステータス・判定結果・担当者・インシデントへの「昇格」概念は持たない。インシデントとは
# 完全に独立している（4章参照）。
@router.get("/cases")
def list_cases(db: Session = Depends(get_db)):
    cnt = (select(CaseEvent.case_id, func.count().label("c")).group_by(CaseEvent.case_id)).subquery()
    rows = db.execute(
        select(Case, cnt.c.c)
        .outerjoin(cnt, cnt.c.case_id == Case.id)
        .order_by(Case.updated_at.desc())
    ).all()
    return [_case_row(c, cnt or 0) for c, cnt in rows]


@router.post("/cases")
def create_case(body: CaseCreate, db: Session = Depends(get_db), _a=Depends(require_editor)):
    c = Case(title=body.title)
    db.add(c)
    db.commit()
    return {"id": c.id}


@router.get("/cases/{case_id}")
def case_detail(case_id: int, db: Session = Depends(get_db)):
    c = db.get(Case, case_id)
    if not c:
        return {"error": "not found"}
    links = db.execute(
        select(CaseEvent, Event, N)
        .join(Event, Event.id == CaseEvent.event_id)
        .join(N, N.event_id == Event.id)
        .where(CaseEvent.case_id == case_id)
        .order_by(nulls_last(N.event_time.desc()))
    ).all()
    events = [{**_row(e, n), "note": le.note} for le, e, n in links]
    return {
        "id": c.id, "title": c.title,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
        "events": events,
    }


@router.put("/cases/{case_id}")
def update_case_title(case_id: int, body: CaseTitleUpdate, db: Session = Depends(get_db), _a=Depends(require_login)):
    c = db.get(Case, case_id)
    if not c:
        return _err(404, "ケースが見つかりません")
    c.title = body.title
    c.updated_at = datetime.now().astimezone()
    db.commit()
    return {"ok": True, "title": c.title}


@router.post("/cases/{case_id}/events")
def add_case_event(case_id: int, body: CaseEventAdd, db: Session = Depends(get_db), _a=Depends(require_editor)):
    """設計書v4 3章：「注目」以外のイベントも自由に追加できる（v3までの注目限定制限は撤廃）。"""
    c = db.get(Case, case_id)
    if not c:
        return _err(404, "ケースが見つかりません")
    if not db.get(Event, body.event_id):
        return _err(404, "イベントが見つかりません")
    existing = db.execute(select(CaseEvent.id).where(
        CaseEvent.case_id == case_id, CaseEvent.event_id == body.event_id)).first()
    if existing:
        return _err(409, "このイベントは既にこのケースに追加されています")
    db.add(CaseEvent(case_id=case_id, event_id=body.event_id, note=body.note))
    c.updated_at = datetime.now().astimezone()
    db.commit()
    return {"ok": True}


@router.put("/cases/{case_id}/events/{event_id}")
def update_case_event_note(case_id: int, event_id: int, body: CaseEventNoteUpdate,
                           db: Session = Depends(get_db), _a=Depends(require_login)):
    link = db.execute(select(CaseEvent).where(
        CaseEvent.case_id == case_id, CaseEvent.event_id == event_id)).scalar_one_or_none()
    if not link:
        return _err(404, "紐付けが見つかりません")
    link.note = body.note
    db.commit()
    return {"ok": True}


@router.delete("/cases/{case_id}/events/{event_id}")
def remove_case_event(case_id: int, event_id: int, db: Session = Depends(get_db), _a=Depends(require_login)):
    """イベント自体は削除せず、ケースとの紐付け(リレーション)のみ解除する。"""
    link = db.execute(select(CaseEvent).where(
        CaseEvent.case_id == case_id, CaseEvent.event_id == event_id)).scalar_one_or_none()
    if not link:
        return _err(404, "紐付けが見つかりません")
    db.delete(link)
    db.commit()
    return {"ok": True}


@router.get("/cases/{case_id}/comments")
def list_case_comments(case_id: int, db: Session = Depends(get_db)):
    rows = db.execute(
        select(CaseComment, User.display_name, User.username)
        .outerjoin(User, User.id == CaseComment.created_by)
        .where(CaseComment.case_id == case_id)
        .order_by(CaseComment.created_at.desc())
    ).all()
    return [{"id": c.id, "body": c.body, "actor_name": dname or uname,
             "created_at": c.created_at.isoformat() if c.created_at else None} for c, dname, uname in rows]


@router.post("/cases/{case_id}/comments")
def add_case_comment(case_id: int, body: CaseCommentCreate, db: Session = Depends(get_db),
                     _a=Depends(require_login)):
    c = db.get(Case, case_id)
    if not c:
        return _err(404, "ケースが見つかりません")
    if not body.body.strip():
        return _err(400, "コメントを入力してください")
    cm = CaseComment(case_id=case_id, body=body.body.strip(), created_by=_a.id if _a else None)
    db.add(cm)
    db.commit()
    return {"id": cm.id}


# ---------------------------- インシデント（アラート単位の確定事案。設計書v4 4章） ----------------------------
# ケースには一切依存しない。「1つの注目アラート(event_id)」と1:1で対応する。
@router.get("/incidents")
def list_incidents(db: Session = Depends(get_db)):
    """インシデント単体の一覧（ケースを経由せず左メニューから直接アクセスする）。
    normalized_eventsとは outerjoin（inner joinだと、元イベントが保持期間切れ等で削除され
    event_idがNULLになったインシデントが一覧から消えてしまうため。models.py Incident参照）。"""
    rows = db.execute(
        select(Incident, IncidentStatus, User.display_name, User.username, N)
        .outerjoin(IncidentStatus, IncidentStatus.id == Incident.status_id)
        .outerjoin(User, User.id == Incident.assignee_user_id)
        .outerjoin(N, N.event_id == Incident.event_id)
        .order_by(Incident.updated_at.desc())
    ).all()
    return [{
        "id": i.id, "event_id": i.event_id, "title": i.title,
        "status_id": i.status_id, "status_name": st.name if st else None,
        "verdict": i.verdict,
        "assignee_user_id": i.assignee_user_id,
        "assignee_name": (dname or uname) if i.assignee_user_id else None,
        "updated_at": i.updated_at.isoformat() if i.updated_at else None,
        "event_source_name": n.source_name if n else None,
        "event_action": n.event_action if n else None, "event_message": n.message if n else None,
    } for i, st, dname, uname, n in rows]


@router.get("/incidents/{incident_id}")
def incident_detail(incident_id: int, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if not inc:
        return {"error": "not found"}
    status = db.get(IncidentStatus, inc.status_id) if inc.status_id else None
    assignee = db.get(User, inc.assignee_user_id) if inc.assignee_user_id else None
    # 主役アラート：このインシデントの起因となった唯一のイベント（複製せず参照表示。設計書v4 5.3節）。
    # event_idは保持期間切れ等でNULLになりうる（ON DELETE SET NULL）。その場合 inc.event_id is
    # None となり、Event.id == None は自動的に IS NULL 判定されるため row は None のままになる
    # （インシデント本体は残り、主役アラート情報のみ「取得できません」表示になる。models.py参照）。
    row = db.execute(_joined().where(Event.id == inc.event_id)).first()
    event = _row(*row) if row else None
    return {
        "id": inc.id, "event_id": inc.event_id, "title": inc.title,
        "status_id": inc.status_id, "status_name": status.name if status else None,
        "verdict": inc.verdict,
        "assignee_user_id": inc.assignee_user_id,
        "assignee_name": (assignee.display_name or assignee.username) if assignee else None,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
        "event": event,
    }


@router.put("/incidents/{incident_id}/status")
def update_incident_status(incident_id: int, body: IncidentStatusUpdate, db: Session = Depends(get_db),
                           user=Depends(require_login)):
    inc = db.get(Incident, incident_id)
    if not inc:
        return _err(404, "インシデントが見つかりません")
    to_status = db.get(IncidentStatus, body.status_id)
    if not to_status:
        return _err(404, "ステータスが見つかりません")
    from_status = db.get(IncidentStatus, inc.status_id) if inc.status_id else None
    role = user.role if user else "admin"  # 認証OFF時は従来どおり全権
    if not can_transition(from_status.special_type if from_status else None, to_status.special_type, role):
        return _err(403, "この遷移を行う権限がありません（システム管理者以上が必要です）")
    old_status_id = inc.status_id
    inc.status_id = to_status.id
    inc.updated_at = datetime.now().astimezone()
    # 「未対応」以外へ変更し、かつ担当者が未割り当てなら操作者を自動アサイン（UX向上策。v1から継続）。
    if to_status.special_type != "unassigned" and inc.assignee_user_id is None and user:
        inc.assignee_user_id = user.id
    db.add(IncidentStatusHistory(incident_id=incident_id, from_status_id=old_status_id,
                                 to_status_id=to_status.id, changed_by=user.id if user else None))
    _incident_audit(db, incident_id=incident_id, action_type="status_change",
                    before=from_status.name if from_status else None, after=to_status.name, user=user)
    db.commit()
    return {"ok": True, "status_id": inc.status_id, "assignee_user_id": inc.assignee_user_id}


@router.put("/incidents/{incident_id}/assignee")
def update_incident_assignee(incident_id: int, body: IncidentAssigneeUpdate, db: Session = Depends(get_db),
                             user=Depends(require_login)):
    inc = db.get(Incident, incident_id)
    if not inc:
        return _err(404, "インシデントが見つかりません")
    if body.assignee_user_id is not None and not db.get(User, body.assignee_user_id):
        return _err(404, "ユーザーが見つかりません")
    before = inc.assignee_user_id
    inc.assignee_user_id = body.assignee_user_id
    inc.updated_at = datetime.now().astimezone()
    _incident_audit(db, incident_id=incident_id, action_type="assignee_change",
                    before=str(before) if before else None,
                    after=str(body.assignee_user_id) if body.assignee_user_id else None, user=user)
    db.commit()
    return {"ok": True, "assignee_user_id": inc.assignee_user_id}


@router.put("/incidents/{incident_id}/verdict")
def update_incident_verdict(incident_id: int, body: IncidentVerdictUpdate, db: Session = Depends(get_db),
                            user=Depends(require_login)):
    inc = db.get(Incident, incident_id)
    if not inc:
        return _err(404, "インシデントが見つかりません")
    before = inc.verdict
    inc.verdict = body.verdict
    inc.updated_at = datetime.now().astimezone()
    _incident_audit(db, incident_id=incident_id, action_type="verdict_change", before=before, after=body.verdict, user=user)
    db.commit()
    return {"ok": True, "verdict": inc.verdict}


@router.post("/incidents/{incident_id}/comments")
def add_incident_comment(incident_id: int, body: IncidentCommentCreate, db: Session = Depends(get_db),
                         user=Depends(require_login)):
    inc = db.get(Incident, incident_id)
    if not inc:
        return _err(404, "インシデントが見つかりません")
    if not body.body.strip():
        return _err(400, "コメントを入力してください")
    c = IncidentComment(incident_id=incident_id, body=body.body.strip(), created_by=user.id if user else None)
    db.add(c)
    db.commit()
    return {"id": c.id}


@router.post("/incidents/{incident_id}/response-actions")
def add_incident_response_action(incident_id: int, body: IncidentResponseActionCreate,
                                 db: Session = Depends(get_db), user=Depends(require_login)):
    inc = db.get(Incident, incident_id)
    if not inc:
        return _err(404, "インシデントが見つかりません")
    at = db.get(IncidentResponseActionType, body.action_type_id)
    if not at:
        return _err(404, "対応アクション種別が見つかりません")
    ra = IncidentResponseAction(incident_id=incident_id, action_type_id=body.action_type_id,
                                detail=body.detail, actor=user.id if user else None)
    db.add(ra)
    db.flush()
    _incident_audit(db, incident_id=incident_id, action_type="response_action.add",
                    before=None, after=at.name, user=user)
    db.commit()
    return {"id": ra.id}


@router.get("/incidents/{incident_id}/activity")
def incident_activity(incident_id: int, db: Session = Depends(get_db), _a=Depends(require_login)):
    """コメント(incident_comments)・対応アクション(incident_response_actions)・
    システム監査ログ(incident_audit_log)を時系列マージしたアクティビティタイムライン（設計書v2 4-4節）。"""
    comments = db.execute(
        select(IncidentComment, User.display_name, User.username)
        .outerjoin(User, User.id == IncidentComment.created_by)
        .where(IncidentComment.incident_id == incident_id)
    ).all()
    actions = db.execute(
        select(IncidentResponseAction, IncidentResponseActionType.name, User.display_name, User.username)
        .join(IncidentResponseActionType, IncidentResponseActionType.id == IncidentResponseAction.action_type_id)
        .outerjoin(User, User.id == IncidentResponseAction.actor)
        .where(IncidentResponseAction.incident_id == incident_id)
    ).all()
    logs = db.execute(
        select(IncidentAuditLog, User.display_name, User.username)
        .outerjoin(User, User.id == IncidentAuditLog.actor)
        .where(IncidentAuditLog.incident_id == incident_id)
    ).all()
    items = []
    for c, dname, uname in comments:
        items.append({
            "id": f"comment-{c.id}", "type": "comment", "body": c.body,
            "before_value": None, "after_value": None,
            "actor_name": dname or uname, "created_at": c.created_at.isoformat() if c.created_at else None,
        })
    for a, type_name, dname, uname in actions:
        items.append({
            "id": f"action-{a.id}", "type": "response_action", "body": a.detail,
            "before_value": None, "after_value": type_name,
            "actor_name": dname or uname, "created_at": a.created_at.isoformat() if a.created_at else None,
        })
    for a, dname, uname in logs:
        items.append({
            "id": f"audit-{a.id}", "type": a.action_type, "body": None,
            "before_value": a.before_value, "after_value": a.after_value,
            "actor_name": dname or uname, "created_at": a.created_at.isoformat() if a.created_at else None,
        })
    items.sort(key=lambda x: x["created_at"] or "", reverse=True)
    return items


# インシデント/ケースの担当者アサイン用に使う軽量なユーザー一覧。/api/users はsysadmin以上限定
# （ロール・有効/無効等の管理情報を含むため）だが、担当者アサインは閲覧者含む全員が行えるため
# （権限マトリクス）、id/username/display_nameのみの最小限データを別途返す。
@router.get("/incident-assignable-users")
def list_assignable_users(db: Session = Depends(get_db), _a=Depends(require_login)):
    rows = db.execute(
        select(User.id, User.username, User.display_name)
        .where(User.enabled.is_(True)).order_by(User.username)
    ).all()
    return [{"id": i, "username": u, "display_name": d} for i, u, d in rows]


# ---- ステータスマスタ管理（sysadmin以上のみ追加・非表示化） ----
@router.get("/incident-statuses")
def list_incident_statuses(db: Session = Depends(get_db), show_hidden: bool = False):
    stmt = select(IncidentStatus).order_by(IncidentStatus.sort_order, IncidentStatus.id)
    if not show_hidden:
        stmt = stmt.where(IncidentStatus.is_visible.is_(True))
    return [_status_row(s) for s in db.execute(stmt).scalars().all()]


@router.post("/incident-statuses")
def create_incident_status(body: IncidentStatusCreate, db: Session = Depends(get_db), user=Depends(require_sysadmin)):
    if not body.name.strip():
        return _err(400, "ステータス名を入力してください")
    max_sort = db.scalar(select(func.max(IncidentStatus.sort_order))) or 0
    st = IncidentStatus(name=body.name.strip(), special_type=None, is_visible=True, sort_order=max_sort + 1)
    db.add(st)
    db.flush()
    _incident_audit(db, incident_id=None, action_type="status_master.create", before=None, after=st.name, user=user)
    db.commit()
    return _status_row(st)


@router.put("/incident-statuses/{status_id}/visibility")
def set_incident_status_visibility(status_id: int, body: IncidentStatusVisibilityUpdate,
                                   db: Session = Depends(get_db), user=Depends(require_sysadmin)):
    st = db.get(IncidentStatus, status_id)
    if not st:
        return _err(404, "ステータスが見つかりません")
    before = st.is_visible
    st.is_visible = body.is_visible
    _incident_audit(db, incident_id=None, action_type="status_master.visibility",
                    before=f"{st.name}: {before}", after=f"{st.name}: {body.is_visible}", user=user)
    db.commit()
    return _status_row(st)


# ---- 対応アクション種別マスタ（sysadmin以上のみ追加・非表示化。設計書v2 4-4節） ----
@router.get("/incident-response-action-types")
def list_response_action_types(db: Session = Depends(get_db), show_hidden: bool = False):
    stmt = select(IncidentResponseActionType).order_by(IncidentResponseActionType.sort_order, IncidentResponseActionType.id)
    if not show_hidden:
        stmt = stmt.where(IncidentResponseActionType.is_visible.is_(True))
    return [_response_action_type_row(t) for t in db.execute(stmt).scalars().all()]


@router.post("/incident-response-action-types")
def create_response_action_type(body: IncidentResponseActionTypeCreate, db: Session = Depends(get_db),
                                user=Depends(require_sysadmin)):
    if not body.name.strip():
        return _err(400, "種別名を入力してください")
    max_sort = db.scalar(select(func.max(IncidentResponseActionType.sort_order))) or 0
    t = IncidentResponseActionType(name=body.name.strip(), is_visible=True, sort_order=max_sort + 1)
    db.add(t)
    db.flush()
    _incident_audit(db, incident_id=None, action_type="response_action_type.create", before=None, after=t.name, user=user)
    db.commit()
    return _response_action_type_row(t)


@router.put("/incident-response-action-types/{type_id}/visibility")
def set_response_action_type_visibility(type_id: int, body: IncidentResponseActionTypeVisibilityUpdate,
                                        db: Session = Depends(get_db), user=Depends(require_sysadmin)):
    t = db.get(IncidentResponseActionType, type_id)
    if not t:
        return _err(404, "対応アクション種別が見つかりません")
    before = t.is_visible
    t.is_visible = body.is_visible
    _incident_audit(db, incident_id=None, action_type="response_action_type.visibility",
                    before=f"{t.name}: {before}", after=f"{t.name}: {body.is_visible}", user=user)
    db.commit()
    return _response_action_type_row(t)


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
    from .license import current_license, days_left, retention_days, retention_window
    lic = current_license(db, force=True)
    ret = retention_days(lic)
    r_start, r_end, r_left = retention_window(db, lic)
    return {
        "licensee": lic.licensee,
        "source": lic.source,  # applied / default
        "started_at": (datetime.fromtimestamp(lic.applied_at).isoformat() if lic.applied_at else None),
        "expires_at": (datetime.fromtimestamp(lic.expires_at).isoformat() if lic.expires_at else None),
        "days_left": days_left(lic),
        "retention_days": ret, "retention_unlimited": ret < 0,
        "retention_started_at": datetime.fromtimestamp(r_start).isoformat(),
        "retention_expires_at": (datetime.fromtimestamp(r_end).isoformat() if r_end else None),
        "retention_days_left": r_left,
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
def ingest_volume(
    db: Session = Depends(get_db),
    hourly_date: date | None = Query(None, description="時間別グラフの対象日（JST）。省略時は本日"),
    daily_start: date | None = Query(None, description="日別グラフの開始日（JST）。省略時は直近31日の開始"),
    daily_end: date | None = Query(None, description="日別グラフの終了日（JST）。省略時は本日"),
):
    """転送量（バイト）の運用向け集計（JST基準）。総量・平均ログサイズ・直近の受信ペース・時間別/日別推移。
    時間別はhourly_date、日別はdaily_start/daily_endで対象日・期間を指定可能（省略時は本日/直近31日）。"""
    from .ingest_stats import avg_bytes, bytes_daily, bytes_hourly, bytes_recent_minutes, bytes_yesterday, total_bytes

    recent_5min = bytes_recent_minutes(db, 5)
    return {
        "total_bytes": total_bytes(db),
        "avg_bytes_per_event": avg_bytes(db),
        "bytes_yesterday": bytes_yesterday(db),
        "bytes_last_5min": recent_5min,
        "avg_bytes_per_minute_last_5min": recent_5min / 5,
        "bytes_hourly": bytes_hourly(db, hourly_date),
        "bytes_daily": bytes_daily(db, daily_start, daily_end),
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
    """マッピング画面。取り込みの現行方式（Taxonomy KEY直接）＋送信設定サンプル＋
    正規化マッピング（検知ルール・相関分析が使う normalized_events 向け）を返す。"""
    from .normalize import MAPPINGS
    from .labels_backend import ST_LABEL
    from .log_samples import SAMPLES
    from .taxonomy_master import ALL_KEYS, LABELS

    groups = []
    for st, fields in MAPPINGS.items():
        groups.append({
            "source_type": st, "source_type_label": ST_LABEL.get(st, st),
            "fields": [{"field": f, "field_label": _FIELD_LABEL.get(f, f), "candidate_keys": k}
                       for f, k in fields.items()],
        })

    # 画面の「よく使うキー」に出す代表例。ALL_KEYSは770個あり全部は出せないので、
    # ラベル付き（＝画面で日本語表示できる）ものだけを用途別に抜粋する。
    common = [
        ("分類", ["class", "source"]),
        ("時刻", ["eventtime"]),
        ("ホスト/ドメイン", ["domain", "vhost", "virtualhost", "virtualdomain", "host", "hostname"]),
        ("通信元", ["client", "srcipv4", "srcipv6", "sourceipaddress"]),
        ("HTTP", ["request", "httpmethod", "uri", "url", "status", "statuscode",
                  "size", "referer", "user_agent"]),
        ("ユーザー", ["username", "accountname", "targetusername"]),
        ("内容", ["message", "severity", "category", "action", "result"]),
        ("Windows", ["eventid", "processid"]),
        ("auditd", ["audit_type", "audit_res", "audit_acct"]),
    ]
    key_groups = [{"title": t,
                   "keys": [{"key": k, "label": LABELS.get(k, "")} for k in ks]}
                  for t, ks in common]

    return {
        "taxonomy_total": len(ALL_KEYS),
        "ingest_note": (
            "受信したJSONのキー名が Taxonomy KEY と一致したものだけを、画面の表示・検索・集計に使う。"
            "一致は大文字小文字を無視して行うので EventTime / EVENTTIME / eventtime はすべて同じ扱いになる。"
            "一致しないキーも値は無改変で保存されるが、表示・検索・集計には使われない。"
            "別名は同一視しないため host と hostname、client と srcipv4 は別のキーとして扱う。"
        ),
        "class_note": (
            "クラスは受信JSONの class キーの値だけで決まる。推定はしない。"
            "class が無いイベントは unknown になるので、送信側で必ず付けること。"
        ),
        "key_groups": key_groups,
        "samples": SAMPLES,
        "note": "候補キーは先頭から順に探索し、最初に見つかった値を採用（値は無改変でコピー）。"
                "event_category/result/severity 等はメッセージ本文からの分類で導出（キー直写しではない）。",
        "normalize_note": (
            "以下は normalized_events（軽量タクソノミー）への対応表で、検知ルール・相関分析・"
            "調査支援が使う。イベント画面とダッシュボードはこの表を使わず、上のTaxonomy KEYを直接読む。"
        ),
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
            "cases": db.scalar(select(func.count()).select_from(Case)),
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
