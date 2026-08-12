"""Events / Dashboard 用API（v12 A案準拠。新規実装）。

設計上の前提（PROJECT_basic_design_revised_v12.md）:
  §4.1.1  受信フィールド = payload内のKEYのうち docs/taxonomy.md のTaxonomy KEYと完全一致するものだけ。
          Taxonomy外KEYは無改変で保存するが、表示・検索・集計・解析には一切使わない。
  §5.2    ドメイン/ホストの代表値優先順位は Taxonomy KEY だけで構成する。
  §10.2   Events列はClassごとにLogSeeker利用者がTaxonomy受信フィールドから選ぶ。固定列にしない。
  §10.3   Event DetailにTaxonomy外KEYを表示しない。

本モジュールは `normalized_events`（normalize.py の MAPPINGS によるKEY読み替えの産物）を
値の取得元にしない。表示値は必ず events.payload 内のTaxonomy KEYから読む。
`normalized_events` は他機能（相関・ルール・ケース等）が引き続き使うため削除しない。

列の選択肢は taxonomy_master.ALL_KEYS（taxonomy.md §3から自動生成）だけで決まり、
受信済みデータのサンプリングは行わない。実データの有無で選択肢が変わると、
設計ではなく実データに引きずられた画面になるため。
"""
import csv
import re
from functools import lru_cache
import io
import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import String, and_, cast, func, literal, or_, select, text, true
from sqlalchemy.dialects.postgresql import JSONB, array as pg_array
from sqlalchemy.orm import Session

from .auth import get_current_user, require_login
from .db import get_db
from .models import IOC, Event, Setting, User, UserSettings
from .schema import EventsClassesUpdate, EventsColumnSetSave, EventsColumnsUpdate
from .taxonomy_master import (ALL_KEYS, CLASS_HINTS, canonical_key, default_columns, is_taxonomy_key,
                             label_of)

router = APIRouter(prefix="/api")

UNKNOWN_CLASS = "unknown"


def _lc_payload():
    """payloadのKEYを小文字化したコピー（SQL式）。**受信payloadは変更しない。**

    Taxonomy照合は大文字小文字を区別しないため、`payload->>'eventtime'`（大文字小文字を
    区別する）では `EventTime` を拾えない。そこで問い合わせ時だけKEYを小文字化した
    JSONBを作り、`lp->>'eventtime'` で引く。

        (SELECT jsonb_object_agg(lower(key), value) FROM jsonb_each_text(events.payload))

    この式は行ごとに1回だけ評価させたいので、必ず _ev()（CTE）経由で使う。
    比較のたびに書くと、`>=` `<=` `ORDER BY` で同じ展開が何度も走って著しく遅くなる。"""
    kv = func.jsonb_each_text(Event.payload).table_valued("key", "value")
    agg = select(func.jsonb_object_agg(func.lower(kv.c.key), kv.c.value)).scalar_subquery()
    # CTEの列として `lp->>'key'` を書けるよう、JSONB型を明示する（型が無いと添字が使えない）
    return cast(agg, JSONB)


def _ev(qy):
    """Events/Dashboardの全クエリの土台となるCTE。

    payloadのKEY小文字化（lp）を**行ごとに1回だけ**計算して添える。以降のフィルタ・集計は
    このCTEの列を参照するだけなので、JSONBの展開が1行1回に収まる。

    **期間はここで先に絞る。** received_at にはインデックスがあるため、展開対象の行を
    先に減らせる。時間軸に受信時刻（管理メタデータ）を使うのは v12 §4.1.1 が認めており、
    参照UI（Trellix Helix）が meta_ts を時間軸にしているのと同じ考え方。
    payload の eventtime は選択可能なTaxonomy列として表示できる。"""
    lp = _lc_payload().label("lp")
    return (select(
        Event.id.label("id"),
        Event.received_at.label("received_at"),
        Event.source.label("source"),
        Event.resolved.label("resolved"),
        Event.payload.label("payload"),
        lp,
    ).where(Event.received_at >= qy.start, Event.received_at <= qy.end).cte("ev"))


def _pv(ev, key: str):
    """CTE上での、大文字小文字を無視したTaxonomy KEYのVALUE。"""
    return func.nullif(ev.c.lp[key.lower()].astext, "")


def _cls(ev):
    """Class VALUE ＝ 受信JSONの `class` KEYのVALUE（大文字小文字は無視。`CLASS` も一致）。"""
    return func.coalesce(_pv(ev, "class"), func.cast(UNKNOWN_CLASS, String))


def _scoped(stmt, qy):
    """Dashboard集計用に events へ直接かける共通条件（期間・Class・ログソース）。
    KEY小文字化コピー(lp)を作らない経路で使う。"""
    stmt = stmt.select_from(Event).where(Event.received_at >= qy.start, Event.received_at <= qy.end)
    if qy.class_value:
        stmt = stmt.where(_class_of(Event.payload) == qy.class_value)
    if qy.source:
        stmt = stmt.where(Event.source == qy.source)
    for f, v in qy.filters:
        kvf = func.jsonb_each_text(Event.payload).table_valued("key", "value")
        hit = select(kvf.c.value).where(func.lower(kvf.c.key) == f, kvf.c.value == v).limit(1).scalar_subquery()
        stmt = stmt.where(hit.isnot(None))
    return stmt


def _class_of(payload_col):
    """CTEを経由せずpayload列から直接Classを取り出す（大文字小文字は無視）。
    Dashboardの内訳集計のように、KEY小文字化コピー(lp)を作らない経路で使う。"""
    kv = func.jsonb_each_text(payload_col).table_valued("key", "value")
    got = (select(kv.c.value).where(func.lower(kv.c.key) == "class",
                                    func.nullif(kv.c.value, "").isnot(None))
           .limit(1).scalar_subquery())
    return func.coalesce(got, func.cast(UNKNOWN_CLASS, String))


def _pick(payload: dict, key: str):
    """Python側の同じ照合（大文字小文字を無視してVALUEを取り出す）。"""
    lk = key.lower()
    for k, v in payload.items():
        if k.lower() == lk and v not in (None, ""):
            return v
    return None

# 代表値優先順位の既定値（v12 §5.2 / normalize-mapping.md v1.7 §6.2）。settings側が正。
DEFAULT_DOMAIN_HOST_PRIORITY = ["domain", "vhost", "virtualhost", "virtualdomain", "host", "hostname"]

# Dashboardの内訳カードの**既定**集計軸。すべてTaxonomy KEY。
# これは「固定の集計軸」ではなく初期値で、LogSeeker利用者が762KEYから自由に選び直せる
# （選択はlocalStorage/サーバーへ保存される）。値が0件の軸はカードを描画しない。
DEFAULT_DASHBOARD_AXES = ["hostname", "client", "srcipv4", "uri", "username", "accountname",
                          "audit_type", "audit_acct",
                          "status", "statuscode", "action", "category", "severity"]

# 集計・時間軸に使うタイムゾーン。日別バケットがJSTの0時で区切られるようにする
# （UTC基準だと日本時間の09:00で日付が変わってしまう）。
DISPLAY_TZ = "Asia/Tokyo"
K_PRIORITY = "dashboard_domain_host_priority"
EXPORT_MAX_ROWS = 20000
TOP_N = 12                 # 内訳カードに出す上位件数
DEFAULT_PERIOD_HOURS = 24



# ---------------------------------------------------------------- 利用者設定

def _prefs(row: UserSettings | None) -> dict:
    """user_settings.events_columns のJSON。旧形式（{class: [keys]}）も読める。"""
    empty = {"columns": {}, "column_sets": {}, "classes": {}, "dashboard": {}}
    if not row or not row.events_columns:
        return empty
    try:
        raw = json.loads(row.events_columns)
    except Exception:
        return empty
    if not isinstance(raw, dict):
        return empty
    if any(k in raw for k in ("columns", "column_sets", "classes", "dashboard")):
        return {**empty, **{k: raw.get(k) or {} for k in empty}}
    return {**empty, "columns": raw}


def _save_prefs(db: Session, user: User, prefs: dict) -> None:
    row = db.get(UserSettings, user.id)
    if not row:
        row = UserSettings(user_id=user.id)
        db.add(row)
    row.events_columns = json.dumps(prefs, ensure_ascii=False)
    db.commit()


def _keep_taxonomy(keys: list[str]) -> list[str]:
    """Taxonomy外KEYを落とす（画面側の不具合等で紛れ込んだ場合の防御。v12 §15）。順序は保つ。"""
    out: list[str] = []
    for k in keys:
        c = canonical_key(k)
        if c and c not in out:
            out.append(c)
    return out


# ---------------------------------------------------------------- 絞り込み

def _period(start: datetime | None, end: datetime | None) -> tuple[datetime, datetime]:
    if start and end:
        return start, end
    e = end or datetime.now(timezone.utc)
    return (start or e - timedelta(hours=DEFAULT_PERIOD_HOURS)), e


def _priority(db: Session) -> list[str]:
    row = db.get(Setting, K_PRIORITY)
    if row and row.value:
        try:
            v = json.loads(row.value)
            if isinstance(v, list) and v:
                return _keep_taxonomy(v) or DEFAULT_DOMAIN_HOST_PRIORITY
        except Exception:
            pass
    db.merge(Setting(key=K_PRIORITY, value=json.dumps(DEFAULT_DOMAIN_HOST_PRIORITY, ensure_ascii=False)))
    db.commit()
    return DEFAULT_DOMAIN_HOST_PRIORITY


# 「注目」判定に使うキーワード（api.py の ATTENTION_KEYWORDS と同じ意味。payload全文に対する一致）
ATTENTION_KEYWORDS = ["fail", "error", "deny", "denied", "invalid", "unauthor", "refused",
                      "reject", "lock", "warn", "attack", "violat", "critical", "alert", "404"]
SEVERE_VALUES = ["warning", "warn", "error", "err", "critical", "crit", "alert", "emerg", "high"]

# 脅威判定で横断的に見るTaxonomy KEY群。同義語として統合しているのではなく、
# 「そのイベントで送信元IP／結果／URIを表しているKEY」を評価時に順に見るだけ（v12 §5.2と同じ考え方）。
# 送信元IPを表し得るTaxonomy KEY
SRC_IP_KEYS = ["srcipv4", "srcipv6", "client", "sourceipaddress", "srchost", "xfwdforip"]
# 結果を表し得るTaxonomy KEY（audit_res は auditd の success/failed）
RESULT_KEYS = ["result", "audit_res", "eventtype", "action"]
# ユーザーを表し得るTaxonomy KEY（audit_acct は auditd のアカウント）
USER_KEYS = ["username", "accountname", "audit_acct", "targetusername"]
STATUS_KEYS = ["statuscode", "status"]
# URIを表し得るTaxonomy KEY（request は "POST /path HTTP/1.1" 形式のリクエスト行）
URI_KEYS = ["uri", "uri_parsed", "url", "request", "query"]

THREATS = ["ioc", "sensitive_path", "web_scan", "auth_fail", "root_ssh", "any"]

# 上の各リストがTaxonomy外KEYを含んでいないことを起動時に検証する（v12 §15）。
# 実装時に「実データにあるから」という理由でTaxonomy外KEYを混ぜてしまう事故を、
# 起動を止めることで確実に防ぐ。使いたいKEYがあるときは、まず docs/taxonomy.md に
# 追加してから taxonomy_master.py を再生成する（backend/tools/gen_taxonomy.py）。
for _name, _keys in (("SRC_IP_KEYS", SRC_IP_KEYS), ("RESULT_KEYS", RESULT_KEYS),
                     ("USER_KEYS", USER_KEYS), ("STATUS_KEYS", STATUS_KEYS),
                     ("URI_KEYS", URI_KEYS), ("DEFAULT_DASHBOARD_AXES", DEFAULT_DASHBOARD_AXES),
                     ("DEFAULT_DOMAIN_HOST_PRIORITY", DEFAULT_DOMAIN_HOST_PRIORITY)):
    _ng = [k for k in _keys if not canonical_key(k)]
    if _ng:
        raise RuntimeError(
            f"{_name} にTaxonomy外KEYが含まれています: {_ng}。"
            "docs/taxonomy.md に定義されたTaxonomy KEYだけを使ってください（v12 §15）。")


def _any_pv(ev, keys: list[str]):
    """複数のTaxonomy KEYのうち最初に値があるもの（横断判定用）。読み替えではなく評価時の走査。"""
    return func.coalesce(*[_pv(ev, k) for k in keys])


@lru_cache(maxsize=4)
def _SENSITIVE_RE(paths: tuple[str, ...]) -> str:
    """機微パス一覧を1本の正規表現（大文字小文字無視で部分一致）へまとめる。
    rules.py の定義をそのまま使い、正規表現の特殊文字だけエスケープする。"""
    return "|".join(re.escape(p) for p in paths)


def _threat_clause(db: Session, ev, threat: str):
    """脅威フィルタ。**判定材料はTaxonomy KEYだけ**（v12 §15。normalized_eventsは使わない）。

    旧実装は normalized_events（MAPPINGSによるKEY読み替えの産物）を見ていたが、
    同じ意味の判定をTaxonomy受信フィールドの上で組み直している。
    機微パス・攻撃シグネチャの定義は rules.py を単一の出処として読み取るだけに留める
    （rules.py 自体は変更しない）。"""
    from .rules import SENSITIVE_PATHS

    uri = _any_pv(ev, URI_KEYS)
    status = _any_pv(ev, STATUS_KEYS)
    result = _any_pv(ev, RESULT_KEYS)
    user = _any_pv(ev, USER_KEYS)
    srcip = _any_pv(ev, SRC_IP_KEYS)

    # 機微パスは約50個あるため ILIKE のOR結合にすると1行あたり50回走って極端に遅い
    # （実測: 24時間分で13秒）。1本の正規表現にまとめてPostgreSQL側の1パスで判定する。
    sensitive = uri.op("~*")(_SENSITIVE_RE(tuple(SENSITIVE_PATHS)))
    # Webスキャンの兆候: 4xx（404等）が立っている
    web_scan = status.op("~")(r"^4\d\d$")
    auth_fail = or_(func.lower(result).in_(["failure", "fail", "failed", "audit_failure"]),
                    func.lower(result).like("%fail%"))
    root_ssh = and_(func.lower(user).in_(["root", "administrator"]), auth_fail)
    # IOC突合: 送信元IP系のTaxonomy KEYの値が ioc テーブルに存在するか（突合はローカル）
    ioc_hit = srcip.in_(select(IOC.value).where(IOC.indicator_type == "ip"))

    table = {"ioc": ioc_hit, "sensitive_path": sensitive, "web_scan": web_scan,
             "auth_fail": auth_fail, "root_ssh": root_ssh}
    if threat == "any":
        return or_(ioc_hit, sensitive, web_scan, auth_fail)
    return table.get(threat)


def _attention_clause(ev):
    """「注目」＝payload全文のキーワード一致、またはTaxonomy KEYの result/severity が失敗・高重大度。
    api.py の同名ロジック（インシデント化の可否判定に使う）と同じ意味を、Taxonomy KEYで組み直したもの。"""
    kw = or_(*[cast(ev.c.payload, String).ilike(f"%{k}%") for k in ATTENTION_KEYWORDS])
    sev = or_(func.lower(_any_pv(ev, RESULT_KEYS)).like("%fail%"),
              func.lower(_pv(ev, "severity")).in_(SEVERE_VALUES))
    return or_(kw, sev)


class EventQuery:
    """Events/Dashboard共通の絞り込み。Taxonomy KEYとClass、期間、全文だけを条件にする。"""

    def __init__(self, db: Session, class_value: str | None, q: str | None,
                 start: datetime | None, end: datetime | None,
                 rep_value: str | None, field: str | None, value: str | None,
                 attention: bool = False, threat: str | None = None, source: str | None = None):
        self.db = db
        self.class_value = class_value
        self.q = q
        self.start, self.end = _period(start, end)
        self.rep_value = rep_value
        # 個別Taxonomyフィールドでの絞り込み（normalize-mapping.md §7.2の単純遷移）。
        # 列ヘッダの絞り込みで複数条件を同時に指定できるよう、KEYと値の対の配列で保持する。
        fs = field if isinstance(field, list) else ([field] if field else [])
        vs = value if isinstance(value, list) else ([value] if value is not None else [])
        self.filters = [(canonical_key(f), v) for f, v in zip(fs, vs) if canonical_key(f)]
        self.attention = attention
        self.threat = threat if threat in THREATS else None
        # ログソース(LogSeeker管理メタデータ)での絞り込み。Dashboardの「ログソース別」から遷移する
        self.source = source

    def apply(self, stmt, ev):
        """CTE(ev)の列だけで条件を組む。期間はCTE側で適用済み。"""
        if self.class_value:
            stmt = stmt.where(_cls(ev) == self.class_value)
        if self.source:
            stmt = stmt.where(ev.c.source == self.source)
        for f, v in self.filters:
            stmt = stmt.where(_pv(ev, f) == v)
        if self.rep_value is not None:
            stmt = stmt.where(self.rep_expr(ev) == self.rep_value)
        if self.q:
            stmt = stmt.where(cast(ev.c.payload, String).ilike(f"%{self.q}%"))
        if self.attention:
            stmt = stmt.where(_attention_clause(ev))
        if self.threat:
            c = _threat_clause(self.db, ev, self.threat)
            if c is not None:
                stmt = stmt.where(c)
        return stmt

    def rep_expr(self, ev):
        """代表値（ドメイン/ホスト）。優先順位の上から最初に見つかった非空VALUE。
        集計とEvents絞り込みで同一式を使うことで、代表値クリック時の取りこぼしを式レベルで
        防ぐ（normalize-mapping.md §7.1）。優先順位は全てTaxonomy KEY。"""
        return func.coalesce(*[_pv(ev, k) for k in _priority(self.db)])


def event_query(db: Session = Depends(get_db), class_value: str | None = None, q: str | None = None,
                start: datetime | None = None, end: datetime | None = None,
                rep_value: str | None = None,
                field: list[str] = Query(default=[]), value: list[str] = Query(default=[]),
                attention: bool = False, threat: str | None = None,
                source: str | None = None) -> EventQuery:
    return EventQuery(db, class_value, q, start, end, rep_value, field, value, attention, threat, source)


# ---------------------------------------------------------------- 行の組み立て

def _row(r, columns: list[str]) -> dict:
    """1行分。値はpayloadのTaxonomy KEYからのみ取り出す（normalized_eventsは使わない）。"""
    p = r.payload if isinstance(r.payload, dict) else {}
    return {
        "id": r.id,
        "received_at": r.received_at.isoformat() if r.received_at else None,
        "class_value": _pick(p, "class") or UNKNOWN_CLASS,
        "source": r.source,
        "resolved": r.resolved,
        "values": {k: _pick(p, k) for k in columns},
    }


# ================================================================ フィールド定義

@router.get("/events/fields")
def events_fields(class_value: str | None = None):
    """Events列として選択できるTaxonomy KEYの全体集合（taxonomy.md §3、762件）。

    **受信データを一切参照しない。** taxonomy.md §3は「この一覧が先に存在し、`class` のVALUEは
    このKEY一覧を制限しない」と定めるため、どのClassでも同じ全KEYから選べる。
    class_value はそのClassの推奨KEY・既定表示列（§6の参考例）を示すためだけに使う。"""
    hints = CLASS_HINTS.get(class_value or "", {})
    keys = [{"key": k, "type": ALL_KEYS[k], "label": label_of(k), "recommended": k in hints}
            for k in ALL_KEYS]
    keys.sort(key=lambda x: (not x["recommended"], x["key"]))
    return {"class_value": class_value, "total": len(keys), "keys": keys,
            "default_columns": default_columns(class_value)}


# ================================================================ 列セット

@router.get("/events/column-sets")
def get_column_sets(class_value: str | None = None, user: User | None = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    """現在の表示列と、名前を付けて保存した列セット（プリセット）一覧。
    未ログイン時はサーバーに保存しないためnullを返し、フロントはlocalStorageへ退避する。"""
    key = class_value or "__all__"
    defaults = default_columns(class_value)
    if not user:
        return {"class_value": class_value, "columns": None, "default_columns": defaults, "sets": {}}
    prefs = _prefs(db.get(UserSettings, user.id))
    return {"class_value": class_value,
            "columns": prefs["columns"].get(key),
            "default_columns": defaults,
            "sets": prefs["column_sets"].get(key) or {}}


@router.put("/events/columns")
def set_columns(body: EventsColumnsUpdate, user: User | None = Depends(get_current_user),
                db: Session = Depends(get_db)):
    """現在の表示列（Class単位）。Taxonomy外KEYは保存時に除外する。"""
    if not user:
        return {"ok": True}
    prefs = _prefs(db.get(UserSettings, user.id))
    prefs["columns"][body.source_type or "__all__"] = _keep_taxonomy(body.columns)
    _save_prefs(db, user, prefs)
    return {"ok": True}


@router.put("/events/column-sets")
def save_column_set(body: EventsColumnSetSave, user: User | None = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    """「名前を付けて保存」。同名があれば上書きする。"""
    if not user:
        return {"ok": True}
    name = body.name.strip()
    if not name:
        return Response(status_code=400, content='{"error":"名前を入力してください"}',
                        media_type="application/json")
    key = body.class_value or "__all__"
    prefs = _prefs(db.get(UserSettings, user.id))
    prefs["column_sets"].setdefault(key, {})[name] = _keep_taxonomy(body.columns)
    _save_prefs(db, user, prefs)
    return {"ok": True, "name": name}


@router.delete("/events/column-sets/{name}")
def delete_column_set(name: str, class_value: str | None = None,
                      user: User | None = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        return {"ok": True}
    prefs = _prefs(db.get(UserSettings, user.id))
    prefs["column_sets"].get(class_value or "__all__", {}).pop(name, None)
    _save_prefs(db, user, prefs)
    return {"ok": True}


# ================================================================ Class

@router.get("/events/classes")
def get_classes(qy: EventQuery = Depends(event_query), db: Session = Depends(get_db),
                user: User | None = Depends(get_current_user)):
    """実際に受信しているClass VALUEの一覧（件数付き）＋利用者の表示/非表示・並び順・ピン留め。
    v12 §3.2によりClass名の固定マスターは持たない。受信したVALUEをそのまま列挙する。"""
    ev = _ev(qy)
    rows = db.execute(select(_cls(ev), func.count()).select_from(ev).group_by(text("1"))).all()
    counts = {(c or "unknown"): n for c, n in rows}

    prefs = _prefs(db.get(UserSettings, user.id) if user else None)
    hidden = set(prefs["classes"].get("hidden") or [])
    order = prefs["classes"].get("order") or []
    pinned = set(prefs["classes"].get("pinned") or [])

    items = [{"class_value": c, "count": n, "hidden": c in hidden, "pinned": c in pinned,
              "has_hints": c in CLASS_HINTS} for c, n in counts.items()]
    items.sort(key=lambda it: (order.index(it["class_value"]) if it["class_value"] in order else 999,
                               it["class_value"]))
    return {"classes": items}


@router.put("/events/classes")
def set_classes(body: EventsClassesUpdate, user: User | None = Depends(get_current_user),
                db: Session = Depends(get_db)):
    if not user:
        return {"ok": True}
    prefs = _prefs(db.get(UserSettings, user.id))
    prefs["classes"] = {"hidden": body.hidden, "order": body.order, "pinned": body.pinned}
    _save_prefs(db, user, prefs)
    return {"ok": True}


# ================================================================ 一覧・詳細

@router.get("/events/search")
def search_events(qy: EventQuery = Depends(event_query), db: Session = Depends(get_db),
                  columns: str = Query("", description="表示するTaxonomy KEY(カンマ区切り)"),
                  limit: int = Query(50, ge=1, le=1000), offset: int = Query(0, ge=0)):
    cols = _keep_taxonomy([c for c in columns.split(",") if c.strip()]) or default_columns(qy.class_value)
    ev = _ev(qy)
    base = qy.apply(select(ev).select_from(ev), ev)
    total = db.scalar(select(func.count()).select_from(base.subquery()))
    stmt = base.order_by(ev.c.received_at.desc(), ev.c.id.desc()).limit(limit).offset(offset)
    items = [_row(r, cols) for r in db.execute(stmt).all()]
    return {"total": total, "limit": limit, "offset": offset, "columns": cols, "items": items}


@router.get("/events/histogram")
def histogram(qy: EventQuery = Depends(event_query), db: Session = Depends(get_db),
              buckets: int = Query(60, ge=10, le=200)):
    """検索結果の時系列分布（画面上部の「視覚化」トグルで出すヒストグラム）。"""
    span = max((qy.end - qy.start).total_seconds(), 1)
    width = span / buckets
    ev = _ev(qy)
    idx = func.floor(func.extract("epoch", ev.c.received_at - qy.start) / width)
    stmt = qy.apply(select(idx.label("b"), func.count()).select_from(ev), ev).group_by(text("1")).order_by(text("1"))
    got = {int(b): n for b, n in db.execute(stmt).all() if b is not None}
    return {"start": qy.start.isoformat(), "end": qy.end.isoformat(), "width_seconds": width,
            "buckets": [{"t": (qy.start + timedelta(seconds=width * i)).isoformat(),
                         "count": got.get(i, 0)} for i in range(buckets)]}


@router.get("/events/facet")
def facet(field: str, qy: EventQuery = Depends(event_query), db: Session = Depends(get_db),
          top: int = Query(20, ge=1, le=200)):
    """指定Taxonomy KEYの値の内訳（セルの絞り込みメニュー・Dashboardの内訳で使う）。"""
    if not is_taxonomy_key(field):
        return {"field": field, "values": []}
    ev = _ev(qy)
    col = _pv(ev, field)
    stmt = qy.apply(select(col.label("v"), func.count()).select_from(ev), ev).where(col.isnot(None))
    stmt = stmt.group_by(text("1")).order_by(func.count().desc()).limit(top)
    return {"field": field, "label": label_of(field),
            "values": [{"value": v, "count": n} for v, n in db.execute(stmt).all()]}


@router.get("/events/detail/{event_id}")
def detail(event_id: int, db: Session = Depends(get_db)):
    """イベント詳細。受信フィールド（Taxonomy KEY完全一致分）だけを返す。
    Taxonomy外KEYはDBに無改変で残るが、返却も表示もしない（v12 §10.3）。"""
    ev = db.get(Event, event_id)
    if not ev:
        return Response(status_code=404, content='{"error":"not found"}', media_type="application/json")
    p = ev.payload if isinstance(ev.payload, dict) else {}
    # 照合は大文字小文字を無視する。表示するTaxonomy KEYは正規表記（例 eventtime）とし、
    # 実際に受信したKEY名（例 EventTime）も併せて返す（payloadは無改変であることを示すため）。
    fields = []
    for k, v in p.items():
        c = canonical_key(k)
        if not c or v in (None, ""):
            continue
        fields.append({"key": c, "received_key": k, "value": v,
                       "label": label_of(c), "type": ALL_KEYS.get(c)})
    fields.sort(key=lambda f: f["key"])
    hidden = sum(1 for k in p if not is_taxonomy_key(k))

    # ケース/インシデントへの導線（調査支援機能。既存テーブルを読むだけで一切変更しない）
    from .api import is_event_attention
    from .models import Case, CaseEvent, Incident
    link = db.execute(select(CaseEvent.case_id, Case.title)
                      .join(Case, Case.id == CaseEvent.case_id)
                      .where(CaseEvent.event_id == event_id)).first()
    inc = db.execute(select(Incident.id, Incident.title).where(Incident.event_id == event_id)).first()

    return {
        "id": ev.id,
        "class_value": _pick(p, "class") or UNKNOWN_CLASS,
        "source": ev.source,
        "received_at": ev.received_at.isoformat() if ev.received_at else None,
        "ingest_channel": ev.ingest_channel,
        "resolved": ev.resolved,
        "fields": fields,
        "taxonomy_outside_count": hidden,   # 件数だけ知らせる（中身は出さない）
        "is_attention": is_event_attention(db, event_id),
        "linked_case": {"id": link[0], "title": link[1]} if link else None,
        "linked_incident": {"id": inc[0], "title": inc[1]} if inc else None,
    }


@router.get("/events/export")
def export_events(qy: EventQuery = Depends(event_query), db: Session = Depends(get_db),
                  columns: str = Query(""), format: str = Query("csv", pattern="^(csv|json)$"),
                  actor=Depends(require_login)):
    """現在の絞り込み・表示列でCSV/JSON出力（画面のExport Table相当）。"""
    cols = _keep_taxonomy([c for c in columns.split(",") if c.strip()]) or default_columns(qy.class_value)
    ev = _ev(qy)
    stmt = qy.apply(select(ev).select_from(ev), ev).order_by(ev.c.received_at.desc(), ev.c.id.desc()).limit(EXPORT_MAX_ROWS)
    rows = [_row(r, cols) for r in db.execute(stmt).all()]

    from .auth import audit
    audit(db, action="events.export", user=actor, detail=f"format={format}, rows={len(rows)}")

    if format == "json":
        return Response(content=json.dumps(rows, ensure_ascii=False, indent=2, default=str),
                        media_type="application/json; charset=utf-8",
                        headers={"Content-Disposition": "attachment; filename=logseeker_events.json"})
    buf = io.StringIO()
    head = ["id", "class", "受信時刻"] + [label_of(c) or c for c in cols]
    w = csv.writer(buf)
    w.writerow(head)
    for r in rows:
        w.writerow([r["id"], r["class_value"], r["received_at"]] + [r["values"].get(c, "") for c in cols])
    return Response(content="﻿" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=logseeker_events.csv"})


# ================================================================ Dashboard

@router.get("/dashboard/overview")
def overview(qy: EventQuery = Depends(event_query), db: Session = Depends(get_db),
             fields: str = Query("", description="内訳カードにするTaxonomy KEY(カンマ区切り)"),
             extra_fields: str = Query("", description="代表値グループに追加表示するTaxonomy KEY")):
    """Dashboard。集計軸はすべてTaxonomy KEY。normalized_eventsは使わない。

    **どのKEYを集計するかは固定しない。** `fields` でLogSeeker利用者が選んだTaxonomy KEYを
    集計軸にする（未指定ならそのClassの既定表示列を使う）。特定KEYを実装側で決め打ちすると、
    送信元がどのTaxonomy KEYを使っているかによって画面が空になるため。"""
    priority = _priority(db)
    extras = _keep_taxonomy([x for x in extra_fields.split(",") if x.strip()])
    axes = _keep_taxonomy([x for x in fields.split(",") if x.strip()]) or \
        _keep_taxonomy(DEFAULT_DASHBOARD_AXES)

    # ---- 内訳は payload を1回だけ展開して集計する ----
    # 軸ごとに `lp->>'key'` を取り出すと、行あたり軸の数だけJSONB抽出が走って遅い
    # （本番57,012件・軸16本で実測12.9秒）。jsonb_each_text で payload を1回展開し、
    # lower(key) が対象軸に含まれる行だけを残して集計する。KEYの小文字化コピー(lp)を
    # 作る必要もなくなるため、この経路ではCTEを使わない。
    want = [k for k in axes] + [k for k in extras]
    kv = func.jsonb_each_text(Event.payload).table_valued("key", "value") \
             .render_derived(name="kv", with_types=False).lateral()
    scan = _scoped(select(func.lower(kv.c.key).label("k"), kv.c.value.label("v"),
                          func.count().label("c")).join(kv, true()), qy)         .where(func.lower(kv.c.key).in_(want), func.nullif(kv.c.value, "").isnot(None))         .group_by(text("1"), text("2")).subquery()
    ranked = select(scan.c.k, scan.c.v, scan.c.c,
                    func.row_number().over(partition_by=scan.c.k,
                                           order_by=scan.c.c.desc()).label("rn")).subquery()
    got: dict[str, list[dict]] = {}
    for k, v, c in db.execute(select(ranked.c.k, ranked.c.v, ranked.c.c)
                              .where(ranked.c.rn <= TOP_N).order_by(ranked.c.k, ranked.c.c.desc())).all():
        got.setdefault(k, []).append({"value": v, "count": c})

    # ログソースと総数は payload に触れずに取れる（received_at のインデックスだけで済む）
    src_q = _scoped(select(Event.source.label("s"), func.count().label("n")), qy).group_by(text("1"))
    by_source: dict[str, int] = {}
    total = 0
    for s, n in db.execute(src_q).all():
        total += n
        if s:
            by_source[s] = n

    # Class は class KEY を持つ行だけ集計し、残りを unknown として差分で求める
    # （行ごとの相関サブクエリを避けるため）
    by_class: dict[str, int] = {}
    cls_q = _scoped(select(kv.c.value.label("v"), func.count().label("n")).join(kv, true()), qy) \
        .where(func.lower(kv.c.key) == "class", func.nullif(kv.c.value, "").isnot(None)).group_by(text("1"))
    named = 0
    for v, n in db.execute(cls_q).all():
        by_class[v] = n
        named += n
    if total - named > 0:
        by_class[UNKNOWN_CLASS] = total - named

    # 代表値は「優先順位の上から最初に見つかった非空VALUE」なので行ごとの解決が要る。
    # DISTINCT ON で1行1件に絞ってから件数を数える（payload展開はここでも1回だけ）。
    prio = pg_array([literal(p) for p in priority])
    picked = _scoped(select(Event.id.label("id"), kv.c.value.label("v")).join(kv, true()), qy) \
        .where(func.lower(kv.c.key).in_(priority), func.nullif(kv.c.value, "").isnot(None)) \
        .distinct(Event.id) \
        .order_by(Event.id, func.array_position(prio, func.lower(kv.c.key))).subquery()
    by_rep = {v: n for v, n in db.execute(
        select(picked.c.v, func.count()).group_by(text("1")).order_by(func.count().desc())).all()}

    def _top(d: dict) -> list[dict]:
        return [{"value": k, "count": v} for k, v in sorted(d.items(), key=lambda x: -x[1])[:TOP_N]]
    breakdowns = [{"field": k, "label": label_of(k), "values": got.get(k, [])} for k in axes]
    return {
        "total": total,
        "period": {"start": qy.start.isoformat(), "end": qy.end.isoformat()},
        # ログソース(source)はLogSeeker管理メタデータ。§4.1.1により表示・集計に使ってよい
        "by_source": _top(by_source),
        "source_count": len(by_source),
        "host_domain_count": len(by_rep),
        "ingest_failed": db.scalar(select(func.count()).select_from(Event)
                                   .where(Event.parse_status == "failed",
                                          Event.received_at >= qy.start, Event.received_at <= qy.end)) or 0,
        "by_class": _top(by_class),
        # ドメイン/ホストは代表値優先順位で集約（v12 §5.3）
        "domain_host": {"priority": priority, "representative": _top(by_rep),
                        "extra": {k: got.get(k, []) for k in extras}},
        # 利用者が選んだTaxonomy KEYごとの内訳カード（既定はDEFAULT_DASHBOARD_AXES）
        "breakdowns": [b for b in breakdowns if b["values"]],
        "empty_axes": [b["field"] for b in breakdowns if not b["values"]],
    }


@router.get("/dashboard/timeline")
def dashboard_timeline(db: Session = Depends(get_db),
                       interval: str = Query("hour", pattern="^(hour|day)$"),
                       date: str | None = Query(None, description="基準日 YYYY-MM-DD（未指定なら本日）"),
                       class_value: str | None = None):
    """イベント件数の推移（時間別＝指定日の24バケット / 日別＝指定日までの30日）。

    時間軸は受信時刻（`received_at`、管理メタデータ）。インデックスがあるため速い。
    バケット境界はJSTで切る（UTC基準だと日別が日本時間09:00で変わってしまう）。"""
    try:
        base = datetime.fromisoformat(date).date() if date else datetime.now(ZoneInfo(DISPLAY_TZ)).date()
    except ValueError:
        base = datetime.now(ZoneInfo(DISPLAY_TZ)).date()

    tz = ZoneInfo(DISPLAY_TZ)
    if interval == "hour":
        start = datetime.combine(base, datetime.min.time(), tzinfo=tz)
        end = start + timedelta(days=1)
        step, n = timedelta(hours=1), 24
    else:
        end = datetime.combine(base, datetime.min.time(), tzinfo=tz) + timedelta(days=1)
        start = end - timedelta(days=30)
        step, n = timedelta(days=1), 30

    local = Event.received_at.op("AT TIME ZONE")(text(f"'{DISPLAY_TZ}'"))
    bucket = func.date_trunc(interval, local)
    stmt = (select(bucket.label("b"), func.count()).select_from(Event)
            .where(Event.received_at >= start, Event.received_at < end))
    if class_value:
        stmt = stmt.where(func.coalesce(func.nullif(Event.payload["class"].astext, ""),
                                        func.cast(UNKNOWN_CLASS, String)) == class_value)
    got = {b.replace(tzinfo=None): n for b, n in db.execute(stmt.group_by(text("1"))).all() if b}

    buckets = []
    for i in range(n):
        t = start + step * i
        key = t.astimezone(tz).replace(tzinfo=None)
        buckets.append({"t": t.isoformat(), "count": got.get(key, 0)})
    return {"interval": interval, "date": base.isoformat(), "buckets": buckets}
