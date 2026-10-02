"""ルールパック（宣言型の検知ルール。docs/rulepack.md）。

ルールを Python のコードではなくデータ（YAML）で書き、このモジュールの共通エンジンで評価する。
将来はルールパックを外部（rule.logseeker.jp 等）から配信できるようにする前提で、
次の性質を最初から持たせている。

- **コードを実行しない。** ルールにできるのは「正規化列 / Taxonomy KEY に対する条件」
  「集約キー」「件数・種類数のしきい値」「証跡に並べる項目」だけ。SQLは常にこのモジュールが組み立て、
  値はすべてバインド変数で渡す。
- **Taxonomy外KEYを使わない。** 条件・証跡に書けるKEYは taxonomy_master.ALL_KEYS に
  あるものだけ（normalize-mapping.md §2.2）。手元のTaxonomyに無いKEYを使うルールは読み込まない
  （配信側のルールが新しく、Taxonomyの更新が追いついていない場合に安全側へ倒すため）。
- **1ルールの不備で全体を止めない。** 検証に失敗したルールはそのルールだけ読み込まず、
  理由を LOAD_ERRORS とログに残す。評価中の失敗も同様に、そのルールだけ飛ばす。
- **重い問い合わせで止まらない。** 1ルールの評価に statement_timeout をかける。
- **外部から受け取るパックは署名必須。** verify_signature()（Ed25519）で検証してから読み込む。
  同梱パック（rulepacks/builtin.yaml）はアプリのコードと同じ扱いのため署名は不要。
"""
import base64
import logging
import re
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import String, and_, case, cast, func, literal, not_, or_, select, text, type_coerce
from sqlalchemy.dialects.postgresql import ARRAY, INET
from sqlalchemy.orm import Session

from .models import Event
from .taxonomy_master import canonical_key

log = logging.getLogger("rulepack")

FORMAT_VERSION = 1
BUILTIN_PATH = Path(__file__).parent / "rulepacks" / "builtin.yaml"

# 条件・集約・証跡に使える正規化列（安全なホワイトリスト）
COLS: dict[str, Any] = {
    "source": Event.source, "source_type": Event.source_type,
    "event_category": Event.event_category, "event_action": Event.event_action,
    "event_result": Event.event_result, "source_ip": Event.source_ip,
    "source_country": Event.source_country, "actor_user": Event.actor_user,
    "host_name": Event.host_name, "device_name": Event.device_name,
    "service_name": Event.service_name, "url_domain": Event.url_domain,
    "url_path": Event.url_path, "http_status_code": Event.http_status_code,
    "message": Event.message,
}
# 集約キーに使える列（＝「関連イベントを見る」でEventsの絞り込みに使えるもの。api.TAX_COLS に含まれる）
GROUPABLE = {"source", "source_ip", "actor_user", "host_name", "device_name", "service_name",
             "url_domain", "source_country", "event_action"}
SEVERITIES = {"critical", "high", "warning", "info"}
CATEGORIES = {"security", "operations"}
OPS = {"eq", "ne", "in", "not_in", "contains", "startswith", "endswith", "regex", "exists", "ip_global"}
MAX_HITS_PER_RULE = 50
STATEMENT_TIMEOUT_MS = 10000
MAX_DEPTH = 6
MAX_LEAVES = 60
MAX_REGEX_LEN = 300
MAX_REGEX_COUNT = 40

# ip_global で「グローバルでない」とみなす範囲（Pythonの ipaddress.is_global に概ね合わせる）
_NON_GLOBAL_NETS = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001:db8::/32",
    "fc00::/7", "fe80::/10", "ff00::/8",
]

# 読み込み結果（/api/rules と管理画面向け）
LOADED: list[dict] = []          # 検証済みルール
LOAD_ERRORS: list[str] = []      # 読み込みを見送ったルールとその理由
PACK_INFO: dict[str, Any] = {}   # パック名・バージョン


class RuleError(ValueError):
    pass


# ================================================================ 検証

def _as_list(v) -> list:
    return v if isinstance(v, list) else [v]


def _check_field(node: dict, where: str) -> None:
    has_key, has_col = "key" in node, "col" in node
    if has_key == has_col:
        raise RuleError(f"{where}: key と col のどちらか一方を指定してください")
    if has_key:
        for k in _as_list(node["key"]):
            if not isinstance(k, str) or not canonical_key(k):
                raise RuleError(f"{where}: Taxonomy KEYではありません: {k!r}")
    else:
        for c in _as_list(node["col"]):
            if c not in COLS:
                raise RuleError(f"{where}: 使えない列です: {c!r}")


def _check_regex(pat, where: str) -> None:
    pats = _as_list(pat)
    if len(pats) > MAX_REGEX_COUNT:
        raise RuleError(f"{where}: 正規表現が多すぎます（{len(pats)}件）")
    for p in pats:
        if not isinstance(p, str) or not p or len(p) > MAX_REGEX_LEN:
            raise RuleError(f"{where}: 正規表現は1〜{MAX_REGEX_LEN}文字の文字列にしてください")
        if "\\b" in p:
            # PostgreSQLの正規表現では \b は後退文字。単語境界は \y だが、意図を誤りやすいので禁止。
            raise RuleError(f"{where}: \\b は使えません（PostgreSQLでは単語境界の意味にならない）")
        try:
            re.compile(p)
        except re.error as e:
            raise RuleError(f"{where}: 正規表現が不正です: {p!r} ({e})") from None


def _check_cond(node, where: str, depth: int, leaves: list) -> None:
    if depth > MAX_DEPTH:
        raise RuleError(f"{where}: 条件の入れ子が深すぎます")
    if not isinstance(node, dict) or not node:
        raise RuleError(f"{where}: 条件はオブジェクトで書いてください")
    groups = [k for k in ("all", "any", "not") if k in node]
    if groups:
        if len(node) != 1:
            raise RuleError(f"{where}: all/any/not は単独で書いてください")
        g = groups[0]
        if g == "not":
            _check_cond(node["not"], f"{where}.not", depth + 1, leaves)
        else:
            items = node[g]
            if not isinstance(items, list) or not items:
                raise RuleError(f"{where}.{g}: 1つ以上の条件を並べてください")
            for i, c in enumerate(items):
                _check_cond(c, f"{where}.{g}[{i}]", depth + 1, leaves)
        return
    leaves.append(node)
    if len(leaves) > MAX_LEAVES:
        raise RuleError(f"{where}: 条件が多すぎます")
    _check_field(node, where)
    ops = [k for k in node if k in OPS]
    extra = set(node) - OPS - {"key", "col"}
    if len(ops) != 1 or extra:
        raise RuleError(f"{where}: 演算子を1つだけ指定してください（{sorted(OPS)}）")
    op, val = ops[0], node[ops[0]]
    if op in ("exists", "ip_global"):
        if not isinstance(val, bool):
            raise RuleError(f"{where}: {op} は true/false で指定してください")
    elif op == "regex":
        _check_regex(val, where)
    elif op in ("in", "not_in"):
        if not isinstance(val, list) or not val or not all(isinstance(x, (str, int)) for x in val):
            raise RuleError(f"{where}: {op} は値のリストで指定してください")
    elif not isinstance(val, (str, int)) or isinstance(val, bool):
        raise RuleError(f"{where}: {op} の値は文字列か数値にしてください")


def validate_rule(r: dict, reserved_ids: set[str]) -> dict:
    """1ルールを検証して正規化した dict を返す。不備があれば RuleError。"""
    if not isinstance(r, dict):
        raise RuleError("ルールはオブジェクトで書いてください")
    rid = r.get("id")
    if not isinstance(rid, str) or not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", rid):
        raise RuleError(f"id が不正です: {rid!r}")
    where = rid
    if rid in reserved_ids:
        raise RuleError(f"{where}: 組み込みルールと id が重複しています")
    for f in ("name", "description", "recommendation"):
        if not isinstance(r.get(f), str) or not r[f].strip():
            raise RuleError(f"{where}: {f} がありません")
    if r.get("severity") not in SEVERITIES:
        raise RuleError(f"{where}: severity は {sorted(SEVERITIES)} のいずれか")
    if r.get("category") not in CATEGORIES:
        raise RuleError(f"{where}: category は {sorted(CATEGORIES)} のいずれか")
    scope = r.get("scope")
    if not isinstance(scope, dict) or not scope:
        # payload の展開対象を必ず絞らせる（全イベントを展開すると重い）
        raise RuleError(f"{where}: scope（正規化列による対象の絞り込み）は必須です")
    for c, v in scope.items():
        if c not in COLS:
            raise RuleError(f"{where}.scope: 使えない列です: {c!r}")
        if not all(isinstance(x, (str, int)) and not isinstance(x, bool) for x in _as_list(v)):
            raise RuleError(f"{where}.scope.{c}: 値は文字列か、そのリストにしてください")
    if "match" in r:
        _check_cond(r["match"], f"{where}.match", 1, [])
    gb = r.get("group_by")
    if not isinstance(gb, list) or not 1 <= len(gb) <= 3 or not all(g in GROUPABLE for g in gb):
        raise RuleError(f"{where}: group_by は {sorted(GROUPABLE)} から1〜3個")
    th = r.get("threshold") or {"count": 1}
    if not isinstance(th, dict) or set(th) - {"count", "distinct", "min_distinct"}:
        raise RuleError(f"{where}: threshold は count / distinct / min_distinct のみ")
    if not isinstance(th.get("count", 1), int) or th.get("count", 1) < 1:
        raise RuleError(f"{where}: threshold.count は1以上の整数")
    if ("distinct" in th) != ("min_distinct" in th):
        raise RuleError(f"{where}: threshold.distinct と min_distinct はセットで指定してください")
    if "distinct" in th:
        _check_field(th["distinct"], f"{where}.threshold.distinct")
        if not isinstance(th["min_distinct"], int) or th["min_distinct"] < 1:
            raise RuleError(f"{where}: threshold.min_distinct は1以上の整数")
    ev = r.get("evidence") or []
    if not isinstance(ev, list) or len(ev) > 6:
        raise RuleError(f"{where}: evidence は6項目まで")
    for i, e in enumerate(ev):
        if not isinstance(e, dict) or not isinstance(e.get("label"), str):
            raise RuleError(f"{where}.evidence[{i}]: label が必要です")
        _check_field(e, f"{where}.evidence[{i}]")
        if e.get("show", "values") not in ("values", "count"):
            raise RuleError(f"{where}.evidence[{i}]: show は values / count")
        if not isinstance(e.get("limit", 3), int) or not 1 <= e.get("limit", 3) <= 5:
            raise RuleError(f"{where}.evidence[{i}]: limit は1〜5")
        if not isinstance(e.get("truncate", 160), int) or not 10 <= e.get("truncate", 160) <= 500:
            raise RuleError(f"{where}.evidence[{i}]: truncate は10〜500")
    title = r.get("title", r["name"])
    if not isinstance(title, str):
        raise RuleError(f"{where}: title は文字列")
    return {**r, "title": title, "threshold": th, "evidence": ev}


def load_pack_text(raw: str, reserved_ids: set[str]) -> tuple[dict, list[dict], list[str]]:
    """パック本文（YAML）を読み、(パック情報, 検証済みルール, 見送り理由) を返す。

    パック全体の形式が不正なら RuleError。個々のルールの不備は見送り理由に積んで続行する。"""
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise RuleError(f"YAMLとして読めません: {e}") from None
    if not isinstance(doc, dict):
        raise RuleError("パックはオブジェクトで書いてください")
    if doc.get("format") != FORMAT_VERSION:
        # 新しい形式のパックを古いエンジンで誤解釈しないよう、知らない形式は丸ごと読まない
        raise RuleError(f"未対応の形式です: format={doc.get('format')!r}（対応: {FORMAT_VERSION}）")
    rules = doc.get("rules")
    if not isinstance(rules, list):
        raise RuleError("rules がありません")
    info = {"pack": str(doc.get("pack", "")), "version": str(doc.get("version", ""))}
    ok: list[dict] = []
    errors: list[str] = []
    seen = set(reserved_ids)
    for i, r in enumerate(rules):
        try:
            v = validate_rule(r, seen)
            seen.add(v["id"])
            ok.append(v)
        except RuleError as e:
            errors.append(f"rules[{i}] {e}")
    return info, ok, errors


def verify_signature(data: bytes, signature_b64: str, public_keys_b64: list[str]) -> bool:
    """Ed25519署名の検証。外部から受け取るパックは、これが True のときだけ読み込むこと。

    公開鍵は複数受け付ける（鍵の入れ替え期間に新旧どちらの署名も通すため）。
    cryptography は署名検証のときだけ必要なので、ここで遅延importする
    （同梱パックだけを使う環境では未導入でも起動・評価できる）。"""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        sig = base64.b64decode(signature_b64.strip(), validate=True)
    except ValueError:
        return False
    for pk in public_keys_b64:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(pk.strip(), validate=True)).verify(sig, data)
            return True
        except (InvalidSignature, ValueError):
            continue
    return False


def load_builtin(reserved_ids: set[str]) -> None:
    """同梱パックを読み込んで LOADED に入れる（起動時に1回。rules.py から呼ぶ）。"""
    LOADED.clear()
    LOAD_ERRORS.clear()
    PACK_INFO.clear()
    try:
        info, ok, errors = load_pack_text(BUILTIN_PATH.read_text(encoding="utf-8"), reserved_ids)
    except (OSError, RuleError) as e:
        LOAD_ERRORS.append(f"{BUILTIN_PATH.name}: {e}")
        log.error("rule pack not loaded: %s", e)
        return
    LOADED.extend(ok)
    LOAD_ERRORS.extend(errors)
    PACK_INFO.update(info)
    for e in errors:
        log.warning("rule skipped: %s", e)


def rule_defs() -> list[dict]:
    """監視ルール一覧（/api/rules）用の定義。"""
    return [{k: r[k] for k in ("id", "name", "severity", "category", "description", "recommendation")}
            for r in LOADED]


# ================================================================ SQL化

def _uses_key(rule: dict) -> bool:
    """ルールが payload の Taxonomy KEY を参照するか（参照しなければ payload を展開しない）。"""
    def walk(n) -> bool:
        if isinstance(n, dict):
            return "key" in n or any(walk(v) for v in n.values())
        if isinstance(n, list):
            return any(walk(v) for v in n)
        return False
    return walk(rule.get("match")) or walk(rule["evidence"]) or walk(rule["threshold"].get("distinct"))


class _Ctx:
    """1ルール分のSQL組み立て。対象行をCTEに絞ってから payload を展開する。"""

    def __init__(self, rule: dict, w: list):
        self.uses_keys = _uses_key(rule)
        cols = [c.label(n) for n, c in COLS.items()]
        if self.uses_keys:
            from .events_api import _lc_payload  # 循環importを避けるため遅延import
            cols.append(_lc_payload().label("lp"))
        scope = [COLS[c].in_([str(x) for x in _as_list(v)]) for c, v in rule["scope"].items()]
        # MATERIALIZED: 小文字化したpayloadを1行1回だけ作る（条件ごとに展開が走らないように）
        self.cte = select(*cols).where(*scope, *w).cte("rp").prefix_with("MATERIALIZED")

    def _one(self, node: dict, name: str):
        """正規化済みの値。前後の空白を除き、空文字と "-"（Windows等の「値なし」）は NULL。"""
        raw = self.cte.c.lp[name.lower()].astext if "key" in node else cast(self.cte.c[name], String)
        return func.nullif(func.nullif(func.btrim(raw), ""), "-")

    def value(self, node: dict):
        names = _as_list(node["key"] if "key" in node else node["col"])
        vals = [self._one(node, n) for n in names]
        return vals[0] if len(vals) == 1 else func.coalesce(*vals)

    def values(self, node: dict) -> list:
        """key/col にリストを書いた場合は「どれか1つが条件を満たす」として扱う。"""
        return [self._one(node, n) for n in _as_list(node["key"] if "key" in node else node["col"])]

    def cond(self, node: dict):
        if "all" in node:
            return and_(*[self.cond(c) for c in node["all"]])
        if "any" in node:
            return or_(*[self.cond(c) for c in node["any"]])
        if "not" in node:
            return not_(self.cond(node["not"]))
        op = next(k for k in node if k in OPS)
        val = node[op]
        preds = [self._leaf(v, op, val) for v in self.values(node)]
        if op in ("ne", "not_in"):
            return and_(*preds)  # 否定系は「どの値も一致しない」
        return or_(*preds)

    @staticmethod
    def _leaf(v, op: str, val):
        # 比較は大文字小文字を区別しない。NULLは常に「一致しない」に倒す（coalesce で false）。
        lv = func.lower(v)
        if op == "eq":
            p = lv == str(val).lower()
        elif op == "ne":
            return func.coalesce(lv != str(val).lower(), True)
        elif op == "in":
            p = lv.in_([str(x).lower() for x in val])
        elif op == "not_in":
            return func.coalesce(lv.notin_([str(x).lower() for x in val]), True)
        elif op == "contains":
            p = lv.contains(str(val).lower(), autoescape=True)
        elif op == "startswith":
            p = lv.startswith(str(val).lower(), autoescape=True)
        elif op == "endswith":
            p = lv.endswith(str(val).lower(), autoescape=True)
        elif op == "regex":
            p = or_(*[v.op("~*")(r) for r in _as_list(val)])
        elif op == "exists":
            return v.isnot(None) if val else v.is_(None)
        elif op == "ip_global":
            g = case((func.pg_input_is_valid(v, "inet"),
                      not_(cast(v, _INET).op("<<=")(func.any(cast(literal(_NON_GLOBAL_NETS), _INET_ARRAY))))),
                     else_=False)
            return func.coalesce(g, False) if val else not_(func.coalesce(g, False))
        else:  # pragma: no cover - validate で弾いている
            raise RuleError(op)
        return func.coalesce(p, False)


_INET = INET()
_INET_ARRAY = ARRAY(INET)


def _uniq_text(vals: list | None, total: int, limit: int, trunc: int) -> str:
    vals = [str(v)[:trunc] for v in (vals or []) if v not in (None, "")]
    if not vals:
        return "-"
    more = f" ほか{total - limit}件" if total > limit else ""
    return "、".join(vals[:limit]) + more


def evaluate_rule(db: Session, rule: dict, w: list) -> list[dict]:
    ctx = _Ctx(rule, w)
    c = ctx.cte.c
    gb = rule["group_by"]
    grp = func.coalesce(*[cast(c[g], String) for g in gb]) if len(gb) > 1 else cast(c[gb[0]], String)
    grp_field = case(*[(c[g].isnot(None), literal(g)) for g in gb], else_=literal(None))
    th = rule["threshold"]

    cols = [grp.label("grp"), grp_field.label("grp_field"), func.count().label("n")]
    dist = None
    if "distinct" in th:
        dist = func.count(func.distinct(ctx.value(th["distinct"])))
        cols.append(dist.label("d"))
    for i, e in enumerate(rule["evidence"]):
        v = ctx.value(e)
        lim = e.get("limit", 3)
        cols.append(func.count(func.distinct(v)).label(f"e{i}_n"))
        if e.get("show", "values") == "values":
            # 証跡に並べるのは先頭 limit 件だけなので、SQL側で切り出す（値が数千種類あっても運ばない）
            agg = type_coerce(func.array_agg(func.distinct(v)).filter(v.isnot(None)), ARRAY(String))
            cols.append(agg[1:lim].label(f"e{i}_v"))

    stmt = select(*cols).select_from(ctx.cte)
    if "match" in rule:
        stmt = stmt.where(ctx.cond(rule["match"]))
    having = [func.count() >= th.get("count", 1)]
    if dist is not None:
        having.append(dist >= th["min_distinct"])
    stmt = (stmt.group_by(text("1"), text("2")).having(and_(*having))
            .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE))

    hits = []
    for row in db.execute(stmt).mappings().all():
        parts = []
        for i, e in enumerate(rule["evidence"]):
            if e.get("show", "values") == "count":
                parts.append(f"{e['label']}: {row[f'e{i}_n']}")
            else:
                parts.append(f"{e['label']}: "
                             f"{_uniq_text(row[f'e{i}_v'], row[f'e{i}_n'], e.get('limit', 3), e.get('truncate', 160))}")
        parts.append(f"{row['n']} 件")
        key = row["grp"]
        hits.append({
            "rule_id": rule["id"], "rule_name": rule["name"], "severity": rule["severity"],
            "category": rule["category"], "title": f"{rule['title']}: {key if key else '(不明)'}",
            "evidence": " / ".join(parts), "count": row["n"], "recommendation": rule["recommendation"],
            "pivot": {"field": row["grp_field"], "value": str(key)} if key else None,
        })
    return hits


def evaluate(db: Session, w: list) -> list[dict]:
    """読み込み済みの全ルールを評価する。1ルールの失敗・タイムアウトは他に波及させない。"""
    hits: list[dict] = []
    if not LOADED:
        return hits
    prev = db.execute(text("SHOW statement_timeout")).scalar()
    for rule in LOADED:
        try:
            with db.begin_nested():
                db.execute(text(f"SET LOCAL statement_timeout = {int(STATEMENT_TIMEOUT_MS)}"))
                hits.extend(evaluate_rule(db, rule, w))
        except Exception as e:  # noqa: BLE001 - 1ルールの失敗で注意喚起全体を落とさない
            # SQLAlchemyの例外文字列はSQL全文を含んで数千文字になるため、1行目だけ残す
            log.warning("rule %s failed: %s", rule["id"], (str(e).splitlines() or [""])[0][:300])
        finally:
            db.execute(text("SELECT set_config('statement_timeout', :v, true)"), {"v": prev})
    return hits
