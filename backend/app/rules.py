"""ルールベース注意喚起（PROJECT.md §15）。蓄積データを走査し、攻撃の兆候＋対策を提示。
AI不要・SQL集計のみ。各ヒットに recommendation（対策）を付ける。IOC一致は最優先。"""
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .models import CustomRule, Event, EventEntity, IOC, Setting
from .models import NormalizedEvent as N

# カスタムルールが対象にできる正規化フィールド（安全なホワイトリスト。任意コード実行はしない）。
FIELD_MAP: dict[str, Any] = {
    "message": N.message, "url_path": N.url_path, "url_domain": N.url_domain,
    "actor_user": N.actor_user, "source_ip": N.source_ip, "device_name": N.device_name,
    "event_category": N.event_category, "event_action": N.event_action, "event_result": N.event_result,
    "http_status_code": N.http_status_code, "service_name": N.service_name,
    "source_country": N.source_country, "host_name": N.host_name,
    "source_asn": N.source_asn, "source_as_org": N.source_as_org,
}
# 集計軸（group_by）に使える項目（Eventsの絞り込みキーと一致させる＝クリックで絞込可能にするため）
GROUPBY_FIELDS = ["source_ip", "actor_user", "device_name", "url_domain", "host_name", "source_country",
                  "source_as_org"]

# しきい値（必要なら調整）
WEB_SCAN_MIN = 10      # 同一IPからの 4xx 失敗リクエスト数
AUTH_FAIL_MIN = 10     # 同一ユーザー/IPの認証失敗数
SENSITIVE_MIN = 3      # 同一IPからの危険パスアクセス数（単発ノイズを除く）
MAX_HITS_PER_RULE = 50 # 1ルールあたりの表示上限（画面が埋もれないように）
HOME_COUNTRY = "JP"    # 「海外」判定の基準国（ISOコード）。将来設定化も可能。
SILENCE_MIN_EVENTS = 5 # ログ未達判定の対象にする最小実績件数（一度きりのテスト等のノイズを除外）
DEFAULT_SILENCE_HOURS = 24


def get_silence_hours(db: Session) -> int:
    row = db.get(Setting, "silence_hours")
    try:
        return int(row.value) if row and row.value else DEFAULT_SILENCE_HOURS
    except (TypeError, ValueError):
        return DEFAULT_SILENCE_HOURS


def set_silence_hours(db: Session, hours: int) -> None:
    row = db.get(Setting, "silence_hours")
    if not row:
        row = Setting(key="silence_hours")
        db.add(row)
    row.value = str(hours)
    db.commit()

# 危険パス（攻撃でよく狙われる）。url_path にこれらを含むアクセスは1回でも要注意。
# 有名CMS/フレームワークの管理画面・設定ファイル探索パターンを含む（WordPress/Movable Type/
# Joomla/Drupal/TYPO3/EC-CUBE 等）。frontend/src/advice.ts の SENSITIVE と同期させること。
SENSITIVE_PATHS = [
    # WordPress
    "wp-login", "xmlrpc.php", "wp-config", "/wp-admin/", "/wp-content/plugins/",
    "/wp-content/uploads/", "/wp-json/wp/v2/users",
    # Movable Type
    "mt-static/", "mt-config.cgi", "/mt.cgi", "mt-search.cgi", "mt-load.cgi", "mt-comments.cgi",
    # Joomla
    "/administrator/", "/components/com_", "configuration.php~",
    # Drupal
    "/user/register", "/core/CHANGELOG.txt", "/sites/default/settings.php",
    # TYPO3
    "/typo3/", "/typo3conf/",
    # EC-CUBE（国内ECサイトで多用）
    "/html/admin/", "/data/downloads/",
    # phpMyAdmin 系
    "/phpmyadmin", "/phpMyAdmin", "/pma/", "/myadmin/", "/dbadmin/",
    # 汎用の機密ファイル・設定ファイル
    "/.env", "/.git", "/.aws", "/.ssh", "/config.php", "/vendor/", "/.well-known/",
    "/.htpasswd", "/.docker/", "web.config",
    # フレームワークのデバッグ/管理系エンドポイント
    "/actuator", "/telescope", "/_profiler", "/_ignition",
    # Webシェル・コマンド実行の痕跡
    "eval-stdin", "/shell", "wso.php", "c99.php", "r57.php", "/cmd.php",
]

# ルール定義（画面の「監視ルール一覧」用）
RULE_DEFS = [
    {"id": "ioc_match", "name": "脅威情報(IOC)一致", "severity": "critical",
     "description": "既知の不正IP/ドメインに一致する通信。",
     "recommendation": "脅威情報に登録済み。該当IP/ドメインを即時遮断し、関連イベントを調査。"},
    {"id": "web_scan", "name": "Webスキャン/探索の疑い", "severity": "high",
     "description": "同一送信元からの 4xx(404等) 失敗リクエストが多発。",
     "recommendation": "該当IPをWAF/FWで遮断。/wp-* 等の不要パスを塞ぎ、レート制限を導入。"},
    {"id": "sensitive_path", "name": "危険パスへのアクセス", "severity": "high",
     "description": "WordPress/Movable Type/Joomla/Drupal/TYPO3/EC-CUBE等の管理画面・.env/.git/phpMyAdmin等、攻撃で狙われるパスへのアクセス。",
     "recommendation": "該当IPを遮断。該当パスを公開停止/認証保護。CMS・プラグインを最新化。"},
    {"id": "auth_bruteforce_user", "name": "認証総当たり（ユーザー単位）", "severity": "high",
     "description": "同一ユーザーへの認証失敗が多発。",
     "recommendation": "アカウントロック/パスワード強化/MFA。攻撃継続なら一時無効化。"},
    {"id": "auth_bruteforce_ip", "name": "認証総当たり（送信元IP単位）", "severity": "high",
     "description": "同一送信元IPからの認証失敗が多発。",
     "recommendation": "該当IPを遮断（Fail2ban等の自動遮断）。公開ポート/VPN露出を見直す。"},
    {"id": "root_ssh_attempt", "name": "rootへのSSH試行", "severity": "high",
     "description": "外部からrootユーザーへのSSH認証試行。root直接ログインは通常禁止すべき。",
     "recommendation": "sshd_config で PermitRootLogin no を設定。PasswordAuthentication no（公開鍵のみ）。Fail2banで自動遮断。必要なら SSH ポートを非標準ポートへ変更 or IP制限。"},
    {"id": "ssh_invalid_user", "name": "SSH不正ユーザー試行", "severity": "warning",
     "description": "存在しないユーザーや権限外ユーザーへのSSH認証失敗。ブルートフォース・辞書攻撃の兆候。",
     "recommendation": "Fail2banで自動遮断。AllowUsers/DenyUsersで許可ユーザーを限定。パスワード認証を無効化し公開鍵のみに。"},
    {"id": "foreign_access", "name": "海外からのアクセス", "severity": "warning",
     "description": "日本国外のIPからのアクセス（GeoIP設定時）。",
     "recommendation": "業務上想定外なら該当国/IPを遮断検討。"},
    {"id": "source_silent", "name": "ログ未達（送信元の停止疑い）", "severity": "warning",
     "description": "これまで継続的に送信していたログソースから、一定時間データが届いていない。",
     "recommendation": "対象機器/エージェントの死活・ネットワーク疎通・NXLog等の転送設定を確認。"},
]


def _rec(rule_id: str) -> tuple[str, str, str]:
    d = next(r for r in RULE_DEFS if r["id"] == rule_id)
    return d["name"], d["severity"], d["recommendation"]


def evaluate(db: Session, conds: list | None = None) -> list[dict[str, Any]]:
    """conds: 現在の画面絞り込み（source_name=logw 等）の条件リスト。指定時はその範囲だけ評価。"""
    w = conds or []
    hits: list[dict[str, Any]] = []

    def add(rule_id, title, evidence, count, pivot=None):
        name, sev, rec = _rec(rule_id)
        hits.append({"rule_id": rule_id, "rule_name": name, "severity": sev,
                     "title": title, "evidence": evidence, "count": count,
                     "recommendation": rec, "pivot": pivot})

    # --- IOC 一致（最優先）: 取り込み済みエンティティ × IOC ---
    ioc_rows = db.execute(
        select(EventEntity.entity_value, IOC.indicator_type, func.max(IOC.source),
               func.count(func.distinct(EventEntity.event_id)))
        .join(IOC, (IOC.value == EventEntity.entity_value) & (IOC.indicator_type == EventEntity.entity_type))
        .join(Event, Event.id == EventEntity.event_id)
        .join(N, N.event_id == EventEntity.event_id)
        .where(*w)
        .group_by(EventEntity.entity_value, IOC.indicator_type)
        .order_by(func.count(func.distinct(EventEntity.event_id)).desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for value, itype, src, cnt in ioc_rows:
        field = "source_ip" if itype == "ip" else "url_domain"
        add("ioc_match", f"IOC一致: {value}",
            f"脅威情報({src or '不明'})登録の{itype} / 関連イベント {cnt} 件", cnt,
            pivot={"field": field, "value": value})

    # --- Webスキャン: 同一IPの 4xx 失敗多発 ---
    rows = db.execute(
        select(N.source_ip, func.count())
        .select_from(Event).join(N, N.event_id == Event.id)
        .where(N.event_category == "web", N.event_result == "failure", N.source_ip.isnot(None), *w)
        .group_by(N.source_ip).having(func.count() >= WEB_SCAN_MIN)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for ip, cnt in rows:
        add("web_scan", f"Webスキャンの疑い: {ip}", f"4xx失敗リクエスト {cnt} 件", cnt,
            pivot={"field": "source_ip", "value": ip})

    # --- 危険パスへのアクセス（webshell/.env/wp-login 等）---
    rows = db.execute(
        select(N.source_ip, func.count())
        .select_from(Event).join(N, N.event_id == Event.id)
        .where(N.source_ip.isnot(None),
               or_(*[N.url_path.ilike(f"%{p}%") for p in SENSITIVE_PATHS]), *w)
        .group_by(N.source_ip).having(func.count() >= SENSITIVE_MIN)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for ip, cnt in rows:
        add("sensitive_path", f"危険パスへのアクセス: {ip}", f"危険パスへのアクセス {cnt} 件", cnt,
            pivot={"field": "source_ip", "value": ip})

    # --- 認証総当たり（ユーザー単位）---
    rows = db.execute(
        select(N.actor_user, func.count())
        .select_from(Event).join(N, N.event_id == Event.id)
        .where(N.event_category.in_(["authentication", "security"]),
               N.event_result == "failure", N.actor_user.isnot(None), *w)
        .group_by(N.actor_user).having(func.count() >= AUTH_FAIL_MIN)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for user, cnt in rows:
        add("auth_bruteforce_user", f"認証総当たりの疑い（ユーザー）: {user}",
            f"認証失敗 {cnt} 件", cnt, pivot={"field": "actor_user", "value": user})

    # --- 認証総当たり（送信元IP単位）---
    rows = db.execute(
        select(N.source_ip, func.count())
        .select_from(Event).join(N, N.event_id == Event.id)
        .where(N.event_category.in_(["authentication", "security"]),
               N.event_result == "failure", N.source_ip.isnot(None), *w)
        .group_by(N.source_ip).having(func.count() >= AUTH_FAIL_MIN)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for ip, cnt in rows:
        add("auth_bruteforce_ip", f"認証総当たりの疑い（IP）: {ip}",
            f"認証失敗 {cnt} 件", cnt, pivot={"field": "source_ip", "value": ip})

    # --- root SSH 試行（1件でも要注意。閾値なし）---
    rows = db.execute(
        select(N.source_ip, func.count())
        .select_from(Event).join(N, N.event_id == Event.id)
        .where(N.event_category == "authentication",
               N.event_result == "failure",
               N.actor_user == "root",
               N.source_ip.isnot(None), *w)
        .group_by(N.source_ip)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for ip, cnt in rows:
        add("root_ssh_attempt", f"rootへのSSH試行: {ip}",
            f"root直接ログイン試行 {cnt} 件（PermitRootLogin no を確認）", cnt,
            pivot={"field": "source_ip", "value": ip})

    # --- SSH 不正ユーザー試行（root以外。閾値なし）---
    rows = db.execute(
        select(N.source_ip, N.actor_user, func.count())
        .select_from(Event).join(N, N.event_id == Event.id)
        .where(N.event_category == "authentication",
               N.event_result == "failure",
               N.service_name == "sshd",
               N.actor_user.isnot(None),
               N.actor_user != "root",
               N.source_ip.isnot(None), *w)
        .group_by(N.source_ip, N.actor_user)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for ip, user, cnt in rows:
        add("ssh_invalid_user", f"SSH不正ユーザー試行: {user}@{ip}",
            f"存在しないまたは不正ユーザー「{user}」への SSH 試行 {cnt} 件", cnt,
            pivot={"field": "source_ip", "value": ip})

    # --- 海外アクセス: GeoIP mmdb 設置時のみ評価（未設置なら source_country は常に null で0件）---
    rows = db.execute(
        select(N.source_country, N.source_ip, func.count())
        .select_from(Event).join(N, N.event_id == Event.id)
        .where(N.source_country.isnot(None), N.source_country != HOME_COUNTRY, N.source_ip.isnot(None), *w)
        .group_by(N.source_country, N.source_ip)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for country, ip, cnt in rows:
        add("foreign_access", f"海外からのアクセス（{country}）: {ip}",
            f"{country} からのアクセス {cnt} 件", cnt, pivot={"field": "source_ip", "value": ip})

    # --- ログ未達（送信元が止まった）: 過去に実績のあるソースが一定時間データを送ってこない ---
    silence_hours = get_silence_hours(db)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=silence_hours)
    rows = db.execute(
        select(Event.source, Event.source_type, func.max(Event.received_at), func.count())
        .select_from(Event).join(N, N.event_id == Event.id)
        .where(Event.source.isnot(None), *w)
        .group_by(Event.source, Event.source_type)
        .having(func.count() >= SILENCE_MIN_EVENTS)
    ).all()
    for source, stype, last, cnt in rows:
        if not last:
            continue
        last_aware = last if last.tzinfo else last.replace(tzinfo=timezone.utc)
        if last_aware < cutoff:
            hrs = int((datetime.now(timezone.utc) - last_aware).total_seconds() // 3600)
            add("source_silent", f"送信元が停止中の疑い: {source}",
                f"最終受信から約 {hrs} 時間経過（種別={stype or '-'} / これまでの実績 {cnt} 件）", 1,
                pivot={"field": "source", "value": source})

    # --- カスタムルール（ユーザー定義。DB保存分を動的評価）---
    hits.extend(_evaluate_custom(db, w))

    # 重大度順に並べる
    order = {"critical": 0, "high": 1, "warning": 2, "info": 3}
    hits.sort(key=lambda h: (order.get(h["severity"], 9), -h["count"]))
    return hits


def _evaluate_custom(db: Session, w: list) -> list[dict[str, Any]]:
    """ユーザー定義ルール（CustomRule）を動的評価。任意コード実行はせず、
    ホワイトリスト化した正規化フィールドへの contains/equals ＋ 件数しきい値のみ扱う。"""
    hits: list[dict[str, Any]] = []
    rows = db.execute(select(CustomRule).where(CustomRule.enabled.is_(True))).scalars().all()
    for r in rows:
        col = FIELD_MAP.get(r.match_field)
        if col is None:
            continue
        match_clause = col.ilike(f"%{r.match_value}%") if r.match_op == "contains" else col == r.match_value
        group_col = FIELD_MAP.get(r.group_by) if r.group_by else None
        rec = r.recommendation or "内容を確認し、必要な対応を検討してください。"
        evidence_base = f'{r.match_field} が "{r.match_value}" に{"部分一致" if r.match_op == "contains" else "一致"}'
        if group_col is not None:
            rows2 = db.execute(
                select(group_col, func.count())
                .select_from(Event).join(N, N.event_id == Event.id)
                .where(group_col.isnot(None), match_clause, *w)
                .group_by(group_col).having(func.count() >= r.min_count)
                .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
            ).all()
            for val, cnt in rows2:
                hits.append({
                    "rule_id": f"custom_{r.id}", "rule_name": r.name, "severity": r.severity,
                    "title": f"{r.name}: {val}", "evidence": f"{evidence_base} / {cnt} 件",
                    "count": cnt, "recommendation": rec,
                    "pivot": {"field": r.group_by, "value": str(val)} if r.group_by in GROUPBY_FIELDS else None,
                })
        else:
            cnt = db.scalar(
                select(func.count()).select_from(Event).join(N, N.event_id == Event.id)
                .where(match_clause, *w)
            ) or 0
            if cnt >= r.min_count:
                hits.append({
                    "rule_id": f"custom_{r.id}", "rule_name": r.name, "severity": r.severity,
                    "title": r.name, "evidence": f"{evidence_base} / {cnt} 件", "count": cnt,
                    "recommendation": rec, "pivot": None,
                })
    return hits
