"""ルールベース注意喚起（PROJECT.md §15）。蓄積データを走査し、攻撃の兆候＋対策を提示。
AI不要・SQL集計のみ。各ヒットに recommendation（対策）を付ける。IOC一致は最優先。"""
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .models import CustomRule, Event, EventEntity, IOC, Setting

# カスタムルールが対象にできる正規化フィールド（安全なホワイトリスト。任意コード実行はしない）。
FIELD_MAP: dict[str, Any] = {
    "message": Event.message, "url_path": Event.url_path, "url_domain": Event.url_domain,
    "actor_user": Event.actor_user, "source_ip": Event.source_ip, "device_name": Event.device_name,
    "event_category": Event.event_category, "event_action": Event.event_action, "event_result": Event.event_result,
    "http_status_code": Event.http_status_code, "service_name": Event.service_name,
    "source_country": Event.source_country, "host_name": Event.host_name,
    "source_asn": Event.source_asn, "source_as_org": Event.source_as_org,
}
# 集計軸（group_by）に使える項目（Eventsの絞り込みキーと一致させる＝クリックで絞込可能にするため）
GROUPBY_FIELDS = ["source_ip", "actor_user", "device_name", "url_domain", "host_name", "source_country",
                  "source_as_org"]

# サーバがエラー応答を返したことを示す本文パターン。
# LiteSpeed/OpenLiteSpeed は自前でエラー応答を返す際に "oops! 500" のように書く。
# web_error にはステータスコードのKEYが無く(本番実測: Message以外のフィールドを持たない)、
# 本文からしか5xxを判別できないためこの形にしている。
# 判定材料の Message は Taxonomy KEY なので、Taxonomy外KEYへの依存にはならない（v12 §15）。
RE_HTTP_5XX = r"oops!\s*5[0-9]{2}"

# しきい値（必要なら調整）
WEB_SCAN_MIN = 10        # 同一IPからの 4xx 失敗リクエスト数
AUTH_FAIL_MIN = 10       # 同一ユーザー/IPの認証失敗数
# 認証総当たり（IP単位）で数える対象。sshd(linux) と auditd(audit) が同一試行を
# 二重に送ってくるため、片方に寄せる（二重カウント排除）。
AUTH_BRUTEFORCE_IP_SOURCE_TYPE = "linux"
SENSITIVE_MIN = 3        # 同一IPからの危険パスアクセス数（単発ノイズを除く）
MAX_HITS_PER_RULE = 50   # 1ルールあたりの表示上限（画面が埋もれないように）
HOME_COUNTRY = "JP"      # 「海外」判定の基準国（ISOコード）。将来設定化も可能。
SILENCE_MIN_EVENTS = 5   # ログ未達判定の対象にする最小実績件数（一度きりのテスト等のノイズを除外）
DEFAULT_SILENCE_HOURS = 24
WEBSHELL_PROBE_MIN = 5   # 同一IPが異なるファイル名で数字名.phpを試行した件数（同一パスの再試行は含めない）
# 同一ログソースからのサーバエラー(5xx)応答の件数。本番実測(2026-08-13, 27日分)では
# 1時間あたりの中央値3件・p90=31件、1日あたりの中央値126件だったため、
# 短時間の単発バーストでは鳴らず、継続した5xxは拾える値として50を置いた。
WEB_5XX_MIN = 50


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

# 数字のみのファイル名(1〜4桁).php への探索（過去に設置されたWebshellを当てずっぽうで探る典型パターン。
# 例: /1.php /222.php /8.php。ファイル名が毎回変わるためSENSITIVE_PATHSの固定文字列一致では拾えない）
WEBSHELL_PROBE_RE = r"(^|/)\d{1,4}\.php$"

# 攻撃ペイロードのシグネチャ（URLのパス・クエリ双方に対して部分一致で検査）。
# frontend/src/advice.ts の PAYLOAD_SIGNATURES と同期させること。今後も追加していく前提の配列。
# 注意: "..%2f" "%2e%2e" "union%20select" "or%201=1" は文字列中の % をILIKEワイルドカードとして
# 意図的にエスケープしていない（例: "%2e%2e" は隣接していなくても "2e" が2回出現すればヒットする）。
# バグではなく、閾値なし・見逃さない設計のpayload_injectionにおいてこの広めの一致が有効に働くことを
# 本番データで確認済み（docs/detection-rules.md 2節参照）。厳密な隣接一致に直す場合は
# .ilike(pattern, escape="\\") で % / _ をエスケープすること。
PAYLOAD_SIGNATURES = [
    # パストラバーサル
    "../", "..%2f", "%2e%2e",
    # SQLインジェクション（union select / or 1=1 はURLエンコード(%20)・フォームエンコード(+)後の
    # 亜種も追加。生のスペースはログの request 文字列上ではほぼ出現しないため）
    "union select", "union%20select", "union+select",
    "sleep(",
    "or 1=1", "or%201=1", "or+1=1",
    ";--",
    # XSS
    "<script", "onerror=", "javascript:",
    # PHPラッパー悪用
    "php://input", "php://filter", "data://text",
    # コマンドインジェクション
    "; cat ", "| id", "`id`",
    # Log4Shell
    "${jndi:",
]

# ルール定義（画面の「監視ルール一覧」用）。
# category: ルールの性格を表す文字列（bool等の決め打ちにせず、将来値が増える前提）。
#   "security"   = 攻撃・不正検知系（悪意ある第三者の挙動を疑うもの）
#   "operations" = 運用監視系（自システムの正常/異常な稼働状態を見るもの。将来SIEM化で増える想定）
RULE_DEFS = [
    {"id": "ioc_match", "name": "脅威情報(IOC)一致", "severity": "critical", "category": "security",
     "description": "既知の不正IP/ドメインに一致する通信。",
     "recommendation": "脅威情報に登録済み。該当IP/ドメインを即時遮断し、関連イベントを調査。"},
    {"id": "payload_injection", "name": "攻撃ペイロード検知", "severity": "critical", "category": "security",
     "description": "URL(パス/クエリ)にパストラバーサル・SQLi・XSS・PHPラッパー・コマンドインジェクション・Log4Shell等の既知の攻撃シグネチャを含む。",
     "recommendation": "該当IPを即時遮断し、対象アプリケーションに脆弱性がないか確認。WAFでの該当シグネチャ遮断を検討。"},
    {"id": "web_scan", "name": "Webスキャン/探索の疑い", "severity": "high", "category": "security",
     "description": "同一送信元からの 4xx(404等) 失敗リクエストが多発。",
     "recommendation": "該当IPをWAF/FWで遮断。/wp-* 等の不要パスを塞ぎ、レート制限を導入。"},
    {"id": "sensitive_path", "name": "危険パスへのアクセス", "severity": "high", "category": "security",
     "description": "WordPress/Movable Type/Joomla/Drupal/TYPO3/EC-CUBE等の管理画面・.env/.git/phpMyAdmin等、攻撃で狙われるパスへのアクセス。",
     "recommendation": "該当IPを遮断。該当パスを公開停止/認証保護。CMS・プラグインを最新化。"},
    {"id": "webshell_probe", "name": "Webshell探索の疑い", "severity": "high", "category": "security",
     "description": "同一送信元が、数字のみのファイル名(例: /1.php)等ランダムな名前の.phpへ異なるパスで404を繰り返す。過去に設置されたWebshellを当てずっぽうで探る典型パターン。",
     "recommendation": "該当IPを遮断。心当たりのない.phpファイルが公開領域に無いか確認し、WAF/レート制限を導入。"},
    {"id": "auth_bruteforce_user", "name": "認証総当たり（ユーザー単位）", "severity": "high", "category": "security",
     "description": "同一ユーザーへの認証失敗が多発。",
     "recommendation": "アカウントロック/パスワード強化/MFA。攻撃継続なら一時無効化。"},
    {"id": "auth_bruteforce_ip", "name": "認証総当たり（送信元IP単位）", "severity": "high", "category": "security",
     "description": "同一送信元IPからの認証失敗が多発。",
     "recommendation": "該当IPを遮断（Fail2ban等の自動遮断）。公開ポート/VPN露出を見直す。"},
    {"id": "root_ssh_attempt", "name": "rootへのSSH試行", "severity": "high", "category": "security",
     "description": "外部からrootユーザーへのSSH認証試行。root直接ログインは通常禁止すべき。",
     "recommendation": "sshd_config で PermitRootLogin no を設定。PasswordAuthentication no（公開鍵のみ）。Fail2banで自動遮断。必要なら SSH ポートを非標準ポートへ変更 or IP制限。"},
    {"id": "ssh_invalid_user", "name": "SSH不正ユーザー試行", "severity": "warning", "category": "security",
     "description": "存在しないユーザーや権限外ユーザーへのSSH認証失敗。ブルートフォース・辞書攻撃の兆候。",
     "recommendation": "Fail2banで自動遮断。AllowUsers/DenyUsersで許可ユーザーを限定。パスワード認証を無効化し公開鍵のみに。"},
    {"id": "foreign_access", "name": "海外からのアクセス", "severity": "warning", "category": "security",
     "description": "日本国外のIPからのアクセス（GeoIP設定時）。",
     "recommendation": "業務上想定外なら該当国/IPを遮断検討。"},
    {"id": "source_silent", "name": "ログ未達（送信元の停止疑い）", "severity": "warning", "category": "operations",
     "description": "これまで継続的に送信していたログソースから、一定時間データが届いていない。",
     "recommendation": "対象機器/エージェントの死活・ネットワーク疎通・NXLog等の転送設定を確認。"},
    {"id": "web_5xx_burst", "name": "サーバエラー(5xx)の多発", "severity": "warning", "category": "operations",
     "description": "同一のログソースで、サーバ側エラー(5xx)の応答が多発している。攻撃ではなくサイト側の不具合・過負荷・設定ミスの疑い。",
     "recommendation": "対象サイトのエラーログ本文を確認し、5xxの直接原因（PHPの致命的エラー・DB接続失敗・タイムアウト・メモリ不足等）を特定する。"
                       "直前のデプロイ・プラグイン更新・設定変更が無いか確認。"
                       "特定URLに集中していれば該当ページ、全体に及んでいればWebサーバ/DB/リソース側を疑う。"},
    {"id": "build_failure", "name": "ビルド失敗", "severity": "warning", "category": "operations",
     "description": "Astroサイトのビルド（npm run build）が失敗した。",
     "recommendation": "手動で `npm run build` を再実行し再現するか確認。error内容と直近のコンテンツ変更・依存パッケージ更新を確認。"
                       "trigger が directus_flow/directus_activity の場合は直前のDirectus側の記事編集内容も確認。"
                       "連続失敗が続く場合はビルド環境（Node.jsバージョン・依存関係）を疑う。"},
]


def _rec(rule_id: str) -> tuple[str, str, str, str]:
    d = next(r for r in RULE_DEFS if r["id"] == rule_id)
    return d["name"], d["severity"], d["recommendation"], d["category"]


def evaluate(db: Session, conds: list | None = None) -> list[dict[str, Any]]:
    """conds: 現在の画面絞り込み（source_name=logw 等）の条件リスト。指定時はその範囲だけ評価。"""
    w = conds or []
    hits: list[dict[str, Any]] = []

    def add(rule_id, title, evidence, count, pivot=None):
        name, sev, rec, cat = _rec(rule_id)
        hits.append({"rule_id": rule_id, "rule_name": name, "severity": sev, "category": cat,
                     "title": title, "evidence": evidence, "count": count,
                     "recommendation": rec, "pivot": pivot})

    # --- IOC 一致（最優先）: 取り込み済みエンティティ × IOC ---
    ioc_rows = db.execute(
        select(EventEntity.entity_value, IOC.indicator_type, func.max(IOC.source),
               func.count(func.distinct(EventEntity.event_id)))
        .join(IOC, (IOC.value == EventEntity.entity_value) & (IOC.indicator_type == EventEntity.entity_type))
        .join(Event, Event.id == EventEntity.event_id)
        .where(*w)
        .group_by(EventEntity.entity_value, IOC.indicator_type)
        .order_by(func.count(func.distinct(EventEntity.event_id)).desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for value, itype, src, cnt in ioc_rows:
        field = "source_ip" if itype == "ip" else "url_domain"
        add("ioc_match", f"IOC一致: {value}",
            f"脅威情報({src or '不明'})登録の{itype} / 関連イベント {cnt} 件", cnt,
            pivot={"field": field, "value": value})

    # --- 攻撃ペイロード検知: URL(パス/クエリ)に既知の攻撃シグネチャ（閾値なし）---
    rows = db.execute(
        select(Event.source_ip, func.count())
        .select_from(Event)
        .where(Event.source_ip.isnot(None),
               or_(*[Event.url_path.ilike(f"%{p}%") for p in PAYLOAD_SIGNATURES],
                   *[Event.url_query.ilike(f"%{p}%") for p in PAYLOAD_SIGNATURES]), *w)
        .group_by(Event.source_ip)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for ip, cnt in rows:
        add("payload_injection", f"攻撃ペイロード検知: {ip}",
            f"パストラバーサル/SQLi/XSS等のシグネチャを含むリクエスト {cnt} 件", cnt,
            pivot={"field": "source_ip", "value": ip})

    # --- Webスキャン: 同一IPの 4xx 失敗多発 ---
    rows = db.execute(
        select(Event.source_ip, func.count())
        .select_from(Event)
        .where(Event.event_category == "web", Event.event_result == "failure", Event.source_ip.isnot(None), *w)
        .group_by(Event.source_ip).having(func.count() >= WEB_SCAN_MIN)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for ip, cnt in rows:
        add("web_scan", f"Webスキャンの疑い: {ip}", f"4xx失敗リクエスト {cnt} 件", cnt,
            pivot={"field": "source_ip", "value": ip})

    # --- 危険パスへのアクセス（webshell/.env/wp-login 等）---
    rows = db.execute(
        select(Event.source_ip, func.count())
        .select_from(Event)
        .where(Event.source_ip.isnot(None),
               or_(*[Event.url_path.ilike(f"%{p}%") for p in SENSITIVE_PATHS]), *w)
        .group_by(Event.source_ip).having(func.count() >= SENSITIVE_MIN)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for ip, cnt in rows:
        add("sensitive_path", f"危険パスへのアクセス: {ip}", f"危険パスへのアクセス {cnt} 件", cnt,
            pivot={"field": "source_ip", "value": ip})

    # --- Webshell探索の疑い: 同一IPが異なるファイル名で数字名.phpへ404を連発 ---
    rows = db.execute(
        select(Event.source_ip, func.count(func.distinct(Event.url_path)))
        .select_from(Event)
        .where(Event.event_category == "web", Event.http_status_code == "404",
               Event.url_path.op("~*")(WEBSHELL_PROBE_RE),
               Event.source_ip.isnot(None), *w)
        .group_by(Event.source_ip).having(func.count(func.distinct(Event.url_path)) >= WEBSHELL_PROBE_MIN)
        .order_by(func.count(func.distinct(Event.url_path)).desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for ip, cnt in rows:
        add("webshell_probe", f"Webshell探索の疑い: {ip}",
            f"異なるファイル名の数字名.phpへの探索アクセス {cnt} 件（例: /1.php等）", cnt,
            pivot={"field": "source_ip", "value": ip})

    # --- 認証総当たり（ユーザー単位）---
    rows = db.execute(
        select(Event.actor_user, func.count())
        .select_from(Event)
        .where(Event.event_category.in_(["authentication", "security"]),
               Event.event_result == "failure", Event.actor_user.isnot(None), *w)
        .group_by(Event.actor_user).having(func.count() >= AUTH_FAIL_MIN)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for user, cnt in rows:
        add("auth_bruteforce_user", f"認証総当たりの疑い（ユーザー）: {user}",
            f"認証失敗 {cnt} 件", cnt, pivot={"field": "actor_user", "value": user})

    # --- 認証総当たり（送信元IP単位）---
    # 同一のSSH失敗試行が sshd(linux) と auditd(audit) の両方から届くため、絞り込まないと
    # 件数が実際の試行回数の約2倍になる（本番実測: 163.7.4.169 = 合計1,679 / audit 884 / linux 795）。
    # audit 側は audit_type が69%NULLで取りこぼしがある（未解決issue）ため、
    # 母数として安定している linux(sshd) 側のみを数える。詳細は docs/detection-rules.md §6。
    rows = db.execute(
        select(Event.source_ip, func.count())
        .select_from(Event)
        .where(Event.source_type == AUTH_BRUTEFORCE_IP_SOURCE_TYPE,
               Event.event_category.in_(["authentication", "security"]),
               Event.event_result == "failure", Event.source_ip.isnot(None), *w)
        .group_by(Event.source_ip).having(func.count() >= AUTH_FAIL_MIN)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for ip, cnt in rows:
        add("auth_bruteforce_ip", f"認証総当たりの疑い（IP）: {ip}",
            f"認証失敗 {cnt} 件", cnt, pivot={"field": "source_ip", "value": ip})

    # --- root SSH 試行（1件でも要注意。閾値なし）---
    rows = db.execute(
        select(Event.source_ip, func.count())
        .select_from(Event)
        .where(Event.event_category == "authentication",
               Event.event_result == "failure",
               Event.actor_user == "root",
               Event.source_ip.isnot(None), *w)
        .group_by(Event.source_ip)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for ip, cnt in rows:
        add("root_ssh_attempt", f"rootへのSSH試行: {ip}",
            f"root直接ログイン試行 {cnt} 件（PermitRootLogin no を確認）", cnt,
            pivot={"field": "source_ip", "value": ip})

    # --- SSH 不正ユーザー試行（root以外。閾値なし）---
    rows = db.execute(
        select(Event.source_ip, Event.actor_user, func.count())
        .select_from(Event)
        .where(Event.event_category == "authentication",
               Event.event_result == "failure",
               Event.service_name == "sshd",
               Event.actor_user.isnot(None),
               Event.actor_user != "root",
               Event.source_ip.isnot(None), *w)
        .group_by(Event.source_ip, Event.actor_user)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for ip, user, cnt in rows:
        add("ssh_invalid_user", f"SSH不正ユーザー試行: {user}@{ip}",
            f"存在しないまたは不正ユーザー「{user}」への SSH 試行 {cnt} 件", cnt,
            pivot={"field": "source_ip", "value": ip})

    # --- 海外アクセス: GeoIP mmdb 設置時のみ評価（未設置なら source_country は常に null で0件）---
    rows = db.execute(
        select(Event.source_country, Event.source_ip, func.count())
        .select_from(Event)
        .where(Event.source_country.isnot(None), Event.source_country != HOME_COUNTRY, Event.source_ip.isnot(None), *w)
        .group_by(Event.source_country, Event.source_ip)
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
        .select_from(Event)
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

    # --- ビルド失敗（Astro, source_type=astro_build）: 運用監視系。1件でも要対応。閾値なし ---
    rows = db.execute(
        select(Event.source, func.count())
        .select_from(Event)
        .where(Event.source_type == "astro_build", Event.event_result == "failure",
               Event.source.isnot(None), *w)
        .group_by(Event.source)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for source, cnt in rows:
        add("build_failure", f"ビルド失敗: {source}", f"ビルド失敗 {cnt} 件", cnt,
            pivot={"field": "source", "value": source})

    # --- サーバエラー(5xx)多発: 運用監視系。ログソース単位で件数がしきい値を超えたら通知 ---
    # 期間は呼び出し側の絞り込み(w)に従う（画面で未指定なら直近24時間）。
    rows = db.execute(
        select(Event.source, func.count())
        .select_from(Event)
        .where(Event.message.op("~*")(RE_HTTP_5XX), Event.source.isnot(None), *w)
        .group_by(Event.source)
        .having(func.count() >= WEB_5XX_MIN)
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for source, cnt in rows:
        add("web_5xx_burst", f"サーバエラー(5xx)の多発: {source}",
            f"5xx応答 {cnt} 件", cnt,
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
                .select_from(Event)
                .where(group_col.isnot(None), match_clause, *w)
                .group_by(group_col).having(func.count() >= r.min_count)
                .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
            ).all()
            for val, cnt in rows2:
                hits.append({
                    "rule_id": f"custom_{r.id}", "rule_name": r.name, "severity": r.severity, "category": "custom",
                    "title": f"{r.name}: {val}", "evidence": f"{evidence_base} / {cnt} 件",
                    "count": cnt, "recommendation": rec,
                    "pivot": {"field": r.group_by, "value": str(val)} if r.group_by in GROUPBY_FIELDS else None,
                })
        else:
            cnt = db.scalar(
                select(func.count()).select_from(Event)
                .where(match_clause, *w)
            ) or 0
            if cnt >= r.min_count:
                hits.append({
                    "rule_id": f"custom_{r.id}", "rule_name": r.name, "severity": r.severity, "category": "custom",
                    "title": r.name, "evidence": f"{evidence_base} / {cnt} 件", "count": cnt,
                    "recommendation": rec, "pivot": None,
                })
    return hits
