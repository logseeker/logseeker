"""ルールベース注意喚起（PROJECT.md §15）。蓄積データを走査し、攻撃の兆候＋対策を提示。
AI不要・SQL集計のみ。各ヒットに recommendation（対策）を付ける。IOC一致は最優先。"""
import ipaddress
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
# 同一ログソースからのサーバエラー(5xx)応答の件数。
# 当初は50を置いたが、kantsuri は日次中央値126件（しきい値の2.5倍）で
# ほぼ毎日発火し、_burst（突発的な急増）ではなく慢性状態の常時表示になっていた。
# 「いつもと違う異常」だけを拾うため、日次p90相当（2026-08-13実測 kantsuri 255）の
# 256へ引き上げた。本番実測(2026-08-16, 30日)では kantsuri の発火日数が
# 28/31日 → 1/31日 になる。
WEB_5XX_MIN = 256

# --- Windowsセキュリティイベント（source_type=windows_event。NXLog im_msvistalog）---
# 条件に使う payload のKEYはすべて Taxonomy KEY（taxonomy.md v1.13 で追加）。照合は大文字小文字を無視する。
WIN_SOURCE_TYPE = "windows_event"
WIN_SPRAY_MIN_USERS = 5   # 同一IPからのログオン失敗(4625)で狙われた異なるアカウント数（パスワードスプレー）
# 評価対象の EventID（event_action に EventID が入る。normalize.py の windows_event 分岐）
WIN_EVENT_IDS = ["4624", "1102", "104", "4769", "4728", "4732", "4756", "4720",
                 "7045", "4697", "4698", "4719", "4688"]
# 特権グループ（4728/4732/4756 の対象グループ名。日本語版Windowsでも組み込みグループ名は英語のまま）
WIN_PRIV_GROUP_RE = (r"admins|administrators|operators|remote desktop users|remote management users|"
                     r"group policy creator owners")
# 攻撃でよく使われるコマンドライン（4688 の CommandLine / NewProcessName。PostgreSQLの ~* で評価）。
# CommandLine は監視対象で「プロセス作成イベントにコマンドラインを含める」ポリシーを有効にしないと
# 出ない（未設定だと NewProcessName だけで判定するため、ツール名以外はほぼ拾えない）。
# PostgreSQLの正規表現なので \b（単語境界）は使わないこと（PostgreSQLでは後退文字の意味になる）。
WIN_SUSPICIOUS_CMD_RE = [
    r"powershell.*\s-(e|ec|enc|encodedcommand)\s",          # エンコード済みコマンドの実行
    r"frombase64string",
    r"downloadstring|downloadfile|invoke-webrequest|invoke-expression|iex\s*\(",
    r"mimikatz|sekurlsa|lsadump|kerberos::",                 # 資格情報窃取ツール
    r"comsvcs(\.dll)?.*minidump|procdump.*lsass",            # LSASSのメモリダンプ
    r"vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|wbadmin(\.exe)?\s+delete",
    r"bcdedit(\.exe)?\s+/set",                               # 回復の無効化（ランサムウェアの典型）
    r"wevtutil(\.exe)?\s+cl\s",                              # イベントログの消去
    r"certutil(\.exe)?.*-urlcache|bitsadmin(\.exe)?.*/transfer",
    r"reg(\.exe)?\s+save\s+hklm\\(sam|system|security)",     # SAM/SYSTEMハイブの持ち出し
    r"ntdsutil",
    r"net1?(\.exe)?\s+(user|localgroup)\s.*/add",
]


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
    # --- Windows（windows_event）---
    {"id": "win_log_cleared", "name": "[Windows] 監査ログの消去", "severity": "critical", "category": "security",
     "description": "Securityログ(1102)またはSystemログ(104)が消去された。侵入後の痕跡隠しで典型的に行われる。",
     "recommendation": "消去した操作者（アカウント）と時刻を確認し、心当たりが無ければ侵害を前提に調査。"
                       "消去前後のログオン・プロセス起動を確認し、本システム側に転送済みの記録を保全する。"},
    {"id": "win_pass_the_hash", "name": "[Windows] Pass-the-Hashの疑い", "severity": "high", "category": "security",
     "description": "パスワードではなく盗んだNTLMハッシュでのログオンを示す形跡"
                    "（4624: ネットワークログオン(3)+NTLM+セッションキー長0、または LogonType 9 + seclogo）。"
                    "ドメイン非参加の環境では正規のログオンでも出ることがある。",
     "recommendation": "該当アカウントのパスワードをリセットし、送信元端末を隔離して調査。"
                       "ローカル管理者パスワードの使い回しを避ける（LAPS）。NTLMの利用制限を検討。"},
    {"id": "win_suspicious_command", "name": "[Windows] 不審なコマンド実行", "severity": "high", "category": "security",
     "description": "プロセス作成(4688)で、エンコード済みPowerShell・資格情報窃取ツール・シャドウコピー削除・"
                    "イベントログ消去など、攻撃でよく使われるコマンドを検出。"
                    "コマンドラインの記録には監視対象側の監査ポリシー設定が必要。",
     "recommendation": "実行したアカウント・親プロセスを確認し、正規の管理作業でなければ端末を隔離して調査。"
                       "シャドウコピー削除・回復の無効化はランサムウェアの直前動作のことが多いので最優先で対応。"},
    {"id": "win_rdp_external", "name": "[Windows] 外部IPからのRDPログオン成功", "severity": "high", "category": "security",
     "description": "グローバルIPからのリモートデスクトップ(4624 LogonType 10)でログオンに成功した。",
     "recommendation": "接続元と利用者に心当たりが無ければ該当アカウントを無効化。"
                       "RDPをインターネットへ直接公開せず、VPN経由・IP制限・NLA・MFAを導入。"},
    {"id": "win_logon_failure_ip", "name": "[Windows] ログオン失敗の多発（送信元IP単位）", "severity": "high", "category": "security",
     "description": "同一送信元IPからのWindowsログオン失敗(4625)が多発。",
     "recommendation": "該当IPを遮断。RDP/SMBの外部公開を見直し、アカウントロックアウトポリシーを設定。"},
    {"id": "win_password_spray", "name": "[Windows] パスワードスプレーの疑い", "severity": "high", "category": "security",
     "description": "同一送信元IPから、多数の異なるアカウントへのログオン失敗(4625)。"
                    "ロックアウトを避けて少数のパスワードを多数のアカウントに試す攻撃。",
     "recommendation": "該当IPを遮断。狙われたアカウントに弱いパスワードが無いか確認し、MFAを導入。"},
    {"id": "win_kerberoasting", "name": "[Windows] Kerberoastingの疑い", "severity": "high", "category": "security",
     "description": "RC4暗号(0x17)のKerberosサービスチケット要求(4769)。サービスアカウントのパスワードを"
                    "オフラインで解読する攻撃で使われる（ドメインコントローラーのログでのみ出る）。",
     "recommendation": "要求元のアカウント・端末を確認。サービスアカウントは25文字以上の長いパスワードかgMSAにし、"
                       "RC4を無効化してAESのみにする。"},
    {"id": "win_priv_group_add", "name": "[Windows] 特権グループへのメンバー追加", "severity": "high", "category": "security",
     "description": "Administrators・Domain Admins・Remote Desktop Users 等の特権グループにメンバーが追加された(4728/4732/4756)。",
     "recommendation": "追加した操作者と追加されたアカウントを確認し、承認された変更でなければ直ちに取り消して調査。"},
    {"id": "win_account_created", "name": "[Windows] ユーザーアカウントの作成", "severity": "warning", "category": "security",
     "description": "ユーザーアカウントが作成された(4720)。攻撃者の永続化（裏口アカウント）でも使われる。",
     "recommendation": "作成者と作成されたアカウントが承認済みの作業か確認。心当たりが無ければ無効化して調査。"},
    {"id": "win_service_installed", "name": "[Windows] サービスのインストール", "severity": "warning", "category": "security",
     "description": "新しいサービスがインストールされた(7045/4697)。PsExec等の横展開やマルウェアの永続化で使われる。",
     "recommendation": "サービス名・実行ファイルパスを確認。一時フォルダ・ユーザーフォルダ上の実行ファイルや、"
                       "cmd/powershellを直接起動するサービスは要注意。"},
    {"id": "win_scheduled_task", "name": "[Windows] タスクスケジューラへの登録", "severity": "warning", "category": "security",
     "description": "スケジュールされたタスクが作成された(4698)。マルウェアの永続化・遠隔実行で使われる。",
     "recommendation": "タスク名と実行内容を確認し、承認されていない登録であれば削除して調査。"},
    {"id": "win_audit_policy_changed", "name": "[Windows] 監査ポリシーの変更", "severity": "warning", "category": "security",
     "description": "システムの監査ポリシーが変更された(4719)。検知を逃れるために監査を無効化する攻撃がある。",
     "recommendation": "変更者と変更内容を確認し、意図しない変更であれば元に戻す。"},
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

    # --- Windowsセキュリティイベント ---
    _evaluate_windows(db, w, add)

    # --- カスタムルール（ユーザー定義。DB保存分を動的評価）---
    hits.extend(_evaluate_custom(db, w))

    # 重大度順に並べる
    order = {"critical": 0, "high": 1, "warning": 2, "info": 3}
    hits.sort(key=lambda h: (order.get(h["severity"], 9), -h["count"]))
    return hits


def _is_global_ip(ip: str | None) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global if ip else False
    except ValueError:
        return False


def _uniq(vals, n: int = 3) -> str:
    """証跡に並べる値（重複除去・先頭n件）。"""
    seen: list[str] = []
    for v in vals:
        if v and v != "-" and v not in seen:
            seen.append(v)
    if not seen:
        return "-"
    more = f" ほか{len(seen) - n}件" if len(seen) > n else ""
    return "、".join(seen[:n]) + more


def _win_evidence(rule_id: str, rs: list) -> str:
    n = len(rs)
    col = lambda k: (r[k] for r in rs)  # noqa: E731
    if rule_id == "win_pass_the_hash":
        return f"対象アカウント: {_uniq(col('target'))} / ログオン先: {_uniq(col('host'))} / {n} 件"
    if rule_id == "win_log_cleared":
        return f"操作者: {_uniq(r['subject'] or r['user'] for r in rs)} / {n} 件"
    if rule_id == "win_rdp_external":
        return f"アカウント: {_uniq(col('user'))} / ログオン先: {_uniq(col('host'))} / {n} 件"
    if rule_id == "win_kerberoasting":
        return f"要求されたサービス: {_uniq(col('service'))} / 要求元: {_uniq(col('user'))} / {n} 件"
    if rule_id == "win_priv_group_add":
        members = (r["member"] if r["member"] not in (None, "-") else r["membersid"] for r in rs)
        return (f"グループ: {_uniq(col('target'))} / 追加されたメンバー: {_uniq(members)}"
                f" / 操作者: {_uniq(col('subject'))} / {n} 件")
    if rule_id == "win_account_created":
        return f"作成されたアカウント: {_uniq(col('target'))} / 操作者: {_uniq(col('subject'))} / {n} 件"
    if rule_id == "win_service_installed":
        svcs = (f"{r['service']}（{r['imagepath']}）" if r["imagepath"] else r["service"] for r in rs)
        return f"サービス: {_uniq(svcs, 2)} / {n} 件"
    if rule_id == "win_scheduled_task":
        return f"タスク: {_uniq(col('task'))} / 登録者: {_uniq(col('subject'))} / {n} 件"
    if rule_id == "win_suspicious_command":
        cmds = ((r["cmdline"] or r["proc"] or "")[:160] for r in rs)
        return f"コマンド: {_uniq(cmds, 2)} / 実行者: {_uniq(col('subject'))} / {n} 件"
    return f"操作者: {_uniq(col('subject'))} / {n} 件"


def _evaluate_windows(db: Session, w: list, add) -> None:
    """Windowsセキュリティイベントのルール（docs/detection-rules.md §14）。

    条件に使う payload のKEYは Taxonomy KEY のみ（taxonomy.md v1.13）。照合は大文字小文字を
    区別しないため、Events画面と同じくKEYを小文字化したJSONB（lp）を1行1回だけ作って参照する
    （MATERIALIZED にしないと条件ごとに展開が走る）。展開するのは WIN_EVENT_IDS の行だけで、
    条件に合った候補行だけをPythonへ返して集約する。"""
    from .events_api import _lc_payload  # 循環importを避けるため遅延import

    win = (select(Event.event_action.label("eid"), Event.source_ip.label("ip"),
                  Event.actor_user.label("user"), Event.host_name.label("host"),
                  _lc_payload().label("lp"))
           .where(Event.source_type == WIN_SOURCE_TYPE, Event.event_action.in_(WIN_EVENT_IDS), *w)
           .cte("win").prefix_with("MATERIALIZED"))

    def v(key: str):
        # Windowsは値の末尾に空白が付くことがある（LogonProcessName = "NtLmSsp " 等）
        return func.nullif(func.btrim(win.c.lp[key].astext), "")

    eid = win.c.eid
    cmd = func.concat(func.coalesce(v("commandline"), ""), " ", func.coalesce(v("newprocessname"), ""))
    pth = (eid == "4624") & or_(
        (v("logontype") == "3") & (func.upper(v("authenticationpackagename")) == "NTLM")
        & (v("keylength") == "0") & (func.upper(func.coalesce(v("targetusername"), "")) != "ANONYMOUS LOGON"),
        (v("logontype") == "9") & (func.lower(v("logonprocessname")) == "seclogo"))
    kerberoast = ((eid == "4769") & (func.lower(v("ticketencryptiontype")) == "0x17")
                  & ~func.coalesce(v("servicename"), "").like("%$")
                  & (func.lower(func.coalesce(v("servicename"), "")) != "krbtgt"))
    cond = or_(
        pth,
        eid == "1102", (eid == "104") & (func.lower(v("channel")) == "system"),
        (eid == "4624") & (v("logontype") == "10"),
        kerberoast,
        eid.in_(["4728", "4732", "4756"]) & func.coalesce(v("targetusername"), "").op("~*")(WIN_PRIV_GROUP_RE),
        eid.in_(["4720", "7045", "4697", "4698", "4719"]),
        (eid == "4688") & or_(*[cmd.op("~*")(r) for r in WIN_SUSPICIOUS_CMD_RE]),
    )
    rows = db.execute(
        select(eid, win.c.ip, win.c.user, win.c.host,
               pth.label("is_pth"), kerberoast.label("is_kerb"),
               v("logontype").label("logontype"), v("targetusername").label("target"),
               v("subjectusername").label("subject"), v("membername").label("member"),
               v("membersid").label("membersid"), v("servicename").label("service"),
               v("imagepath").label("imagepath"), v("taskname").label("task"),
               v("commandline").label("cmdline"), v("newprocessname").label("proc"))
        .select_from(win).where(cond).limit(20000)
    ).mappings().all()

    # (rule_id, 集約キー) -> 行リスト。集約キーは送信元IP（ネットワーク起点のもの）かホスト名。
    buckets: dict[tuple[str, str], list] = {}

    def put(rule_id: str, key: str | None, r) -> None:
        buckets.setdefault((rule_id, key or "(不明)"), []).append(r)

    for r in rows:
        e = r["eid"]
        if r["is_pth"]:
            put("win_pass_the_hash", r["ip"] or r["host"], r)
        elif e in ("1102", "104"):
            put("win_log_cleared", r["host"], r)
        elif e == "4624" and r["logontype"] == "10":
            if _is_global_ip(r["ip"]):
                put("win_rdp_external", r["ip"], r)
        elif r["is_kerb"]:
            put("win_kerberoasting", r["ip"] or r["host"], r)
        elif e in ("4728", "4732", "4756"):
            put("win_priv_group_add", r["host"], r)
        elif e == "4720":
            put("win_account_created", r["host"], r)
        elif e in ("7045", "4697"):
            put("win_service_installed", r["host"], r)
        elif e == "4698":
            put("win_scheduled_task", r["host"], r)
        elif e == "4719":
            put("win_audit_policy_changed", r["host"], r)
        elif e == "4688":
            put("win_suspicious_command", r["host"], r)

    per_rule: dict[str, int] = {}
    for (rule_id, key), rs in sorted(buckets.items(), key=lambda kv: -len(kv[1])):
        if per_rule.get(rule_id, 0) >= MAX_HITS_PER_RULE:
            continue
        per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
        by_ip = key == rs[0]["ip"]
        pivot = None if key == "(不明)" else {"field": "source_ip" if by_ip else "host_name", "value": key}
        name = _rec(rule_id)[0].replace("[Windows] ", "")
        add(rule_id, f"{name}: {key}", _win_evidence(rule_id, rs), len(rs), pivot=pivot)

    # --- ログオン失敗(4625): IP単位の多発 / パスワードスプレー（正規化済みの列だけで集計できる）---
    rows = db.execute(
        select(Event.source_ip, func.count(), func.count(func.distinct(Event.actor_user)))
        .select_from(Event)
        .where(Event.source_type == WIN_SOURCE_TYPE, Event.event_action == "4625",
               Event.source_ip.isnot(None), *w)
        .group_by(Event.source_ip)
        .having(or_(func.count() >= AUTH_FAIL_MIN,
                    func.count(func.distinct(Event.actor_user)) >= WIN_SPRAY_MIN_USERS))
        .order_by(func.count().desc()).limit(MAX_HITS_PER_RULE)
    ).all()
    for ip, cnt, users in rows:
        pivot = {"field": "source_ip", "value": ip}
        if users >= WIN_SPRAY_MIN_USERS:
            add("win_password_spray", f"パスワードスプレーの疑い: {ip}",
                f"{users} 個の異なるアカウントへのログオン失敗 {cnt} 件", cnt, pivot=pivot)
        if cnt >= AUTH_FAIL_MIN:
            add("win_logon_failure_ip", f"ログオン失敗の多発: {ip}",
                f"ログオン失敗 {cnt} 件（対象アカウント {users} 個）", cnt, pivot=pivot)


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
