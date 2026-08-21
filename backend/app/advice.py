"""イベント1件から「危険度と対応策」を導く（AIなし・ルールと同じ考え方をイベント単位で再現）。

frontend/src/advice.ts の adviseForEvent と同じ判定を、同じ順序でPythonに写したもの。
危険パス・Webshell探索・攻撃ペイロードの定義は rules.py の定数をそのまま参照するため、
「同期させること」の対象は advice.ts との1対1対応だけになる。

用途は2つ。
- インシデント化できるイベントかどうかの判定（api.py の create_incident_from_event）
- 画面が出している対応策とサーバ側の可否判定を一致させること
  （画面にボタンが出ているのにAPIが400を返す、という食い違いを防ぐ）

入力は **docs/taxonomy.md のTaxonomy KEY** で受ける（v12 §4.1.1）。
"""
import re

from .rules import PAYLOAD_SIGNATURES, SENSITIVE_PATHS, WEBSHELL_PROBE_RE

# 判定に使うTaxonomy KEY。payload から大文字小文字を無視して読む。
ADVICE_KEYS = ["category", "result", "severity", "username", "accountname",
               "uri", "query", "statuscode", "status", "class"]

_SEVERE = ["critical", "crit", "alert", "emerg", "error", "err", "warning", "warn"]
_PRIVILEGED_USERS = ["root", "administrator", "admin"]
_WEBSHELL_PROBE = re.compile(WEBSHELL_PROBE_RE, re.IGNORECASE)


def _s(v) -> str:
    return "" if v is None else str(v)


def advise_for_event(e: dict) -> dict | None:
    """対応策（level/title/rec/actions）を返す。該当なしは None。
    判定の順序は advice.ts と同じで、先に一致したものを返す。"""
    cat = _s(e.get("category")).lower()
    result = _s(e.get("result")).lower()
    user = (_s(e.get("username")) or _s(e.get("accountname"))).lower()
    # uri はクエリを含む場合があるため、? 以降を query 側にも回して判定に載せる
    raw_uri = _s(e.get("uri"))
    if "?" in raw_uri:
        path, uri_query = raw_uri.split("?", 1)
    else:
        path, uri_query = raw_uri, ""
    query = _s(e.get("query")) or uri_query
    status = _s(e.get("statuscode")) or _s(e.get("status"))
    sev = _s(e.get("severity")).lower()

    # 攻撃ペイロード検知（パストラバーサル/SQLi/XSS等。件数しきい値なし・最優先）
    url_combined = f"{path} {query}".lower()
    if any(p.lower() in url_combined for p in PAYLOAD_SIGNATURES):
        return {"level": "danger", "title": "攻撃ペイロード検知",
                "rec": "パストラバーサル/SQLi/XSS等の既知シグネチャを含むリクエスト。"
                       "該当IPを即時遮断し、対象アプリの脆弱性有無を確認。",
                "actions": ["IP遮断", "脆弱性確認", "WAF"]}

    # ビルド失敗（Astro, source_type=astro_build）: 運用監視系。攻撃系とは別トーン
    if (cat == "build" or "build" in _s(e.get("class"))) and "fail" in result:
        return {"level": "warning", "title": "ビルド失敗（要対応）",
                "rec": "npm run build を手動で再実行して再現するか確認。"
                       "errorの内容と直近のコンテンツ変更・依存パッケージ更新を確認。"
                       "trigger が directus_flow/directus_activity ならDirectus側の記事編集内容も確認。",
                "actions": ["ビルド再実行", "error内容確認", "Directus編集確認", "ビルド環境確認"]}

    # 認証失敗（root は特に危険）
    if "fail" in result or result == "failure":
        if user in _PRIVILEGED_USERS:
            return {"level": "danger", "title": "特権ユーザーへのログイン試行",
                    "rec": "root/管理者への直接ログインは禁止推奨。該当IPを遮断し、鍵認証・多要素認証へ。",
                    "actions": ["IP遮断", "PermitRootLogin no", "公開鍵のみ(PasswordAuth無効)", "Fail2ban"]}
        return {"level": "warning", "title": "認証失敗（総当たりの疑い）",
                "rec": "同一IP/ユーザーで多発するなら総当たり。該当IPを遮断し、MFA・アカウントロックを検討。",
                "actions": ["IP遮断", "MFA", "アカウントロック", "SSH/RDPポート制限"]}

    # 危険パスへのアクセス
    if path and any(p.lower() in path.lower() for p in SENSITIVE_PATHS):
        return {"level": "danger", "title": "危険パスへのアクセス",
                "rec": ".env/.git/wp-login 等への探索。該当IPを遮断し、当該パスを公開停止・認証保護。",
                "actions": ["IP遮断", "該当パス公開停止", "管理画面に認証", "CMS/プラグイン更新"]}

    # Webshell探索の疑い（数字名.phpへの404。1件でも要注意）
    if status == "404" and _WEBSHELL_PROBE.search(path):
        return {"level": "danger", "title": "Webshell探索の疑い",
                "rec": "数字名の.phpへの探索アクセス。過去に設置されたWebshellを当てずっぽうで探る典型パターン。"
                       "該当IPを遮断し、心当たりのない.phpが無いか確認。",
                "actions": ["IP遮断", ".php確認", "WAF"]}

    # Webスキャン（4xx失敗）
    if re.fullmatch(r"4\d\d", status):
        return {"level": "warning", "title": "Webスキャン/探索の疑い",
                "rec": "存在しないパスへの探索の可能性。多発する送信元はWAF/FWで遮断、レート制限。",
                "actions": ["IP遮断", "WAF", "レート制限"]}

    # 高重大度（上記に当たらないが警告以上）
    if sev in _SEVERE:
        return {"level": "warning" if sev.startswith("warn") else "danger",
                "title": "重大度の高いイベント",
                "rec": "内容を確認し、原因（攻撃・障害・設定）を切り分け。必要なら送信元を制限。",
                "actions": ["内容確認", "送信元IP調査"]}

    return None


def advise_for_payload(payload: dict) -> dict | None:
    """受信payloadから直接判定する。KEYの照合は大文字小文字を無視する（画面と同じ扱い）。"""
    p = payload if isinstance(payload, dict) else {}
    lower = {k.lower(): v for k, v in p.items()}
    return advise_for_event({k: lower.get(k) for k in ADVICE_KEYS})
