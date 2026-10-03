"""監査ログを「誰が・何を・どれに・どう変えたか」が読める形で残すための仕組み。

以前は変更系APIをミドルウェアで一律 `api.change` として記録しており、メソッドとパスしか
残らなかった（`PUT /api/custom-rules/3 200` では、どのルールの何を変えたか分からない）。

記録の流れ:
  1. 各エンドポイントが処理の中で `note(request, action, target=..., detail=...)` を呼び、
     「何をしたか」を日本語で request.state に置く（変更前の値を知っているのはエンドポイントだけ）。
  2. main.py のミドルウェアがレスポンス後に `record_request()` を呼び、上の内容に
     ユーザー・IP・HTTPステータスを合わせて1行だけ書く。
  3. note() が呼ばれずに終わったリクエスト（権限不足・入力エラー等で早期returnしたもの）も
     ROUTES から操作名を引いて記録する（失敗した操作も監査対象のため）。

パスワード・APIキー・Webhook URL・クライアントシークレットの値は絶対に detail に入れない
（「変更した」事実だけを書く）。
"""
import re

from fastapi import Request

# ---- 操作名（action → 画面表示用の日本語） ----
ACTION_LABELS: dict[str, str] = {
    "login": "ログイン",
    "login.admin": "管理パネルへのログイン",
    "logout": "ログアウト",
    "user.create": "ユーザー追加",
    "user.update": "ユーザー編集",
    "user.password": "パスワード変更",
    "user.delete": "ユーザー削除",
    "auth.toggle": "ログイン認証の切替",
    "sso.config": "SSO設定の変更",
    "ip_restrict.config": "IPアクセス制限の変更",
    "ip_restrict.block": "IP制限によるアクセス拒否",
    "audit.download": "監査ログのダウンロード",
    "events.export": "イベントのエクスポート",
    "incident.create": "インシデント作成",
    "incident.status": "インシデントのステータス変更",
    "incident.assignee": "インシデントの担当者変更",
    "incident.verdict": "インシデントの判定変更",
    "incident.comment": "インシデントへのコメント",
    "incident.response_action": "インシデントの対応アクション記録",
    "incident_status.create": "インシデントステータスの追加",
    "incident_status.visibility": "インシデントステータスの表示切替",
    "response_action_type.create": "対応アクション種別の追加",
    "response_action_type.visibility": "対応アクション種別の表示切替",
    "asset.create": "資産の登録",
    "asset.update": "資産の編集",
    "asset.delete": "資産の削除",
    "asset.local_name": "ローカルIPの表示名変更",
    "case.create": "ケース作成",
    "case.rename": "ケース名の変更",
    "case.event_add": "ケースへのイベント追加",
    "case.event_note": "ケース内イベントのメモ編集",
    "case.event_remove": "ケースからイベントを除外",
    "case.comment": "ケースへのコメント",
    "custom_rule.create": "検知ルールの追加",
    "custom_rule.update": "検知ルールの編集",
    "custom_rule.delete": "検知ルールの削除",
    "silence.update": "ログ未達しきい値の変更",
    "license.apply": "ライセンスの適用",
    "ioc.feed": "脅威インテリジェンスフィードの設定",
    "ioc.settings": "IOC同期間隔の変更",
    "ioc.sync": "IOCの手動同期",
    "notify.config": "通知設定の変更",
    "notify.test_email": "テストメールの送信",
    "notify.test_slack": "Slackテスト通知の送信",
    "notify.send_now": "通知の即時送信",
    "api.change": "変更操作",
}

# ---- ルート（メソッド, FastAPIのパステンプレート）→ action ----
# note() が呼ばれなかったリクエスト（早期エラー等）と、旧形式 `api.change` 行の表示に使う。
ROUTES: dict[tuple[str, str], str] = {
    ("POST", "/api/events/{event_id}/incident"): "incident.create",
    ("PUT", "/api/assets/local/{ip}"): "asset.local_name",
    ("POST", "/api/assets"): "asset.create",
    ("PUT", "/api/assets/{asset_id}"): "asset.update",
    ("DELETE", "/api/assets/{asset_id}"): "asset.delete",
    ("POST", "/api/cases"): "case.create",
    ("PUT", "/api/cases/{case_id}"): "case.rename",
    ("POST", "/api/cases/{case_id}/events"): "case.event_add",
    ("PUT", "/api/cases/{case_id}/events/{event_id}"): "case.event_note",
    ("DELETE", "/api/cases/{case_id}/events/{event_id}"): "case.event_remove",
    ("POST", "/api/cases/{case_id}/comments"): "case.comment",
    ("PUT", "/api/incidents/{incident_id}/status"): "incident.status",
    ("PUT", "/api/incidents/{incident_id}/assignee"): "incident.assignee",
    ("PUT", "/api/incidents/{incident_id}/verdict"): "incident.verdict",
    ("POST", "/api/incidents/{incident_id}/comments"): "incident.comment",
    ("POST", "/api/incidents/{incident_id}/response-actions"): "incident.response_action",
    ("POST", "/api/incident-statuses"): "incident_status.create",
    ("PUT", "/api/incident-statuses/{status_id}/visibility"): "incident_status.visibility",
    ("POST", "/api/incident-response-action-types"): "response_action_type.create",
    ("PUT", "/api/incident-response-action-types/{type_id}/visibility"): "response_action_type.visibility",
    ("POST", "/api/custom-rules"): "custom_rule.create",
    ("PUT", "/api/custom-rules/{rule_id}"): "custom_rule.update",
    ("DELETE", "/api/custom-rules/{rule_id}"): "custom_rule.delete",
    ("POST", "/api/monitor/silence"): "silence.update",
    ("POST", "/api/license"): "license.apply",
    ("POST", "/api/ioc/feeds"): "ioc.feed",
    ("POST", "/api/ioc/settings"): "ioc.settings",
    ("POST", "/api/ioc/sync"): "ioc.sync",
    ("PUT", "/api/notifications"): "notify.config",
    ("POST", "/api/notifications/test/email"): "notify.test_email",
    ("POST", "/api/notifications/test/slack"): "notify.test_slack",
    ("POST", "/api/notifications/send-now"): "notify.send_now",
    ("POST", "/api/users"): "user.create",
    ("PUT", "/api/users/{user_id}"): "user.update",
    ("DELETE", "/api/users/{user_id}"): "user.delete",
    ("POST", "/api/auth/require"): "auth.toggle",
    ("PUT", "/api/sso"): "sso.config",
    ("PUT", "/api/admin/ip-restrict"): "ip_restrict.config",
}

# 個人の表示設定（列の並び・Classの表示順・お知らせ既読）は監査対象外。
# 列の表示切替のたびに1行増え、肝心の操作が埋もれるため。
SKIP: set[tuple[str, str]] = {
    ("PUT", "/api/events/columns"),
    ("PUT", "/api/events/column-sets"),
    ("DELETE", "/api/events/column-sets/{name}"),
    ("PUT", "/api/events/classes"),
    ("PUT", "/api/changelog/dismissed"),
}
# login/logout は auth_api.py 側で直接記録している（ログイン前はトークンからユーザーを引けないため）。
SKIP_PATHS = {"/api/auth/login", "/api/auth/admin-login", "/api/auth/logout"}

_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

_ROUTE_RE = [(m, re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", t) + "$"), a) for (m, t), a in ROUTES.items()]


def label_of(action: str, method: str | None = None, path: str | None = None) -> str:
    """表示用の操作名。旧形式の `api.change` 行はメソッドとパスから操作名を推定する。"""
    if action == "api.change" and method and path:
        for m, rx, a in _ROUTE_RE:
            if m == method and rx.match(path):
                return ACTION_LABELS[a]
    return ACTION_LABELS.get(action, action)


# ---- 値の整形 ----
SEVERITY_LABELS = {"critical": "重大", "high": "高", "warning": "警告"}
MATCH_OP_LABELS = {"contains": "部分一致", "equals": "完全一致"}
VERDICT_LABELS = {"unjudged": "未判定", "true_positive": "True Positive（真陽性）",
                  "false_positive": "誤検知", "over_detection": "過検知", "other": "その他"}


def fmt(v, limit: int = 80) -> str:
    if v is None or v == "":
        return "（なし）"
    if isinstance(v, bool):
        return "有効" if v else "無効"
    s = str(v).replace("\r", " ").replace("\n", " ")
    return s if len(s) <= limit else s[:limit] + "…"


def diff(labels: dict[str, str], before: dict, after: dict,
         formatters: dict | None = None) -> list[str]:
    """after に含まれる項目のうち、値が変わったものを「項目: 旧 → 新」で返す。"""
    formatters = formatters or {}
    out = []
    for k, label in labels.items():
        if k not in after:
            continue
        b, a = before.get(k), after[k]
        if (None if b == "" else b) == (None if a == "" else a):
            continue
        f = formatters.get(k, fmt)
        out.append(f"{label}: {f(b)} → {f(a)}")
    return out


def join(parts: list[str], empty: str = "変更なし") -> str:
    return " / ".join(p for p in parts if p) or empty


# ---- 記録 ----
def note(request: Request, action: str, target: str | None = None, detail: str | None = None,
         status: str | None = None) -> None:
    """このリクエストで何をしたかを置いておく（実際の書き込みはミドルウェア）。
    status はHTTPステータスでは成否が分からない場合（200で {"ok": false} を返すAPI等）にだけ渡す。"""
    request.state.audit_note = {"action": action, "target": target, "detail": detail, "status": status}


def record_request(request: Request, status_code: int) -> None:
    path = request.url.path
    if not path.startswith("/api") or path in SKIP_PATHS:
        return
    route = request.scope.get("route")
    template = getattr(route, "path", path)
    key = (request.method, template)
    if key in SKIP:
        return
    if 300 <= status_code < 400:
        return  # 末尾スラッシュ等のリダイレクト。転送先のリクエストが別に記録される
    n = getattr(request.state, "audit_note", None)
    if n is None and request.method not in _MUTATING:
        return  # 閲覧系は、エクスポート等 note() を呼んだものだけ記録する

    from .auth import audit, client_ip, get_current_user
    from .db import SessionLocal

    if n is None:
        # 早期エラー等で note() が呼ばれなかった。操作名と、パス中のIDだけは残す。
        params = request.scope.get("path_params") or {}
        n = {"action": ROUTES.get(key, "api.change"),
             "target": ", ".join(f"#{v}" if k.endswith("_id") else str(v) for k, v in params.items()) or None,
             "detail": ("存在しないAPIへのリクエスト" if route is None
                        else None if status_code < 400
                        else "処理されませんでした（権限不足・入力エラー・対象なし等）"),
             "status": None}
    status = n.get("status") or str(status_code)

    db = SessionLocal()
    try:
        user = get_current_user(request.headers.get("authorization"), db)
        detail = n.get("detail")
        audit(db, action=n["action"], user=user, method=request.method, path=path, status=status,
              target=(n.get("target") or None) and str(n["target"])[:255],
              detail=detail[:2000] if detail else None, ip=client_ip(request))
    finally:
        db.close()
