// イベント1件から「危険度と対応策」を導く（AIなし・ルールと同じ考え方をフロントで軽量再現）。
// rules.py の判定と整合。イベント一覧の「対応策」列とイベント詳細で共用。

export interface EventAdvice {
  level: "danger" | "warning";
  title: string;
  rec: string;          // 対応策の説明
  actions: string[];    // 具体アクション（バッジ表示用）
}

interface EventLike {
  event_category?: string | null;
  event_result?: string | null;
  event_severity?: string | null;
  actor_user?: string | null;
  url_path?: string | null;
  http_status_code?: string | null;
  source_type?: string | null;
}

const SENSITIVE = [
  "wp-login", "xmlrpc.php", "wp-config", "/.env", "/.git", "/.aws", "/phpmyadmin",
  "/phpMyAdmin", "eval-stdin", "/shell", "/wp-content/plugins/", "/wp-admin/", "/.ssh",
  "/config.php", "/vendor/", "/.well-known/", "wso.php",
];

export function adviseForEvent(e: EventLike): EventAdvice | null {
  const cat = (e.event_category || "").toLowerCase();
  const result = (e.event_result || "").toLowerCase();
  const user = (e.actor_user || "").toLowerCase();
  const path = e.url_path || "";
  const status = e.http_status_code || "";
  const sev = (e.event_severity || "").toLowerCase();

  // 認証失敗（root は特に危険）
  if ((cat === "authentication" || cat === "security") && result === "failure") {
    if (user === "root" || user === "administrator" || user === "admin") {
      return {
        level: "danger",
        title: "特権ユーザーへのログイン試行",
        rec: "root/管理者への直接ログインは禁止推奨。該当IPを遮断し、鍵認証・多要素認証へ。",
        actions: ["IP遮断", "PermitRootLogin no", "公開鍵のみ(PasswordAuth無効)", "Fail2ban"],
      };
    }
    return {
      level: "warning",
      title: "認証失敗（総当たりの疑い）",
      rec: "同一IP/ユーザーで多発するなら総当たり。該当IPを遮断し、MFA・アカウントロックを検討。",
      actions: ["IP遮断", "MFA", "アカウントロック", "SSH/RDPポート制限"],
    };
  }

  // 危険パスへのアクセス
  if (path && SENSITIVE.some((p) => path.toLowerCase().includes(p.toLowerCase()))) {
    return {
      level: "danger",
      title: "危険パスへのアクセス",
      rec: ".env/.git/wp-login 等への探索。該当IPを遮断し、当該パスを公開停止・認証保護。",
      actions: ["IP遮断", "該当パス公開停止", "管理画面に認証", "CMS/プラグイン更新"],
    };
  }

  // Webスキャン（4xx失敗）
  if (cat === "web" && result === "failure" && /^4\d\d$/.test(status)) {
    return {
      level: "warning",
      title: "Webスキャン/探索の疑い",
      rec: "存在しないパスへの探索の可能性。多発する送信元はWAF/FWで遮断、レート制限。",
      actions: ["IP遮断", "WAF", "レート制限"],
    };
  }

  // 高重大度（上記に当たらないが警告以上）
  if (["critical", "crit", "alert", "emerg", "error", "err", "warning", "warn"].includes(sev)) {
    return {
      level: sev.startsWith("warn") ? "warning" : "danger",
      title: "重大度の高いイベント",
      rec: "内容を確認し、原因（攻撃・障害・設定）を切り分け。必要なら送信元を制限。",
      actions: ["内容確認", "送信元IP調査"],
    };
  }

  return null;
}
