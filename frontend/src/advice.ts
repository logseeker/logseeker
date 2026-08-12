// イベント1件から「危険度と対応策」を導く（AIなし・ルールと同じ考え方をフロントで軽量再現）。
// rules.py の判定と整合。イベント一覧の「対応策」列とイベント詳細で共用。
//
// 入力は **docs/taxonomy.md のTaxonomy KEY** で受ける（v12 §4.1.1）。
// 旧版は normalized_events の列名（event_category / url_path 等）で受けていたが、
// あれは normalize.py の MAPPINGS によるKEY読み替えの産物で、v12 §15が禁じている。
// 判定内容そのものは変えていない。

export interface EventAdvice {
  level: "danger" | "warning";
  title: string;
  rec: string;          // 対応策の説明
  actions: string[];    // 具体アクション（バッジ表示用）
}

/** Taxonomy KEYで表したイベント。値は payload から読んだものをそのまま渡す。 */
export interface TaxonomyEventLike {
  category?: string | null;
  result?: string | null;
  severity?: string | null;
  username?: string | null;
  accountname?: string | null;
  uri?: string | null;
  query?: string | null;
  statuscode?: string | null;
  status?: string | null;
  class?: string | null;
}

// backend/app/rules.py の SENSITIVE_PATHS と同期させること。
const SENSITIVE = [
  // WordPress
  "wp-login", "xmlrpc.php", "wp-config", "/wp-admin/", "/wp-content/plugins/",
  "/wp-content/uploads/", "/wp-json/wp/v2/users",
  // Movable Type
  "mt-static/", "mt-config.cgi", "/mt.cgi", "mt-search.cgi", "mt-load.cgi", "mt-comments.cgi",
  // Joomla
  "/administrator/", "/components/com_", "configuration.php~",
  // Drupal
  "/user/register", "/core/CHANGELOG.txt", "/sites/default/settings.php",
  // TYPO3
  "/typo3/", "/typo3conf/",
  // EC-CUBE
  "/html/admin/", "/data/downloads/",
  // phpMyAdmin 系
  "/phpmyadmin", "/phpMyAdmin", "/pma/", "/myadmin/", "/dbadmin/",
  // 汎用の機密ファイル・設定ファイル
  "/.env", "/.git", "/.aws", "/.ssh", "/config.php", "/vendor/", "/.well-known/",
  "/.htpasswd", "/.docker/", "web.config",
  // フレームワークのデバッグ/管理系エンドポイント
  "/actuator", "/telescope", "/_profiler", "/_ignition",
  // Webシェル・コマンド実行の痕跡
  "eval-stdin", "/shell", "wso.php", "c99.php", "r57.php", "/cmd.php",
];

// backend/app/rules.py の WEBSHELL_PROBE_RE と同期させること（数字のみのファイル名(1〜4桁).php への探索）。
const WEBSHELL_PROBE_RE = /(^|\/)\d{1,4}\.php$/i;

// backend/app/rules.py の PAYLOAD_SIGNATURES と同期させること。今後も追加していく前提の配列。
const PAYLOAD_SIGNATURES = [
  // パストラバーサル
  "../", "..%2f", "%2e%2e",
  // SQLインジェクション（union select / or 1=1 はURLエンコード(%20)・フォームエンコード(+)後の
  // 亜種も追加。生のスペースはログの request 文字列上ではほぼ出現しないため）
  "union select", "union%20select", "union+select",
  "sleep(",
  "or 1=1", "or%201=1", "or+1=1",
  ";--",
  // XSS
  "<script", "onerror=", "javascript:",
  // PHPラッパー悪用
  "php://input", "php://filter", "data://text",
  // コマンドインジェクション
  "; cat ", "| id", "`id`",
  // Log4Shell
  "${jndi:",
];

export function adviseForEvent(e: TaxonomyEventLike): EventAdvice | null {
  const cat = (e.category || "").toLowerCase();
  const result = (e.result || "").toLowerCase();
  const user = (e.username || e.accountname || "").toLowerCase();
  // uri はクエリを含む場合があるため、? 以降を query 側にも回して判定に載せる
  const rawUri = e.uri || "";
  const [path, uriQuery] = rawUri.includes("?") ? [rawUri.slice(0, rawUri.indexOf("?")), rawUri.slice(rawUri.indexOf("?") + 1)] : [rawUri, ""];
  const query = e.query || uriQuery;
  const status = e.statuscode || e.status || "";
  const sev = (e.severity || "").toLowerCase();

  // 攻撃ペイロード検知（パストラバーサル/SQLi/XSS等。件数しきい値なし・最優先）
  const urlCombined = `${path} ${query}`.toLowerCase();
  if (PAYLOAD_SIGNATURES.some((p) => urlCombined.includes(p.toLowerCase()))) {
    return {
      level: "danger",
      title: "攻撃ペイロード検知",
      rec: "パストラバーサル/SQLi/XSS等の既知シグネチャを含むリクエスト。該当IPを即時遮断し、対象アプリの脆弱性有無を確認。",
      actions: ["IP遮断", "脆弱性確認", "WAF"],
    };
  }

  // ビルド失敗（Astro, source_type=astro_build）: 運用監視系。攻撃系とは別トーン（「不審」ではなく「要対応」）
  if ((cat === "build" || (e.class || "").includes("build")) && result.includes("fail")) {
    return {
      level: "warning",
      title: "ビルド失敗（要対応）",
      rec: "npm run build を手動で再実行して再現するか確認。errorの内容と直近のコンテンツ変更・依存パッケージ更新を確認。"
        + "trigger が directus_flow/directus_activity ならDirectus側の記事編集内容も確認。",
      actions: ["ビルド再実行", "error内容確認", "Directus編集確認", "ビルド環境確認"],
    };
  }

  // 認証失敗（root は特に危険）。
  // 旧版は category が authentication/security であることを条件にしていたが、category は
  // 送信元が明示しないと存在しないTaxonomy KEYなので、result の失敗判定を主軸にする
  // （backend の _threat_clause の auth_fail と同じ考え方）。
  if (result.includes("fail") || result === "failure") {
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

  // Webshell探索の疑い（数字名.phpへの404。1件でも要注意。件数しきい値なし）
  if (status === "404" && WEBSHELL_PROBE_RE.test(path)) {
    return {
      level: "danger",
      title: "Webshell探索の疑い",
      rec: "数字名の.phpへの探索アクセス。過去に設置されたWebshellを当てずっぽうで探る典型パターン。該当IPを遮断し、心当たりのない.phpが無いか確認。",
      actions: ["IP遮断", ".php確認", "WAF"],
    };
  }

  // Webスキャン（4xx失敗）
  if (/^4\d\d$/.test(status)) {
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
