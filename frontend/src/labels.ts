// source_type の日本語表示（syslog は使わない・出さない）
export const ST_LABEL: Record<string, string> = {
  web_access: "Webアクセス",
  web_error: "Webエラー",
  google_workspace_audit: "Google Workspace監査",
  router: "ルーター",
  nas: "NAS",
  auth: "認証ログ",
  application: "アプリケーション",
  system: "システム",
  mail: "メール",
  windows_event: "Windowsイベント",
  linux: "Linux",
  security: "セキュリティ",
  dns: "DNS",
  dhcp: "DHCP",
  firewall: "ファイアウォール",
  smb: "SMB",
  asset: "資産管理",
  m365_audit: "Microsoft 365監査",
  entra_signin: "Entraサインイン",
  unknown: "Unknown",
};

export const stLabel = (st: string | null | undefined): string =>
  (st && ST_LABEL[st]) || st || "Unknown";

// 正規化フィールド名（絞り込みキー）の日本語表示。絞り込みチップやカスタムルール画面で使う。
export const FIELD_LABEL: Record<string, string> = {
  source_name: "ログソース", source_type: "種別", parse_status: "解析状態",
  event_category: "カテゴリ", event_action: "アクション", event_result: "結果",
  event_severity: "重大度", device_name: "ホスト/デバイス", source_ip: "送信元IP",
  source_country: "国コード", source_asn: "AS番号", source_as_org: "AS組織名",
  actor_user: "ユーザー", url_domain: "ドメイン", url_path: "URLパス",
  http_status_code: "HTTPステータス", host_name: "ホスト名", observer_name: "観測ホスト",
  service_name: "サービス", network_protocol: "プロトコル", message: "メッセージ",
};

export const fieldLabel = (k: string): string => FIELD_LABEL[k] || k;
