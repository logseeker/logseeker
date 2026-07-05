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
