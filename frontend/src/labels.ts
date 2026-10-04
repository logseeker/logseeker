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

// event_time等はAPIからUTCのISO文字列（例: "2026-08-07T11:55:00+00:00"）で届く。
// 文字列を単純に切り出すとUTCの数字がそのまま表示され、ブラウザのローカル時刻(JST等)と
// 9時間ズレるため、Dateとして解釈してローカルタイムゾーンで整形する。
// 時刻の表示は、DBのタイムゾーン設定（開発=UTC・本番=JST）やブラウザの設定に関係なく常にJSTにそろえる。
// APIの文字列をそのまま切り出して表示すると、環境によって9時間ずれる（2026-10-04に監査ログで発覚）。
const JST = new Intl.DateTimeFormat("ja-JP", {
  timeZone: "Asia/Tokyo", year: "numeric", month: "2-digit", day: "2-digit",
  hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
});

export const fmtTime = (iso: string | null | undefined): string => {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = Object.fromEntries(JST.formatToParts(d).map((x) => [x.type, x.value]));
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}`;
};

/** datetime-local 入力欄用（JSTの "YYYY-MM-DDTHH:mm"）と、その逆変換。 */
export const toJstInput = (iso?: string): string => (iso ? fmtTime(iso).slice(0, 16).replace(" ", "T") : "");
export const fromJstInput = (local: string): string | undefined =>
  local ? new Date(`${local}:00+09:00`).toISOString() : undefined;
