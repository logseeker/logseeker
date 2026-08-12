export interface EventRow {
  id: number;
  source_name: string | null;
  source_type: string | null;
  device_name: string | null;
  url_domain: string | null;
  parse_status: string;
  received_at: string | null;
  event_time: string | null;
  event_time_confidence: string | null;
  event_category: string | null;
  event_action: string | null;
  event_result: string | null;
  event_severity: string | null;
  service_name: string | null;
  source_ip: string | null;
  source_country: string | null;
  source_asn: number | null;
  source_as_org: string | null;
  actor_user: string | null;
  url_path: string | null;
  url_query: string | null;
  http_method: string | null;
  http_status_code: string | null;
  message: string | null;
  resolved: boolean;
  payload: Record<string, unknown>;
}

export interface Timeline { buckets: string[]; series: Record<string, number[]>; }
export interface Count { value: string | null; count: number; }
export interface FieldInfo { field: string; distinct: number; values: Count[]; }

// ============================ Events / Dashboard（v12 A案・新実装）============================
// 「受信フィールド」＝ payload内のKEYのうち docs/taxonomy.md のTaxonomy KEYと完全一致するもの
// だけ（v12 §4.1.1）。列の選択肢は実データではなくTaxonomy（762KEY）が決める。

export interface TaxonomyField {
  key: string; type: string; label: string | null;
  recommended: boolean;    // そのClassの参考例に載っているKEYか（並び順のヒント。制限ではない）
}
export interface EventsFields {
  class_value: string | null; total: number; keys: TaxonomyField[]; default_columns: string[];
}

// 列セット＝名前を付けて保存した表示列のプリセット
export interface ColumnSets {
  class_value: string | null;
  columns: string[] | null;          // 現在の表示列（未保存ならnull→default_columnsを使う）
  default_columns: string[];
  sets: Record<string, string[]>;    // 名前 -> 列
}

export interface EventsClass {
  class_value: string; count: number; hidden: boolean; pinned: boolean; has_hints: boolean;
}
export interface EventsClassesResponse { classes: EventsClass[]; }

export interface EventSearchRow {
  id: number;
  received_at: string | null;
  class_value: string | null;
  source: string | null;
  resolved: boolean;
  values: Record<string, unknown>;   // 表示中のTaxonomy KEYの値だけ
}
export interface EventsSearchResponse {
  total: number; limit: number; offset: number; columns: string[]; items: EventSearchRow[];
}

export interface HistogramBucket { t: string; count: number }
export interface HistogramResponse {
  start: string; end: string; width_seconds: number; buckets: HistogramBucket[];
}

export interface FacetResponse { field: string; label?: string | null; values: Count[] }

export interface EventField { key: string; value: unknown; label: string | null; type: string | null }
export interface EventDetailData {
  id: number;
  class_value: string | null;
  source: string | null;
  received_at: string | null;
  ingest_channel: string;
  resolved: boolean;
  fields: EventField[];              // Taxonomy KEY完全一致分のみ
  taxonomy_outside_count: number;    // Taxonomy外KEYは件数だけ（中身は返さない。v12 §10.3）
  is_attention: boolean;
  linked_case: { id: number; title: string } | null;
  linked_incident: { id: number; title: string } | null;
}

export interface DashboardBreakdown { field: string; label: string | null; values: Count[] }
export interface DashboardOverview {
  total: number;
  period: { start: string; end: string };
  by_source: Count[];
  source_count: number;
  host_domain_count: number;
  ingest_failed: number;
  by_class: Count[];
  domain_host: { priority: string[]; representative: Count[]; extra: Record<string, Count[]> };
  breakdowns: DashboardBreakdown[];  // 集計軸は利用者が選ぶ（固定しない）
  empty_axes: string[];             // 選択中だが受信値が無い軸（カードを出さない）
}

export interface FilterState {
  q?: string;
  start?: string;
  end?: string;
  attention?: boolean;
  threat?: string;   // ioc / sensitive_path / web_scan / auth_fail / any
  tax: Record<string, string>;
}

export interface EntityRow {
  entity_type: string; entity_value: string; count: number;
  first_seen: string | null; last_seen: string | null;
}
export interface AssetRow {
  id: number | null;
  ip: string;
  ip_version: "v4" | "v6";
  scope: "local" | "registered_global";
  label: string | null;
  description: string | null;
  display_name: string | null;
  count: number;
  first_seen: string | null;
  last_seen: string | null;
}
export interface EntityDetail {
  entity_type: string; entity_value: string; count: number;
  first_seen: string | null; last_seen: string | null;
  source_names: string[]; source_types: string[];
}
export type IncidentSpecialType = "unassigned" | "done" | "reopened" | null;
export interface IncidentStatusDef {
  id: number; name: string; special_type: IncidentSpecialType;
  is_visible: boolean; sort_order: number;
}
export interface IncidentResponseActionTypeDef {
  id: number; name: string; is_visible: boolean; sort_order: number;
}
export type Verdict = "unjudged" | "true_positive" | "false_positive" | "over_detection" | "other";

// ケース＝複数イベントを束ねる調査ワークスペース（ステータス・判定結果・担当者を持たない。
// インシデントへの「昇格」概念も無い。設計書v4 3章）
export interface CaseRow {
  id: number; title: string;
  updated_at: string | null; event_count: number;
}
export interface CaseDetail extends Omit<CaseRow, "event_count" | "updated_at"> {
  created_at: string | null; updated_at: string | null;
  events: (EventRow & { note: string | null })[];
}
export interface CaseCommentItem {
  id: number; body: string; actor_name: string | null; created_at: string | null;
}

// インシデント一覧の行（ケースを経由しない独立したインシデント一覧用。設計書v4 4章）
// event_idは保持期間切れ等で元イベントが削除されるとnullになりうる（ON DELETE SET NULL）。
export interface IncidentRow {
  id: number; event_id: number | null; title: string;
  status_id: number | null; status_name: string | null;
  verdict: Verdict;
  assignee_user_id: number | null; assignee_name: string | null;
  updated_at: string | null;
  event_source_name: string | null; event_action: string | null; event_message: string | null;
}

// インシデント＝アラート単位の確定事案（ケースには依存しない。設計書v4 4章）
// event_idは保持期間切れ等で元イベントが削除されるとnullになりうる（ON DELETE SET NULL）。
export interface IncidentDetail {
  id: number; event_id: number | null; title: string;
  status_id: number | null; status_name: string | null;
  verdict: Verdict;
  assignee_user_id: number | null; assignee_name: string | null;
  created_at: string | null; updated_at: string | null;
  event: EventRow | null;   // 起因となった唯一のアラート（主役アラート情報）
}
export interface AssignableUser { id: number; username: string; display_name: string | null; }
export interface IncidentActivityItem {
  id: string; type: string; body: string | null;
  before_value: string | null; after_value: string | null;
  actor_name: string | null; created_at: string | null;
}
export interface IngestStatus {
  total: number; dead_letters: number; tcp_port: number | null;
  by_channel: { channel: string | null; count: number; last_received: string | null }[];
}

export interface IngestVolume {
  total_bytes: number;
  avg_bytes_per_event: number;
  bytes_yesterday: number;
  bytes_last_5min: number;
  avg_bytes_per_minute_last_5min: number;
  bytes_hourly: { hour: string; bytes: number }[];
  bytes_daily: { day: string; bytes: number }[];
}

export interface RuleHit {
  rule_id: string; rule_name: string; severity: string; category: string;
  title: string; evidence: string; count: number; recommendation: string;
  pivot: { field: string; value: string } | null;
}
export interface RuleDef {
  id: string; name: string; severity: string; category: string; description: string; recommendation: string;
}

export interface CustomRule {
  id: number; name: string; description: string | null; severity: string; enabled: boolean;
  match_field: string; match_op: string; match_value: string;
  group_by: string | null; min_count: number; recommendation: string | null;
  created_by: string | null; created_at: string | null;
}
export interface CustomRulesResponse {
  items: CustomRule[]; match_fields: string[]; groupby_fields: string[];
}

export interface LicenseInfo {
  licensee: string | null;
  source: string; // applied / default
  started_at: string | null;
  expires_at: string | null;
  days_left: number | null;
  retention_days: number;
  retention_unlimited: boolean;
  retention_started_at: string;
  retention_expires_at: string | null;
  retention_days_left: number | null;
}

export interface IocFeed {
  name: string; enabled: boolean; has_key: boolean;
  last_synced_at: string | null; last_status: string | null;
  last_count: number; ioc_count: number;
}
export interface IocFeedsInfo {
  sync_hours: number; total_ioc: number; feeds: IocFeed[];
}

export type Role = "viewer" | "editor" | "sysadmin" | "admin";
export interface AuthUser {
  id: number; username: string; display_name: string | null;
  role: Role; role_label: string; enabled: boolean; is_sso: boolean;
  created_at: string | null; last_login_at: string | null;
}
export interface CreateUserResult extends AuthUser {
  email_sent: boolean | null;     // true=仮パスワードをメール送信 / null=メール通知が無効なため対象外
}
export interface SsoStatus {
  enabled: boolean; configured: boolean; issuer: string; client_id: string;
  has_secret: boolean; redirect_uri: string; allowed_domains: string;
  auto_provision_role: string; implemented: boolean;
}
export interface AuthStatus {
  auth_required: boolean;
  user: AuthUser | null;
  roles: { value: Role; label: string }[];
  sso: SsoStatus;
}
export interface IpAllowEntry { cidr: string; label: string; }
export interface IpRestrictStatus {
  enabled: boolean;
  allowlist: IpAllowEntry[];
  your_ip: string | null;
}
export interface AuditRow {
  id: number; at: string | null; username: string | null; role: string | null;
  action: string; method: string | null; path: string | null; status: string | null;
  target: string | null; detail: string | null; ip: string | null;
}
export interface AuditResponse { total: number; items: AuditRow[]; }

export interface CorrelationItem {
  value: string;
  event_count: number;
  source_type_count: number;
  source_types: string[];
  source_names: string[];
  first_seen: string | null;
  last_seen: string | null;
  failure_count: number;
  is_ioc: boolean;
}
export interface CorrelationResponse {
  entity_type: string; min_sources: number; items: CorrelationItem[];
}

export interface DeadLetterRow {
  id: number; received_at: string | null; ingest_channel: string | null;
  source: string | null; source_type: string | null; receiver_ip: string | null;
  error_type: string | null; error_message: string | null; raw_text: string;
}
export interface DeadLettersResponse { total: number; items: DeadLetterRow[]; }

export interface MappingField { field: string; field_label: string; candidate_keys: string[]; }
export interface MappingGroup { source_type: string; source_type_label: string; fields: MappingField[]; }
export interface TaxonomyKeyRef { key: string; label: string; }
export interface TaxonomyKeyGroup { title: string; keys: TaxonomyKeyRef[]; }
export interface LogSample {
  id: string; title: string; target: string; file: string;
  lang: string; note: string; keys: string[]; body: string;
}
export interface MappingsResponse {
  taxonomy_total: number;
  ingest_note: string;
  class_note: string;
  key_groups: TaxonomyKeyGroup[];
  samples: LogSample[];
  note: string;
  normalize_note: string;
  groups: MappingGroup[];
}

export interface AdminOverview {
  counts: Record<string, number>;
  parse_status: Record<string, number>;
  by_source_type: { source_type: string | null; count: number }[];
  by_channel: { channel: string | null; count: number; last_received: string | null }[];
  license: { licensee: string | null; source: string; days_left: number | null };
  ingest: { tcp_port: number | null; auth_enabled: boolean };
  ioc_sync_hours: number;
  retention: { days: number; unlimited: boolean; oldest_event_at: string | null };
  silence_hours: number;
}

export interface NotificationConfig {
  email_enabled: boolean;
  email_host: string;
  email_port: number;
  email_user: string;
  email_pass: string;
  email_from: string;
  email_to: string;
  slack_enabled: boolean;
  slack_webhook: string;
  min_severity: string;
  last_notified?: string;
}

export type Screen =
  | "dashboard" | "events" | "sources" | "hosts" | "assets" | "entities" | "correlations"
  | "fields" | "mappings" | "ingest" | "operations" | "deadletters" | "cases" | "incident" | "incidents"
  | "mastersettings" | "rules"
  | "threatintel" | "notifications" | "license" | "admin" | "users" | "audit" | "changelog"
  | "administration";

export interface ReleaseItem {
  tag_name: string;
  name: string;
  body: string;
  published_at: string | null;
  html_url: string;
  prerelease: boolean;
}

export interface DashboardTimeline {
  interval: "hour" | "day";
  date: string;
  buckets: { t: string; count: number }[];
}
