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
  actor_user: string | null;
  url_path: string | null;
  http_method: string | null;
  http_status_code: string | null;
  message: string | null;
}

export interface EventsResponse {
  total: number; limit: number; offset: number; items: EventRow[];
}

export interface EventDetail {
  id: number;
  source: string | null;
  source_type: string | null;
  ingest_channel: string;
  receiver_ip: string | null;
  received_at: string | null;
  parser_name: string | null;
  parser_version: string | null;
  parse_status: string;
  parse_error: string | null;
  payload: Record<string, unknown>;
  normalized: Record<string, unknown>;
}

export interface Timeline { buckets: string[]; series: Record<string, number[]>; }
export interface Count { value: string | null; count: number; }
export interface FieldInfo { field: string; distinct: number; values: Count[]; }

export interface Summary {
  total: number;
  recent_24h: number;
  ingest_failed: number;
  dead_letters: number;
  source_count: number;
  host_domain_count: number;
  by_source_name: Count[];
  by_device: Count[];
  by_domain: Count[];
  top_source_ip: Count[];
  top_actor_user: Count[];
  top_url_path: Count[];
  by_http_status: Count[];
  by_event_action: Count[];
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
export interface EntityDetail {
  entity_type: string; entity_value: string; count: number;
  first_seen: string | null; last_seen: string | null;
  source_names: string[]; source_types: string[];
}
export interface IncidentRow {
  id: number; title: string; status: string; severity: string | null;
  owner: string | null; summary: string | null; updated_at: string | null; event_count: number;
}
export interface IncidentDetail extends Omit<IncidentRow, "event_count" | "updated_at"> {
  created_at: string | null;
  events: (EventRow & { note: string | null })[];
}
export interface Annotation {
  id: number; comment: string | null; tags: string | null;
  created_by: string | null; created_at: string | null;
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
  bytes_daily: { day: string; bytes: number }[];
  bytes_monthly: { month: string; bytes: number }[];
}

export interface RuleHit {
  rule_id: string; rule_name: string; severity: string;
  title: string; evidence: string; count: number; recommendation: string;
  pivot: { field: string; value: string } | null;
}
export interface RuleDef {
  id: string; name: string; severity: string; description: string; recommendation: string;
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
  expires_at: string | null;
  days_left: number | null;
  retention_days: number;
  retention_unlimited: boolean;
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
export interface MappingsResponse { note: string; groups: MappingGroup[]; }

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
  | "dashboard" | "events" | "sources" | "hosts" | "entities" | "correlations"
  | "fields" | "mappings" | "ingest" | "operations" | "deadletters" | "incidents" | "rules"
  | "threatintel" | "notifications" | "license" | "admin" | "users" | "audit" | "changelog";

export interface ReleaseItem {
  tag_name: string;
  name: string;
  body: string;
  published_at: string | null;
  html_url: string;
  prerelease: boolean;
}
