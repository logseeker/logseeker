import type {
  AdminOverview, Annotation, AuditResponse, AuthStatus, AuthUser, CorrelationResponse, Count,
  CreateUserResult, CustomRule, CustomRulesResponse, DeadLettersResponse, EntityDetail, EntityRow,
  EventDetail, EventRow, EventsResponse, FieldInfo, FilterState, IncidentDetail, IncidentRow,
  IngestStatus, IocFeedsInfo, LicenseInfo, MappingsResponse, NotificationConfig, Role, RuleDef,
  RuleHit, SsoStatus, Summary, Timeline,
} from "./types";

const BASE = (import.meta.env.VITE_API_BASE as string) || "";

// ---- 認証トークン（localStorage 保持）----
const TOKEN_KEY = "logseeker_token";
export const tokenStore = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (t: string) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
};
// 401 発生時のコールバック（App がログイン画面へ誘導するために登録）
let onUnauthorized: (() => void) | null = null;
export const setUnauthorizedHandler = (fn: () => void) => { onUnauthorized = fn; };

function authHeaders(): Record<string, string> {
  const t = tokenStore.get();
  return t ? { Authorization: `Bearer ${t}` } : {};
}

function qs(f: FilterState, extra: Record<string, string | number> = {}): string {
  const p = new URLSearchParams();
  if (f.q) p.set("q", f.q);
  if (f.start) p.set("start", f.start);
  if (f.end) p.set("end", f.end);
  if (f.attention) p.set("attention", "true");
  if (f.threat) p.set("threat", f.threat);
  Object.entries(f.tax).forEach(([k, v]) => p.set(k, v));
  Object.entries(extra).forEach(([k, v]) => p.set(k, String(v)));
  const s = p.toString();
  return s ? `?${s}` : "";
}

async function handle<T>(res: Response): Promise<T> {
  if (res.status === 401 && onUnauthorized) { tokenStore.clear(); onUnauthorized(); }
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try { const j = await res.json(); if (j?.error) msg = j.error; } catch { /* noop */ }
    throw new Error(msg);
  }
  return res.json() as Promise<T>;
}

async function get<T>(path: string): Promise<T> {
  return handle<T>(await fetch(`${BASE}${path}`, { headers: { ...authHeaders() } }));
}

async function send<T>(method: string, path: string, body?: unknown): Promise<T> {
  return handle<T>(await fetch(`${BASE}${path}`, {
    method,
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: body === undefined ? undefined : JSON.stringify(body),
  }));
}
const post = <T>(path: string, body: unknown): Promise<T> => send<T>("POST", path, body);
const put = <T>(path: string, body: unknown): Promise<T> => send<T>("PUT", path, body);
const del = <T>(path: string): Promise<T> => send<T>("DELETE", path);

const ev = (v: string) => encodeURIComponent(v);

// 認証必須(ON)の環境では /api/* すべてに Bearer トークンが要る。CSV等のファイルは
// 素の <a href> だとヘッダを付けられず401になるため、fetch+blob で認証ヘッダ付きDLする。
async function downloadFile(path: string, filename: string): Promise<void> {
  const res = await fetch(`${BASE}${path}`, { headers: { ...authHeaders() } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

export const api = {
  events: (f: FilterState, limit = 100, offset = 0) =>
    get<EventsResponse>(`/api/events${qs(f, { limit, offset })}`),
  eventDetail: (id: number) => get<EventDetail>(`/api/events/${id}`),
  timeline: (f: FilterState, interval: string, groupby?: string) =>
    get<Timeline>(`/api/timeline${qs(f, groupby ? { interval, groupby } : { interval })}`),
  groupby: (f: FilterState, field: string, top = 20) =>
    get<Count[]>(`/api/groupby${qs(f, { field, top })}`),
  sourceTypes: (f: FilterState) => get<{ source_type: string | null; count: number }[]>(`/api/source-types${qs(f)}`),
  fields: (f: FilterState) => get<FieldInfo[]>(`/api/fields${qs(f)}`),
  summary: (f: FilterState) => get<Summary>(`/api/dashboard/summary${qs(f)}`),

  // MVP3: エンティティ & 相関
  entities: (type?: string, q?: string) =>
    get<EntityRow[]>(`/api/entities?${new URLSearchParams({ ...(type ? { type } : {}), ...(q ? { q } : {}) })}`),
  entity: (type: string, value: string) => get<EntityDetail>(`/api/entity?type=${ev(type)}&value=${ev(value)}`),
  entityEvents: (type: string, value: string) => get<EventRow[]>(`/api/entity/events?type=${ev(type)}&value=${ev(value)}`),
  related: (id: number) => get<{ keys: { entity_type: string; entity_value: string }[]; items: EventRow[] }>(`/api/events/${id}/related`),

  // MVP5: インシデント & コメント
  incidents: () => get<IncidentRow[]>(`/api/incidents`),
  createIncident: (b: { title: string; severity?: string; summary?: string; owner?: string }) =>
    post<{ id: number }>(`/api/incidents`, b),
  incident: (id: number) => get<IncidentDetail>(`/api/incidents/${id}`),
  addIncidentEvent: (id: number, b: { event_id: number; note?: string }) =>
    post<{ ok: boolean }>(`/api/incidents/${id}/events`, b),
  annotations: (id: number) => get<Annotation[]>(`/api/events/${id}/annotations`),
  addAnnotation: (id: number, b: { comment?: string; tags?: string }) =>
    post<{ id: number }>(`/api/events/${id}/annotations`, b),

  ingestStatus: () => get<IngestStatus>(`/api/admin/ingest-status`),

  // ルール / 注意喚起（現在の絞り込みに追従）
  ruleHits: (f: FilterState) => get<{ hits: RuleHit[] }>(`/api/rule-hits${qs(f)}`),
  rules: () => get<RuleDef[]>(`/api/rules`),

  // カスタムルール（ユーザー定義の検知条件）
  customRules: () => get<CustomRulesResponse>(`/api/custom-rules`),
  createCustomRule: (b: Partial<CustomRule> & { name: string; match_field: string; match_value: string }) =>
    post<CustomRule>(`/api/custom-rules`, b),
  updateCustomRule: (id: number, b: Partial<CustomRule>) => put<CustomRule>(`/api/custom-rules/${id}`, b),
  deleteCustomRule: (id: number) => del<{ ok: boolean }>(`/api/custom-rules/${id}`),

  // ログ未達監視のしきい値
  silenceSettings: () => get<{ hours: number }>(`/api/monitor/silence`),
  saveSilenceSettings: (hours: number) => post<{ ok: boolean }>(`/api/monitor/silence`, { hours }),

  // イベントのCSV/JSONエクスポート（現在の絞り込みに従う。認証ヘッダ付きでblobダウンロード）
  exportEvents: (f: FilterState, format: "csv" | "json") =>
    downloadFile(`/api/events/export${qs(f, { format })}`, `logseeker_events.${format}`),

  // ライセンス
  license: () => get<LicenseInfo>(`/api/license`),
  applyLicense: (key: string) => post<{ ok?: boolean; error?: string }>(`/api/license`, { key }),

  // 脅威インテリ（IOCフィード）
  iocFeeds: () => get<IocFeedsInfo>(`/api/ioc/feeds`),
  updateFeed: (b: { name: string; api_key?: string; enabled: boolean }) =>
    post<{ ok: boolean }>(`/api/ioc/feeds`, b),
  iocSettings: (sync_hours: number) => post<{ ok: boolean }>(`/api/ioc/settings`, { sync_hours }),
  iocSyncNow: () => post<{ results: { name: string; count: number; status: string }[] }>(`/api/ioc/sync`, {}),

  // 相関分析（AI不要・複数ソース横断）
  correlations: (entity_type = "ip", min_sources = 1, limit = 100) =>
    get<CorrelationResponse>(`/api/correlations?entity_type=${entity_type}&min_sources=${min_sources}&limit=${limit}`),

  // 取り込み失敗（Dead Letter）
  deadLetters: () => get<DeadLettersResponse>(`/api/dead-letters`),

  // マッピング（正規化キー対応表）
  mappings: () => get<MappingsResponse>(`/api/mappings`),
  downloadMappingsCsv: () => downloadFile(`/api/mappings.csv`, "logseeker_mappings.csv"),

  // 管理
  adminOverview: () => get<AdminOverview>(`/api/admin/overview`),

  // 認証・ユーザー・監査
  authStatus: () => get<AuthStatus>(`/api/auth/status`),
  login: (username: string, password: string) =>
    post<{ token: string; user: AuthUser }>(`/api/auth/login`, { username, password }),
  logout: () => post<{ ok: boolean }>(`/api/auth/logout`, {}),
  listUsers: () => get<AuthUser[]>(`/api/users`),
  createUser: (b: { username: string; display_name?: string; role: Role; email?: string; password?: string }) =>
    post<CreateUserResult>(`/api/users`, b),
  updateUser: (id: number, b: { display_name?: string; role?: Role; enabled?: boolean; password?: string }) =>
    put<AuthUser>(`/api/users/${id}`, b),
  deleteUser: (id: number) => del<{ ok: boolean }>(`/api/users/${id}`),
  toggleAuth: (enabled: boolean) => post<{ ok: boolean; auth_required: boolean }>(`/api/auth/require`, { enabled }),
  audit: (limit = 500) => get<AuditResponse>(`/api/audit?limit=${limit}`),
  downloadAuditCsv: () => downloadFile(`/api/audit.csv`, "logseeker_audit.csv"),
  downloadAuditJson: () => downloadFile(`/api/audit.json`, "logseeker_audit.json"),
  getSso: () => get<SsoStatus>(`/api/sso`),
  saveSso: (b: Partial<SsoStatus> & { client_secret?: string; enabled: boolean }) =>
    put<{ ok: boolean; note: string }>(`/api/sso`, b),

  // 通知設定（全ライセンスティアで使用可）
  notifConfig: () => get<NotificationConfig>(`/api/notifications`),
  saveNotifConfig: (cfg: NotificationConfig) => put<{ ok: boolean }>(`/api/notifications`, cfg),
  testEmail: () => post<{ ok: boolean; error?: string }>(`/api/notifications/test/email`, {}),
  testSlack: () => post<{ ok: boolean; error?: string }>(`/api/notifications/test/slack`, {}),
  notifyNow: () => post<{ hits: number; result: object }>(`/api/notifications/send-now`, {}),
};
