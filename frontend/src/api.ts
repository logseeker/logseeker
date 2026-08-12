import type {
  AdminOverview, AssetRow, AssignableUser, AuditResponse, AuthStatus, AuthUser, CaseCommentItem,
  CaseDetail, CaseRow, CorrelationResponse, Count, CreateUserResult, CustomRule, CustomRulesResponse,
  ColumnSets, DashboardOverview, DashboardTimeline, DeadLettersResponse, EntityDetail, EntityRow, EventDetailData, EventRow,
  EventsClassesResponse, EventsFields, EventsSearchResponse, FacetResponse, FieldInfo, FilterState, HistogramResponse,
  IncidentActivityItem, IncidentDetail, IncidentResponseActionTypeDef, IncidentRow, IncidentStatusDef,
  IngestStatus, IngestVolume, IocFeedsInfo, IpRestrictStatus, LicenseInfo, MappingsResponse, NotificationConfig,
  ReleaseItem, Role, RuleDef, RuleHit, SsoStatus, Verdict,
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

// Events/Dashboardの検索条件（v12 A案）。絞り込みはTaxonomy KEY・Class・期間・全文のみ。
export interface EventQuery {
  class_value?: string | null;
  q?: string;
  start?: string;
  end?: string;
  field?: string;        // 個別Taxonomyフィールドでの単純絞り込み（normalize-mapping.md §7.2）
  value?: string;
  rep_value?: string;    // 代表値グループでの絞り込み（同 §7.1：集計時と同じ優先順位のOR条件）
}

function eq(qy: EventQuery, extra: Record<string, string | number> = {}): string {
  const p = new URLSearchParams();
  const put_ = (k: string, v: unknown) => { if (v !== undefined && v !== null && v !== "") p.set(k, String(v)); };
  put_("class_value", qy.class_value);
  put_("q", qy.q); put_("start", qy.start); put_("end", qy.end);
  put_("field", qy.field); put_("value", qy.value); put_("rep_value", qy.rep_value);
  Object.entries(extra).forEach(([k, v]) => put_(k, v));
  const s = p.toString();
  return s ? `?${s}` : "";
}

export const api = {
  // ---- Events / Dashboard（v12 A案。値はpayloadのTaxonomy KEYからのみ取得する）----
  eventsFields: (class_value?: string | null) =>
    get<EventsFields>(`/api/events/fields${class_value ? `?class_value=${ev(class_value)}` : ""}`),
  columnSets: (class_value?: string | null) =>
    get<ColumnSets>(`/api/events/column-sets${class_value ? `?class_value=${ev(class_value)}` : ""}`),
  saveColumns: (class_value: string | null, columns: string[]) =>
    put<{ ok: boolean }>(`/api/events/columns`, { source_type: class_value, columns }),
  saveColumnSet: (name: string, class_value: string | null, columns: string[]) =>
    put<{ ok: boolean; name: string }>(`/api/events/column-sets`, { name, class_value, columns }),
  deleteColumnSet: (name: string, class_value?: string | null) =>
    del<{ ok: boolean }>(`/api/events/column-sets/${ev(name)}${class_value ? `?class_value=${ev(class_value)}` : ""}`),

  eventsClasses: (qy: EventQuery = {}) => get<EventsClassesResponse>(`/api/events/classes${eq(qy)}`),
  setEventsClasses: (b: { hidden: string[]; order: string[]; pinned: string[] }) =>
    put<{ ok: boolean }>(`/api/events/classes`, b),

  searchEvents: (qy: EventQuery, columns: string[], limit = 50, offset = 0) =>
    get<EventsSearchResponse>(`/api/events/search${eq(qy, { columns: columns.join(","), limit, offset })}`),
  eventsHistogram: (qy: EventQuery, buckets = 60) =>
    get<HistogramResponse>(`/api/events/histogram${eq(qy, { buckets })}`),
  eventsFacet: (qy: EventQuery, field: string, top = 20) =>
    get<FacetResponse>(`/api/events/facet${eq(qy, { field, top })}`),
  eventDetail: (id: number) => get<EventDetailData>(`/api/events/detail/${id}`),
  exportEvents: (qy: EventQuery, columns: string[], format: "csv" | "json") =>
    downloadFile(`/api/events/export${eq(qy, { columns: columns.join(","), format })}`,
      `logseeker_events.${format}`),
  dashboardTimeline: (interval: "hour" | "day", date: string, class_value?: string | null) =>
    get<DashboardTimeline>(`/api/dashboard/timeline?interval=${interval}&date=${ev(date)}` +
      (class_value ? `&class_value=${ev(class_value)}` : "")),
  dashboardOverview: (qy: EventQuery, fields: string[] = [], extraFields: string[] = []) =>
    get<DashboardOverview>(`/api/dashboard/overview${eq(qy, {
      ...(fields.length ? { fields: fields.join(",") } : {}),
      ...(extraFields.length ? { extra_fields: extraFields.join(",") } : {}),
    })}`),

  // ---- 他画面（ログソース/フィールド/ホスト・ドメイン/ルール）が使う既存API（無変更）----
  groupby: (f: FilterState, field: string, top = 20) =>
    get<Count[]>(`/api/groupby${qs(f, { field, top })}`),
  fields: (f: FilterState) => get<FieldInfo[]>(`/api/fields${qs(f)}`),

  // MVP3: エンティティ & 相関
  entities: (type?: string, q?: string) =>
    get<EntityRow[]>(`/api/entities?${new URLSearchParams({ ...(type ? { type } : {}), ...(q ? { q } : {}) })}`),
  entity: (type: string, value: string) => get<EntityDetail>(`/api/entity?type=${ev(type)}&value=${ev(value)}`),
  entityEvents: (type: string, value: string) => get<EventRow[]>(`/api/entity/events?type=${ev(type)}&value=${ev(value)}`),
  related: (id: number) => get<{ keys: { entity_type: string; entity_value: string }[]; items: EventRow[] }>(`/api/events/${id}/related`),

  // 資産（アセット）：ローカルIPは自動判定、グローバルIPは手動登録
  assets: () => get<AssetRow[]>(`/api/assets`),
  createAsset: (b: { ip: string; label?: string; description?: string; display_name?: string }) =>
    post<{ id: number; ip: string; ip_version: string; label: string | null; description: string | null; display_name: string | null }>(`/api/assets`, b),
  updateAsset: (id: number, b: { label?: string; description?: string; display_name?: string }) =>
    put<{ id: number; ip: string; ip_version: string; label: string | null; description: string | null; display_name: string | null }>(`/api/assets/${id}`, b),
  deleteAsset: (id: number) => del<{ ok: boolean }>(`/api/assets/${id}`),
  setLocalAssetDisplayName: (ip: string, display_name: string | null) =>
    put<{ id: number; ip: string; ip_version: string; label: string | null; description: string | null; display_name: string | null }>(`/api/assets/local/${ip}`, { display_name }),

  setEventResolved: (id: number, resolved: boolean) =>
    put<{ ok: boolean; resolved: boolean }>(`/api/events/${id}/resolved`, { resolved }),

  // ケース（設計書v4 3章）：複数イベントを束ねる調査ワークスペース。ステータス・判定結果・
  // 担当者は持たず、インシデントへの「昇格」概念も無い（インシデントとは完全に独立）
  cases: () => get<CaseRow[]>(`/api/cases`),
  createCase: (title: string) => post<{ id: number }>(`/api/cases`, { title }),
  case: (id: number) => get<CaseDetail>(`/api/cases/${id}`),
  updateCaseTitle: (id: number, title: string) => put<{ ok: boolean; title: string }>(`/api/cases/${id}`, { title }),
  addCaseEvent: (id: number, b: { event_id: number; note?: string }) =>
    post<{ ok: boolean }>(`/api/cases/${id}/events`, b),
  updateCaseEventNote: (id: number, eventId: number, note: string | null) =>
    put<{ ok: boolean }>(`/api/cases/${id}/events/${eventId}`, { note }),
  removeCaseEvent: (id: number, eventId: number) => del<{ ok: boolean }>(`/api/cases/${id}/events/${eventId}`),
  caseComments: (id: number) => get<CaseCommentItem[]>(`/api/cases/${id}/comments`),
  addCaseComment: (id: number, body: string) => post<{ id: number }>(`/api/cases/${id}/comments`, { body }),

  // インシデント（設計書v4 4章）：「注目」イベント単体から直接生成される、アラートと1:1の確定事案
  createIncidentFromEvent: (eventId: number) => post<{ id: number }>(`/api/events/${eventId}/incident`, {}),
  incidents: () => get<IncidentRow[]>(`/api/incidents`),
  incident: (id: number) => get<IncidentDetail>(`/api/incidents/${id}`),
  updateIncidentStatus: (id: number, status_id: number) =>
    put<{ ok: boolean; status_id: number; assignee_user_id: number | null }>(`/api/incidents/${id}/status`, { status_id }),
  updateIncidentAssignee: (id: number, assignee_user_id: number | null) =>
    put<{ ok: boolean; assignee_user_id: number | null }>(`/api/incidents/${id}/assignee`, { assignee_user_id }),
  updateIncidentVerdict: (id: number, verdict: Verdict) =>
    put<{ ok: boolean; verdict: string }>(`/api/incidents/${id}/verdict`, { verdict }),
  addIncidentComment: (id: number, body: string) =>
    post<{ id: number }>(`/api/incidents/${id}/comments`, { body }),
  addIncidentResponseAction: (id: number, b: { action_type_id: number; detail?: string }) =>
    post<{ id: number }>(`/api/incidents/${id}/response-actions`, b),
  incidentActivity: (id: number) => get<IncidentActivityItem[]>(`/api/incidents/${id}/activity`),
  incidentAssignableUsers: () => get<AssignableUser[]>(`/api/incident-assignable-users`),

  // ステータスマスタ（sysadmin以上のみ追加・非表示化）
  incidentStatuses: (showHidden = false) =>
    get<IncidentStatusDef[]>(`/api/incident-statuses${showHidden ? "?show_hidden=true" : ""}`),
  createIncidentStatus: (name: string) => post<IncidentStatusDef>(`/api/incident-statuses`, { name }),
  setIncidentStatusVisibility: (id: number, is_visible: boolean) =>
    put<IncidentStatusDef>(`/api/incident-statuses/${id}/visibility`, { is_visible }),

  // 対応アクション種別マスタ（sysadmin以上のみ追加・非表示化）
  responseActionTypes: (showHidden = false) =>
    get<IncidentResponseActionTypeDef[]>(`/api/incident-response-action-types${showHidden ? "?show_hidden=true" : ""}`),
  createResponseActionType: (name: string) =>
    post<IncidentResponseActionTypeDef>(`/api/incident-response-action-types`, { name }),
  setResponseActionTypeVisibility: (id: number, is_visible: boolean) =>
    put<IncidentResponseActionTypeDef>(`/api/incident-response-action-types/${id}/visibility`, { is_visible }),

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
  ingestVolume: (params?: { hourlyDate?: string; dailyStart?: string; dailyEnd?: string }) => {
    const p = new URLSearchParams();
    if (params?.hourlyDate) p.set("hourly_date", params.hourlyDate);
    if (params?.dailyStart) p.set("daily_start", params.dailyStart);
    if (params?.dailyEnd) p.set("daily_end", params.dailyEnd);
    const s = p.toString();
    return get<IngestVolume>(`/api/admin/ingest-volume${s ? `?${s}` : ""}`);
  },

  // 認証・ユーザー・監査
  authStatus: () => get<AuthStatus>(`/api/auth/status`),
  login: (username: string, password: string) =>
    post<{ token: string; user: AuthUser }>(`/api/auth/login`, { username, password }),
  adminLogin: (username: string, password: string) =>
    post<{ token: string; user: AuthUser }>(`/api/auth/admin-login`, { username, password }),
  adminStatus: () => get<{ user: AuthUser | null }>(`/api/auth/admin-status`),
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
  getIpRestrict: () => get<IpRestrictStatus>(`/api/admin/ip-restrict`),
  saveIpRestrict: (b: { enabled: boolean; allowlist: { cidr: string; label: string }[] }) =>
    put<IpRestrictStatus>(`/api/admin/ip-restrict`, b),

  // 通知設定（全ライセンスティアで使用可）
  notifConfig: () => get<NotificationConfig>(`/api/notifications`),
  saveNotifConfig: (cfg: NotificationConfig) => put<{ ok: boolean }>(`/api/notifications`, cfg),
  testEmail: () => post<{ ok: boolean; error?: string }>(`/api/notifications/test/email`, {}),
  testSlack: () => post<{ ok: boolean; error?: string }>(`/api/notifications/test/slack`, {}),
  notifyNow: () => post<{ hits: number; result: object }>(`/api/notifications/send-now`, {}),

  // お知らせ・更新履歴（GitHub Releases。バックエンドでキャッシュ済み）
  changelog: () => get<ReleaseItem[]>(`/api/changelog`),
  // 既読状態（ログイン中はDB、未ログインはフロント側でlocalStorageにフォールバック）
  getDismissedRelease: () => get<{ last_dismissed_release: string | null }>(`/api/changelog/dismissed`),
  setDismissedRelease: (tag_name: string) => put<{ ok: boolean }>(`/api/changelog/dismissed`, { tag_name }),

};
