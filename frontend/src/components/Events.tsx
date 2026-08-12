import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api } from "../api";
import type { EventQuery } from "../api";
import { fmtTime } from "../labels";
import { EventDetail } from "./EventDetail";
import { adviseForEvent } from "../advice";
import type {
  AuthStatus, ColumnSets, EventsClass, EventSearchRow, EventsSearchResponse,
  HistogramResponse, Screen, TaxonomyField,
} from "../types";

const ROW_CHOICES = [50, 100, 500, 1000];
// 脅威フィルタ（判定はbackendのTaxonomy KEYベース。_threat_clause参照）
const THREATS = [
  { value: "", label: "指定なし" },
  { value: "any", label: "いずれか" },
  { value: "ioc", label: "既知の脅威(IOC)一致" },
  { value: "sensitive_path", label: "機微パスへのアクセス" },
  { value: "web_scan", label: "Webスキャンの兆候" },
  { value: "auth_fail", label: "認証失敗" },
  { value: "root_ssh", label: "特権ユーザーへの試行" },
];
// 対応策の判定に使うTaxonomy KEY（一覧に出していなくても取得する）
const ADVICE_KEYS = ["category", "result", "severity", "username", "accountname",
                     "uri", "query", "statuscode", "status", "class"];
const LS_PREFIX = "logseeker_events_v3";

/** 未ログイン時のフォールバック保存先（サーバーはログイン利用者単位でしか保存しないため）。 */
function lsGet<T>(key: string, fb: T): T {
  try { const v = localStorage.getItem(`${LS_PREFIX}_${key}`); return v ? (JSON.parse(v) as T) : fb; }
  catch { return fb; }
}
function lsSet(key: string, v: unknown) {
  try { localStorage.setItem(`${LS_PREFIX}_${key}`, JSON.stringify(v)); } catch { /* noop */ }
}

const isoLocal = (iso?: string) => (iso ? iso.slice(0, 16) : "");
const toIso = (local: string) => (local ? new Date(local).toISOString() : undefined);

type Props = {
  onEntity: (type: string, value: string) => void;
  onNav: (s: Screen) => void;
  onOpenCase: (id: number) => void;
  onOpenIncident: (id: number) => void;
  auth?: AuthStatus;
  initialEventId?: number;
  /** Dashboardから遷移してきたときの初期条件 */
  initialQuery?: EventQuery;
};

export function Events({ onEntity, onNav, onOpenCase, onOpenIncident, auth, initialEventId, initialQuery }: Props) {
  const loggedIn = !!auth?.user;

  // ---- 検索条件（「検索」ボタンで確定。ドロップダウン変更では飛ばさない）----
  const [applied, setApplied] = useState<EventQuery>(() => initialQuery ?? {});
  const [draft, setDraft] = useState<EventQuery>(() => initialQuery ?? {});
  useEffect(() => { if (initialQuery) { setApplied(initialQuery); setDraft(initialQuery); } }, [initialQuery]);

  const cls = applied.class_value ?? null;

  // ---- Class ----
  const [classes, setClasses] = useState<EventsClass[]>([]);
  const loadClasses = useCallback(() => {
    api.eventsClasses({ start: applied.start, end: applied.end }).then((r) => {
      if (loggedIn) { setClasses(r.classes); return; }
      const local = lsGet("classes", { hidden: [] as string[], pinned: [] as string[], order: [] as string[] });
      const hid = new Set(local.hidden), pin = new Set(local.pinned);
      setClasses(r.classes.map((c) => ({ ...c, hidden: hid.has(c.class_value), pinned: pin.has(c.class_value) })));
    }).catch(() => setClasses([]));
  }, [loggedIn, applied.start, applied.end]);
  useEffect(loadClasses, [loadClasses]);
  const visibleClasses = classes.filter((c) => !c.hidden);
  const pinnedClasses = visibleClasses.filter((c) => c.pinned);

  // ---- 列（Taxonomy KEYのみ。実データでは決まらない）----
  const [fields, setFields] = useState<TaxonomyField[]>([]);
  const [sets, setSets] = useState<ColumnSets | null>(null);
  const [columns, setColumns] = useState<string[]>([]);
  const labelOf = useMemo(() => {
    const m = new Map(fields.map((f) => [f.key, f.label]));
    return (k: string) => m.get(k) || k;
  }, [fields]);

  const loadColumns = useCallback(() => {
    Promise.all([api.eventsFields(cls), api.columnSets(cls)]).then(([f, s]) => {
      setFields(f.keys);
      const local = lsGet<Record<string, string[]>>("columns", {});
      const saved = loggedIn ? s.columns : (local[cls ?? "__all__"] ?? null);
      setSets({ ...s, columns: saved, sets: loggedIn ? s.sets : lsGet(`sets_${cls ?? "__all__"}`, {}) });
      setColumns(saved && saved.length ? saved : f.default_columns);
    }).catch(() => { setFields([]); setColumns([]); });
  }, [cls, loggedIn]);
  useEffect(loadColumns, [loadColumns]);

  const persistColumns = (cols: string[]) => {
    setColumns(cols);
    if (loggedIn) { api.saveColumns(cls, cols).then(loadColumns).catch(() => {}); return; }
    const local = lsGet<Record<string, string[]>>("columns", {});
    local[cls ?? "__all__"] = cols;
    lsSet("columns", local);
    loadColumns();
  };

  // ---- 結果 ----
  const [rows, setRows] = useState<EventsSearchResponse | null>(null);
  const [limit, setLimit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [sel, setSel] = useState<number | null>(initialEventId ?? null);
  const [showViz, setShowViz] = useState(false);
  const [hist, setHist] = useState<HistogramResponse | null>(null);
  const [panel, setPanel] = useState<null | "columns" | "classes">(null);
  const [gear, setGear] = useState(false);
  const [showAdvice, setShowAdvice] = useState(false);

  useEffect(() => { setOffset(0); }, [applied, limit]);
  useEffect(() => {
    if (!columns.length) return;
    const need = showAdvice ? [...new Set([...columns, ...ADVICE_KEYS])] : columns;
    api.searchEvents(applied, need, limit, offset).then(setRows)
      .catch((e) => setErr((e as Error).message));
  }, [applied, columns, limit, offset, showAdvice]);
  useEffect(() => {
    if (!showViz) return;
    api.eventsHistogram(applied, 60).then(setHist).catch(() => setHist(null));
  }, [applied, showViz]);

  const pivot = (field: string, value: unknown) => {
    const q = { ...applied, field, value: String(value ?? "") };
    setApplied(q); setDraft(q);
  };
  const clearPivot = () => {
    const q = { ...applied, field: undefined, value: undefined, rep_value: undefined };
    setApplied(q); setDraft(q);
  };

  const chips: { label: string; clear: () => void }[] = [];
  if (applied.class_value) chips.push({ label: `Class: ${applied.class_value}`,
    clear: () => { const q = { ...applied, class_value: undefined }; setApplied(q); setDraft(q); } });
  if (applied.field) chips.push({ label: `${labelOf(applied.field)}: ${applied.value}`, clear: clearPivot });
  if (applied.rep_value) chips.push({ label: `ドメイン/ホスト: ${applied.rep_value}`, clear: clearPivot });
  if (applied.source) chips.push({ label: `ログソース: ${applied.source}`,
    clear: () => { const q = { ...applied, source: undefined }; setApplied(q); setDraft(q); } });
  if (applied.threat) chips.push({ label: `脅威: ${THREATS.find((t) => t.value === applied.threat)?.label ?? applied.threat}`,
    clear: () => { const q = { ...applied, threat: undefined }; setApplied(q); setDraft(q); } });
  if (applied.attention) chips.push({ label: "注目のみ",
    clear: () => { const q = { ...applied, attention: undefined }; setApplied(q); setDraft(q); } });
  if (applied.q) chips.push({ label: `検索 "${applied.q}"`,
    clear: () => { const q = { ...applied, q: undefined }; setApplied(q); setDraft(q); } });

  return (
    <div className="d-flex align-items-start" style={{ gap: "1rem" }}>
      <div style={{ flex: sel != null ? "1 1 60%" : "1 1 100%", minWidth: 0 }}>
        {err && <div className="alert alert-danger">{err}</div>}

        {/* ===== 検索バー ===== */}
        <div className="card mb-2">
          <div className="card-body py-2">
            <div className="d-flex gap-2 align-items-center mb-2">
              <input className="form-control" placeholder="全文検索（payload全体を対象）"
                value={draft.q ?? ""} onChange={(e) => setDraft({ ...draft, q: e.target.value })}
                onKeyDown={(e) => e.key === "Enter" && setApplied(draft)} />
              <button className="btn btn-primary" onClick={() => setApplied(draft)}>検索</button>
            </div>
            <div className="d-flex flex-wrap gap-2 align-items-end">
              <div>
                <label className="form-label mb-0 small">Class</label>
                <div className="d-flex gap-1">
                  <select className="form-select form-select-sm" style={{ width: 190 }}
                    value={draft.class_value ?? ""}
                    onChange={(e) => setDraft({ ...draft, class_value: e.target.value || undefined })}>
                    <option value="">すべて</option>
                    {visibleClasses.map((c) => (
                      <option key={c.class_value} value={c.class_value}>{c.class_value} ({c.count})</option>
                    ))}
                  </select>
                  <button className="btn btn-sm btn-ghost-secondary" onClick={() => setPanel("classes")}>設定</button>
                </div>
              </div>
              <div>
                <label className="form-label mb-0 small">開始</label>
                <input type="datetime-local" className="form-control form-control-sm"
                  value={isoLocal(draft.start)} onChange={(e) => setDraft({ ...draft, start: toIso(e.target.value) })} />
              </div>
              <div>
                <label className="form-label mb-0 small">終了</label>
                <input type="datetime-local" className="form-control form-control-sm"
                  value={isoLocal(draft.end)} onChange={(e) => setDraft({ ...draft, end: toIso(e.target.value) })} />
              </div>
              <div>
                <label className="form-label mb-0 small">脅威</label>
                <select className="form-select form-select-sm" style={{ width: 190 }}
                  value={applied.threat ?? ""}
                  onChange={(e) => { const q = { ...applied, threat: e.target.value || undefined }; setApplied(q); setDraft(q); }}>
                  {THREATS.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                </select>
              </div>
              <div className="form-check ms-2">
                <input className="form-check-input" type="checkbox" id="attention" checked={!!applied.attention}
                  onChange={(e) => { const q = { ...applied, attention: e.target.checked || undefined }; setApplied(q); setDraft(q); }} />
                <label className="form-check-label small" htmlFor="attention">注目のみ</label>
              </div>
              <div className="form-check">
                <input className="form-check-input" type="checkbox" id="viz" checked={showViz}
                  onChange={(e) => setShowViz(e.target.checked)} />
                <label className="form-check-label small" htmlFor="viz">視覚化</label>
              </div>

              <div className="ms-auto d-flex align-items-end gap-2">
                <div>
                  <label className="form-label mb-0 small">列セット</label>
                  <select className="form-select form-select-sm" style={{ width: 190 }} value=""
                    onChange={(e) => { const s = sets?.sets?.[e.target.value]; if (s) persistColumns(s); }}>
                    <option value="">{columns.length}列を表示中</option>
                    {Object.keys(sets?.sets ?? {}).map((n) => <option key={n} value={n}>{n}</option>)}
                  </select>
                </div>
                <div className="position-relative">
                  <button className="btn btn-sm btn-outline-secondary" onClick={() => setGear(!gear)} title="表の設定">⚙</button>
                  {gear && (
                    <div className="card position-absolute end-0 mt-1" style={{ zIndex: 30, minWidth: 210 }}>
                      <div className="list-group list-group-flush">
                        <button className="list-group-item list-group-item-action"
                          onClick={() => { setGear(false); setPanel("columns"); }}>列をカスタマイズ</button>
                        <button className="list-group-item list-group-item-action"
                          onClick={() => { setGear(false); persistColumns(sets?.default_columns ?? []); }}>列を既定に戻す</button>
                        <button className="list-group-item list-group-item-action"
                          onClick={() => { setGear(false); api.exportEvents(applied, columns, "csv").catch((e) => setErr((e as Error).message)); }}>CSVで出力</button>
                        <button className="list-group-item list-group-item-action"
                          onClick={() => { setGear(false); api.exportEvents(applied, columns, "json").catch((e) => setErr((e as Error).message)); }}>JSONで出力</button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {pinnedClasses.length > 0 && (
              <div className="d-flex flex-wrap gap-1 mt-2">
                {pinnedClasses.map((c) => (
                  <button key={c.class_value}
                    className={`btn btn-sm ${applied.class_value === c.class_value ? "btn-primary" : "btn-outline-secondary"}`}
                    onClick={() => { const q = { ...applied, class_value: c.class_value }; setApplied(q); setDraft(q); }}>
                    {c.class_value} <span className="text-secondary">({c.count})</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {chips.length > 0 && (
          <div className="d-flex flex-wrap gap-1 mb-2 align-items-center">
            <span className="text-secondary small">絞り込み:</span>
            {chips.map((c, i) => (
              <span key={i} role="button" className="badge bg-blue text-white" onClick={c.clear}>{c.label} ✕</span>
            ))}
          </div>
        )}

        {/* 旧Events画面から引き続き提供する操作 */}
        <div className="d-flex flex-wrap align-items-center gap-2 mb-2">
          <button className="btn btn-sm btn-outline-primary" onClick={() => setPanel("columns")}>
            ⚙ 列を編集（現在{columns.length}列）
          </button>
          <button className={`btn btn-sm ${showAdvice ? "btn-warning" : "btn-outline-warning"}`}
            onClick={() => setShowAdvice(!showAdvice)} title="危険度と対応策を一覧に表示する">
            ⚒ 対応策を{showAdvice ? "隠す" : "表示"}
          </button>
          <div className="btn-group btn-group-sm ms-auto">
            <button className="btn btn-outline-secondary"
              onClick={() => api.exportEvents(applied, columns, "csv").catch((e) => setErr((e as Error).message))}>↓ CSV</button>
            <button className="btn btn-outline-secondary"
              onClick={() => api.exportEvents(applied, columns, "json").catch((e) => setErr((e as Error).message))}>↓ JSON</button>
          </div>
          <button className="btn btn-sm btn-outline-danger" onClick={() => onNav("rules")}
            title="ルール / 注意喚起の画面へ">♡ 攻撃・注意喚起を見る</button>
        </div>

        {showViz && hist && (
          <div className="card mb-2"><div className="card-body py-2">
            <ReactECharts style={{ height: 120 }} option={{
              grid: { left: 40, right: 10, top: 10, bottom: 20 },
              tooltip: { trigger: "axis" },
              xAxis: { type: "category", data: hist.buckets.map((b) => fmtTime(b.t)), axisLabel: { fontSize: 9 } },
              yAxis: { type: "value" },
              series: [{ type: "bar", data: hist.buckets.map((b) => b.count) }],
            }} />
          </div></div>
        )}

        <div className="card">
          <div className="card-body py-2 d-flex align-items-center">
            <span className="text-secondary small">
              {rows ? `${rows.total.toLocaleString()} 件の結果が見つかりました` : "検索中..."}
            </span>
            <span className="ms-auto text-secondary small">
              表示列は taxonomy.md のTaxonomy KEYから選択します（{fields.length}件）
            </span>
          </div>
          <div className="table-responsive">
            <table className="table table-sm table-vcenter card-table">
              <thead>
                <tr>
                  <th style={{ width: 70 }}>対応</th>
                  {/* Classは受信payloadのフィールドではなくLogSeeker管理情報。行の class_value を
                      そのまま出す（右パネルのバッジと必ず同じ値になるようにする）。 */}
                  <th className="text-nowrap">Class</th>
                  {columns.map((k) => (
                    <th key={k} className="text-nowrap">
                      {labelOf(k)}
                      <span className="text-secondary ms-1 small">{k}</span>
                      <button className="btn btn-sm btn-ghost-secondary p-0 ms-1" title="この列を非表示"
                        onClick={() => persistColumns(columns.filter((c) => c !== k))}>✕</button>
                    </th>
                  ))}
                  {columns.length === 0 && <th className="text-secondary">列が選択されていません（⚙→列をカスタマイズ）</th>}
                  {showAdvice && <th className="text-nowrap">対応策</th>}
                </tr>
              </thead>
              <tbody>
                {(rows?.items ?? []).map((r: EventSearchRow) => (
                  <tr key={r.id} className={sel === r.id ? "table-active" : ""} role="button"
                    onClick={() => setSel(r.id)}>
                    <td onClick={(e) => e.stopPropagation()}>
                      <div className="form-check form-switch mb-0">
                        <input className="form-check-input" type="checkbox" checked={r.resolved}
                          onChange={() => api.setEventResolved(r.id, !r.resolved)
                            .then(() => api.searchEvents(applied, columns, limit, offset).then(setRows))} />
                      </div>
                    </td>
                    <td className="text-nowrap">
                      <span className={`badge ${r.class_value === "unknown" ? "bg-secondary-lt" : "bg-blue-lt"}`}>
                        {r.class_value}
                      </span>
                    </td>
                    {columns.map((k) => {
                      const v = r.values[k];
                      const s = v === null || v === undefined || v === "" ? "" : String(v);
                      return (
                        <td key={k} className="text-truncate" style={{ maxWidth: 240 }} title={s}>
                          {s ? (
                            <span className="d-inline-flex align-items-center gap-1">
                              <span className="text-truncate">{s}</span>
                              <button className="btn btn-sm btn-ghost-secondary p-0" title={`${labelOf(k)} = ${s} で絞り込む`}
                                onClick={(e) => { e.stopPropagation(); pivot(k, s); }}>⌄</button>
                            </span>
                          ) : <span className="text-secondary">-</span>}
                        </td>
                      );
                    })}
                    {showAdvice && <AdviceCell row={r} />}
                  </tr>
                ))}
                {rows && rows.items.length === 0 && (
                  <tr><td colSpan={columns.length + (showAdvice ? 3 : 2)} className="text-center text-secondary py-4">
                    該当するイベントがありません
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="card-footer d-flex align-items-center gap-2">
            <span className="text-secondary small">rows</span>
            {ROW_CHOICES.map((n) => (
              <button key={n} className={`btn btn-sm ${limit === n ? "btn-primary" : "btn-ghost-secondary"}`}
                onClick={() => setLimit(n)}>{n}</button>
            ))}
            <span className="ms-auto text-secondary small">
              {rows ? `${rows.items.length ? offset + 1 : 0}〜${offset + rows.items.length}` : ""}
            </span>
            <div className="btn-group">
              <button className="btn btn-sm" disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - limit))}>前へ</button>
              <button className="btn btn-sm" disabled={!rows || offset + limit >= rows.total}
                onClick={() => setOffset(offset + limit)}>次へ</button>
            </div>
          </div>
        </div>
      </div>

      {sel != null && (
        <div style={{ flex: "0 0 38%", maxWidth: 540, position: "sticky", top: 8 }}>
          <EventDetail id={sel} variant="panel" onClose={() => setSel(null)} onPivot={pivot}
            onEntity={onEntity} onOpenCase={onOpenCase} onOpenIncident={onOpenIncident} />
        </div>
      )}

      {panel === "columns" && (
        <ColumnsPanel fields={fields} columns={columns} sets={sets?.sets ?? {}}
          onApply={persistColumns}
          onSaveAs={(name, cols) => {
            if (loggedIn) return api.saveColumnSet(name, cls, cols).then(loadColumns);
            const s = lsGet<Record<string, string[]>>(`sets_${cls ?? "__all__"}`, {});
            s[name] = cols; lsSet(`sets_${cls ?? "__all__"}`, s); loadColumns();
            return Promise.resolve();
          }}
          onDeleteSet={(name) => {
            if (loggedIn) return api.deleteColumnSet(name, cls).then(loadColumns);
            const s = lsGet<Record<string, string[]>>(`sets_${cls ?? "__all__"}`, {});
            delete s[name]; lsSet(`sets_${cls ?? "__all__"}`, s); loadColumns();
            return Promise.resolve();
          }}
          onReset={() => persistColumns(sets?.default_columns ?? [])}
          onClose={() => setPanel(null)} />
      )}
      {panel === "classes" && (
        <ClassesPanel classes={classes} onClose={() => setPanel(null)}
          onSave={(hidden, pinned, order) => {
            if (loggedIn) return api.setEventsClasses({ hidden, pinned, order }).then(loadClasses);
            lsSet("classes", { hidden, pinned, order }); loadClasses();
            return Promise.resolve();
          }} />
      )}
    </div>
  );
}

/** 対応策セル。危険度と推奨アクションを advice.ts（rules.pyと整合）で導く。
 * 判定に使う値はTaxonomy KEYから取るため、列に出していなくても算出できる。 */
function AdviceCell({ row }: { row: EventSearchRow }) {
  const v = row.values as Record<string, unknown>;
  const str = (k: string) => (v[k] == null ? null : String(v[k]));
  const a = adviseForEvent({
    category: str("category"), result: str("result"), severity: str("severity"),
    username: str("username"), accountname: str("accountname"),
    uri: str("uri"), query: str("query"),
    statuscode: str("statuscode"), status: str("status"), class: row.class_value,
  });
  if (!a) return <td><span className="text-secondary">-</span></td>;
  return (
    <td style={{ minWidth: 220 }}>
      <span className={`badge ${a.level === "danger" ? "bg-red-lt" : "bg-yellow-lt"}`} title={a.rec}>
        {a.title}
      </span>
      <div className="d-flex flex-wrap gap-1 mt-1">
        {a.actions.map((x) => <span key={x} className="badge bg-secondary-lt">{x}</span>)}
      </div>
    </td>
  );
}

/** 列のカスタマイズ：1本のリストで、⣿をドラッグして並び替え、チェックで表示/非表示。 */
function ColumnsPanel({ fields, columns, sets, onApply, onSaveAs, onDeleteSet, onReset, onClose }: {
  fields: TaxonomyField[]; columns: string[]; sets: Record<string, string[]>;
  onApply: (cols: string[]) => void;
  onSaveAs: (name: string, cols: string[]) => Promise<void>;
  onDeleteSet: (name: string) => Promise<void>;
  onReset: () => void; onClose: () => void;
}) {
  // 選択中の列を上に、残りのTaxonomy KEYを推奨→KEY名順で下に並べる
  const [order, setOrder] = useState<string[]>(() => {
    const rest = fields.map((f) => f.key).filter((k) => !columns.includes(k));
    return [...columns, ...rest];
  });
  const [checked, setChecked] = useState<Set<string>>(new Set(columns));
  const [q, setQ] = useState("");
  const [name, setName] = useState("");
  const from = useRef<number | null>(null);
  const byKey = useMemo(() => new Map(fields.map((f) => [f.key, f])), [fields]);

  const selected = order.filter((k) => checked.has(k));
  const shown = order.filter((k) => {
    if (!q) return true;
    const f = byKey.get(k);
    return k.toLowerCase().includes(q.toLowerCase()) || (f?.label ?? "").toLowerCase().includes(q.toLowerCase());
  });

  const drop = (to: number) => {
    const f = from.current; from.current = null;
    if (f === null || f === to) return;
    setOrder((p) => { const n = [...p]; const [m] = n.splice(f, 1); n.splice(to, 0, m); return n; });
  };

  return (
    <>
      <div style={{ position: "fixed", inset: 0, zIndex: 1040, background: "rgba(0,0,0,.15)" }} onClick={onClose} />
      <div className="card" style={{ position: "fixed", top: 0, right: 0, bottom: 0, width: 440, zIndex: 1050, borderRadius: 0 }}>
        <div className="card-header">
          <h3 className="card-title mb-0">列をカスタマイズ</h3>
          <button className="btn-close ms-auto" onClick={onClose} />
        </div>
        <div className="card-body" style={{ overflowY: "auto" }}>
          <p className="text-secondary small">
            docs/taxonomy.md の全Taxonomy KEY（{fields.length}件）から選べます。受信データの有無では
            選択肢は変わりません。★はこのClassの参考例に載っているKEYです。
          </p>
          <input className="form-control form-control-sm mb-2" placeholder="フィールド名・表示名で検索"
            value={q} onChange={(e) => setQ(e.target.value)} />
          <div className="text-secondary small mb-1">表示中 {selected.length} 列</div>
          <div className="list-group" style={{ maxHeight: "48vh", overflowY: "auto" }}>
            {shown.map((k) => {
              const i = order.indexOf(k);
              const f = byKey.get(k);
              return (
                <div key={k} draggable className="list-group-item d-flex align-items-center gap-2 py-1"
                  onDragStart={() => { from.current = i; }} onDragOver={(e) => e.preventDefault()}
                  onDrop={() => drop(i)} style={{ cursor: "grab" }}>
                  <span className="text-secondary" aria-hidden>⣿</span>
                  <input className="form-check-input mt-0" type="checkbox" checked={checked.has(k)}
                    onChange={() => setChecked((p) => { const n = new Set(p); n.has(k) ? n.delete(k) : n.add(k); return n; })} />
                  <span className="flex-fill">
                    {f?.recommended && <span className="text-warning me-1">★</span>}
                    {f?.label ? <>{f.label} <span className="text-secondary small">({k})</span></> : k}
                  </span>
                  <span className="text-secondary small">{f?.type}</span>
                </div>
              );
            })}
          </div>

          <hr />
          <div className="d-flex gap-1">
            <input className="form-control form-control-sm" placeholder="列セット名を付けて保存"
              value={name} onChange={(e) => setName(e.target.value)} />
            <button className="btn btn-sm btn-outline-primary" disabled={!name.trim() || !selected.length}
              onClick={() => onSaveAs(name.trim(), selected).then(() => setName(""))}>保存</button>
          </div>
          {Object.keys(sets).length > 0 && (
            <div className="list-group list-group-flush mt-2">
              {Object.entries(sets).map(([n, cols]) => (
                <div key={n} className="list-group-item px-0 py-1 d-flex align-items-center">
                  <button className="btn btn-sm btn-link p-0" onClick={() => { setChecked(new Set(cols)); setOrder([...cols, ...order.filter((k) => !cols.includes(k))]); }}>
                    {n}<span className="text-secondary ms-1">({cols.length}列)</span>
                  </button>
                  <button className="btn btn-sm btn-ghost-danger ms-auto p-0" onClick={() => onDeleteSet(n)}>削除</button>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="card-footer d-flex justify-content-between">
          <button className="btn btn-outline-secondary" onClick={() => { onReset(); onClose(); }}>既定に戻す</button>
          <button className="btn btn-primary" onClick={() => { onApply(selected); onClose(); }}>適用</button>
        </div>
      </div>
    </>
  );
}

/** Classの表示/非表示・並び順・クイックボタン（既定はクイックボタン0件＝何も出さない）。 */
function ClassesPanel({ classes, onSave, onClose }: {
  classes: EventsClass[];
  onSave: (hidden: string[], pinned: string[], order: string[]) => Promise<void>;
  onClose: () => void;
}) {
  const [order, setOrder] = useState(classes.map((c) => c.class_value));
  const [hidden, setHidden] = useState(new Set(classes.filter((c) => c.hidden).map((c) => c.class_value)));
  const [pinned, setPinned] = useState(new Set(classes.filter((c) => c.pinned).map((c) => c.class_value)));
  const byKey = new Map(classes.map((c) => [c.class_value, c]));
  const move = (i: number, d: -1 | 1) => setOrder((p) => {
    const n = [...p], j = i + d;
    if (j < 0 || j >= n.length) return p;
    [n[i], n[j]] = [n[j], n[i]]; return n;
  });
  return (
    <>
      <div className="modal-backdrop show" style={{ position: "fixed", inset: 0, zIndex: 1040 }} onClick={onClose} />
      <div className="modal d-block" style={{ position: "fixed", inset: 0, zIndex: 1050, overflowY: "auto" }}>
        <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">Class表示設定</h5>
              <button className="btn-close" onClick={onClose} />
            </div>
            <div className="modal-body">
              <p className="text-secondary small">
                Class名は受信JSONの <code>class</code> VALUE です（固定マスターは持ちません）。
                「表示」を外すとドロップダウンから消え、「クイック」に付けると検索バーの下にボタンが出ます。
              </p>
              <div className="list-group" style={{ maxHeight: 380, overflowY: "auto" }}>
                {order.map((c, i) => (
                  <div key={c} className="list-group-item d-flex align-items-center gap-2">
                    <div className="form-check mb-0">
                      <input className="form-check-input" type="checkbox" checked={!hidden.has(c)}
                        onChange={() => setHidden((p) => { const n = new Set(p); n.has(c) ? n.delete(c) : n.add(c); return n; })} />
                      <label className="form-check-label">{c} <span className="text-secondary small">({byKey.get(c)?.count ?? 0})</span></label>
                    </div>
                    <div className="form-check mb-0 ms-auto">
                      <input className="form-check-input" type="checkbox" checked={pinned.has(c)} disabled={hidden.has(c)}
                        onChange={() => setPinned((p) => { const n = new Set(p); n.has(c) ? n.delete(c) : n.add(c); return n; })} />
                      <label className="form-check-label small">クイック</label>
                    </div>
                    <span className="btn-group btn-group-sm">
                      <button className="btn btn-sm" disabled={i === 0} onClick={() => move(i, -1)}>↑</button>
                      <button className="btn btn-sm" disabled={i === order.length - 1} onClick={() => move(i, 1)}>↓</button>
                    </span>
                  </div>
                ))}
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn" onClick={onClose}>キャンセル</button>
              <button className="btn btn-primary"
                onClick={() => onSave([...hidden], [...pinned].filter((p) => !hidden.has(p)), order).then(onClose)}>保存</button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
