import { useCallback, useEffect, useMemo, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api } from "../api";
import type { EventQuery } from "../api";
import { BarChart } from "./BarChart";
import { PieChart } from "./PieChart";
import type { DashboardOverview, DashboardTimeline, ReleaseItem, TaxonomyField } from "../types";

const LS_AXES = "logseeker_dashboard_axes_v3";
const LS_EXTRA = "logseeker_dashboard_extra_v3";

type ChangelogState = {
  releases: ReleaseItem[]; latest: ReleaseItem | undefined; unread: boolean; dismiss: () => void; loaded: boolean;
};

type Props = {
  /** 代表値グループのクリック（集計時と同じ優先順位のOR条件でEventsへ。normalize-mapping.md §7.1） */
  onPickRep: (value: string) => void;
  /** 個別Taxonomyフィールドのクリック（そのKEY:VALUEをそのまま条件に。同 §7.2） */
  onPickField: (field: string, value: string) => void;
  onPickClass: (classValue: string) => void;
  /** ログソース別カードのクリック（LogSeeker管理メタデータ source での絞り込み） */
  onPickSource: (source: string) => void;
  changelog: ChangelogState;
  onNavChangelog: () => void;
};

const PERIODS = [
  { key: "24h", label: "24時間", hours: 24 },
  { key: "7d", label: "7日間", hours: 24 * 7 },
  { key: "30d", label: "30日間", hours: 24 * 30 },
];

const lsGet = <T,>(k: string, fb: T): T => {
  try { const v = localStorage.getItem(k); return v ? (JSON.parse(v) as T) : fb; } catch { return fb; }
};
const todayJst = () => new Date(Date.now() + 9 * 3600_000).toISOString().slice(0, 10);

export function Dashboard({ onPickRep, onPickField, onPickClass, onPickSource, changelog, onNavChangelog }: Props) {
  const [periodKey, setPeriodKey] = useState("24h");
  const [classValue, setClassValue] = useState<string | null>(null);
  const [axes, setAxes] = useState<string[] | null>(() => lsGet<string[] | null>(LS_AXES, null));
  const [extra, setExtra] = useState<string[]>(() => lsGet(LS_EXTRA, [] as string[]));
  const [ov, setOv] = useState<DashboardOverview | null>(null);
  const [fields, setFields] = useState<TaxonomyField[]>([]);
  const [picker, setPicker] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // イベント件数の推移（時間別＝その日の24バケット / 日別＝その日までの30日）
  const [interval, setInterval] = useState<"hour" | "day">("hour");
  const [date, setDate] = useState(todayJst);
  const [tl, setTl] = useState<DashboardTimeline | null>(null);

  const period = PERIODS.find((p) => p.key === periodKey)!;
  const query = useCallback((): EventQuery => {
    const end = new Date();
    return {
      class_value: classValue ?? undefined,
      start: new Date(end.getTime() - period.hours * 3600_000).toISOString(),
      end: end.toISOString(),
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [periodKey, classValue]);

  useEffect(() => {
    api.dashboardOverview(query(), axes ?? [], extra).then(setOv).catch((e) => setErr((e as Error).message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, axes?.join(","), extra.join(",")]);
  useEffect(() => {
    api.dashboardTimeline(interval, date, classValue).then(setTl).catch(() => setTl(null));
  }, [interval, date, classValue]);
  useEffect(() => {
    api.eventsFields(classValue).then((f) => setFields(f.keys)).catch(() => setFields([]));
  }, [classValue]);

  const labelOf = useMemo(() => {
    const m = new Map(fields.map((f) => [f.key, f.label]));
    return (k: string) => m.get(k) || k;
  }, [fields]);

  const save = (v: string[], key: string, fn: (x: string[]) => void) => {
    fn(v);
    try { localStorage.setItem(key, JSON.stringify(v)); } catch { /* noop */ }
  };

  const Stat = ({ label, value }: { label: string; value: string | number }) => (
    <div className="col">
      <div className="card card-sm"><div className="card-body">
        <div className="text-secondary small">{label}</div>
        <div className="h2 mb-0">{typeof value === "number" ? value.toLocaleString() : value}</div>
      </div></div>
    </div>
  );

  const tlLabel = (iso: string) => {
    const d = new Date(iso);
    return interval === "hour"
      ? d.toLocaleString("ja-JP", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })
      : d.toLocaleDateString("ja-JP", { month: "2-digit", day: "2-digit" });
  };

  return (
    <div>
      {err && <div className="alert alert-danger">{err}</div>}
      {changelog.unread && changelog.latest && (
        <div className="alert alert-info d-flex align-items-center">
          <div className="flex-fill">
            新しいお知らせ：<strong>{changelog.latest.name || changelog.latest.tag_name}</strong>
            <a role="button" className="ms-2" onClick={onNavChangelog}>見る</a>
          </div>
          <button className="btn btn-sm btn-ghost-secondary" onClick={changelog.dismiss}>閉じる</button>
        </div>
      )}

      <div className="d-flex flex-wrap align-items-end gap-2 mb-3">
        <div className="btn-group">
          {PERIODS.map((p) => (
            <button key={p.key} className={`btn btn-sm ${p.key === periodKey ? "btn-primary" : "btn-outline-secondary"}`}
              onClick={() => setPeriodKey(p.key)}>{p.label}</button>
          ))}
        </div>
        <div>
          <label className="form-label mb-0 small">Class</label>
          <select className="form-select form-select-sm" style={{ width: 180 }} value={classValue ?? ""}
            onChange={(e) => setClassValue(e.target.value || null)}>
            <option value="">すべて</option>
            {(ov?.by_class ?? []).map((c) => (
              <option key={String(c.value)} value={String(c.value)}>{c.value} ({c.count})</option>
            ))}
          </select>
        </div>
        <button className="btn btn-sm btn-outline-primary ms-auto" onClick={() => setPicker(true)}>
          ⚙ 集計する項目を選ぶ
        </button>
      </div>

      {!ov ? <div className="text-secondary text-center py-4">読み込み中...</div> : (
        <>
          <div className="row row-cols-1 row-cols-sm-3 row-cols-lg-5 row-cards mb-3">
            <Stat label={`総イベント（${period.label}）`} value={ov.total} />
            <Stat label="ログソース数" value={ov.source_count} />
            <Stat label="ホスト/ドメイン数" value={ov.host_domain_count} />
            <Stat label="取り込み失敗" value={ov.ingest_failed} />
            <div className="col">
              <div className="card card-sm"><div className="card-body">
                <div className="text-secondary small">Class</div>
                <div className="d-flex flex-wrap gap-1 mt-1">
                  {ov.by_class.slice(0, 4).map((c) => (
                    <button key={String(c.value)} className="btn btn-sm btn-outline-secondary py-0"
                      title="このClassでEventsを開く" onClick={() => onPickClass(String(c.value))}>
                      {c.value ?? "(空)"} <span className="text-secondary">{c.count.toLocaleString()}</span>
                    </button>
                  ))}
                </div>
              </div></div>
            </div>
          </div>

          <div className="card mb-3">
            <div className="card-header"><h3 className="card-title mb-0">ログソース別</h3></div>
            <div className="card-body">
              {ov.by_source.length === 0 ? <div className="text-secondary small">データがありません</div> : (
                <div className="row g-2">
                  {ov.by_source.map((s) => (
                    <div className="col-6 col-lg-3" key={String(s.value)}>
                      <div className="card card-sm" role="button" title="このログソースでEventsを開く"
                        onClick={() => s.value && onPickSource(String(s.value))}>
                        <div className="card-body py-2">
                          <div className="text-truncate text-primary">{s.value ?? "(空)"}</div>
                          <div className="text-secondary small">{s.count.toLocaleString()} 件</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* イベント件数の推移（本番と同じ：時間別/日別・日付指定・本日） */}
          <div className="card mb-3">
            <div className="card-header d-flex align-items-center">
              <h3 className="card-title mb-0">イベント件数の推移</h3>
              <div className="ms-auto d-flex align-items-center gap-2">
                <div className="btn-group btn-group-sm">
                  <button className={`btn ${interval === "hour" ? "btn-primary" : "btn-outline-secondary"}`}
                    onClick={() => setInterval("hour")}>時間別</button>
                  <button className={`btn ${interval === "day" ? "btn-primary" : "btn-outline-secondary"}`}
                    onClick={() => setInterval("day")}>日別</button>
                </div>
                <input type="date" className="form-control form-control-sm" style={{ width: 150 }}
                  value={date} onChange={(e) => setDate(e.target.value || todayJst())} />
                <button className="btn btn-sm btn-outline-secondary" onClick={() => setDate(todayJst())}>本日</button>
              </div>
            </div>
            <div className="card-body">
              {!tl ? <div className="text-secondary small text-center py-4">読み込み中...</div> : (
                <ReactECharts style={{ height: 240 }} option={{
                  grid: { left: 50, right: 16, top: 16, bottom: 60 },
                  tooltip: { trigger: "axis" },
                  xAxis: {
                    type: "category", data: tl.buckets.map((b) => tlLabel(b.t)),
                    axisLabel: { fontSize: 10, rotate: 45 },
                  },
                  yAxis: { type: "value" },
                  series: [{ type: "bar", data: tl.buckets.map((b) => b.count) }],
                }} />
              )}
            </div>
          </div>

          {/* ドメイン/ホストは代表値優先順位で集約（v12 §5.3） */}
          <div className="card mb-3">
            <div className="card-header d-flex align-items-center">
              <h3 className="card-title mb-0">ドメイン / ホスト（代表値）</h3>
              <div className="ms-auto d-flex flex-wrap gap-2">
                {ov.domain_host.priority.map((k) => (
                  <div className="form-check form-check-inline mb-0" key={k}>
                    <input className="form-check-input" type="checkbox" id={`ex-${k}`} checked={extra.includes(k)}
                      onChange={() => save(extra.includes(k) ? extra.filter((x) => x !== k) : [...extra, k], LS_EXTRA, setExtra)} />
                    <label className="form-check-label small" htmlFor={`ex-${k}`}>{k}</label>
                  </div>
                ))}
              </div>
            </div>
            <div className="card-body">
              <div className="row">
                <div className="col-md-6"><PieChart data={ov.domain_host.representative} onPick={onPickRep} /></div>
                <div className="col-md-6"><BarChart data={ov.domain_host.representative} onPick={onPickRep} /></div>
              </div>
              <div className="text-secondary small mt-2">
                優先順位: {ov.domain_host.priority.join(" > ")}（先頭から最初に見つかった値を代表値として集計）
              </div>
              {Object.entries(ov.domain_host.extra).map(([k, vals]) => (
                vals.length ? (
                  <div key={k} className="mt-3">
                    <div className="text-secondary small mb-1">追加表示: {labelOf(k)}（{k}）</div>
                    <BarChart data={vals} height={130} onPick={(v) => onPickField(k, v)} />
                  </div>
                ) : null
              ))}
            </div>
          </div>

          {/* 集計軸は利用者が選ぶ（既定値あり・0件の軸はカードを出さない） */}
          <div className="row row-cards">
            {ov.breakdowns.map((b) => (
              <div className="col-md-6" key={b.field}>
                <div className="card mb-3">
                  <div className="card-header">
                    <h3 className="card-title mb-0">
                      {b.label || b.field}<span className="text-secondary small ms-1">{b.field}</span>
                    </h3>
                    <button className="btn btn-sm btn-ghost-secondary ms-auto" title="このカードを外す"
                      onClick={() => save((axes ?? ov.breakdowns.map((x) => x.field)).filter((a) => a !== b.field), LS_AXES, (v) => setAxes(v))}>✕</button>
                  </div>
                  <div className="card-body">
                    <BarChart data={b.values} onPick={(v) => onPickField(b.field, v)} />
                  </div>
                </div>
              </div>
            ))}
          </div>
          {ov.breakdowns.length === 0 && (
            <div className="card"><div className="card-body text-center text-secondary">
              集計対象の値がありません。「⚙ 集計する項目を選ぶ」からTaxonomy KEYを選択してください。
            </div></div>
          )}
          {ov.empty_axes.length > 0 && (
            <div className="text-secondary small">
              選択中で受信値が無い項目（カード非表示）: {ov.empty_axes.join(", ")}
            </div>
          )}
        </>
      )}

      {picker && (
        <AxisPicker fields={fields} selected={axes ?? (ov?.breakdowns.map((b) => b.field) ?? [])}
          onClose={() => setPicker(false)}
          onApply={(next) => { save(next, LS_AXES, (v) => setAxes(v)); setPicker(false); }} />
      )}
    </div>
  );
}

function AxisPicker({ fields, selected, onApply, onClose }: {
  fields: TaxonomyField[]; selected: string[]; onApply: (v: string[]) => void; onClose: () => void;
}) {
  const [sel, setSel] = useState<Set<string>>(new Set(selected));
  const [q, setQ] = useState("");
  const shown = fields.filter((f) => !q || f.key.includes(q.toLowerCase()) ||
    (f.label ?? "").toLowerCase().includes(q.toLowerCase()));
  return (
    <>
      <div style={{ position: "fixed", inset: 0, zIndex: 1040, background: "rgba(0,0,0,.15)" }} onClick={onClose} />
      <div className="card" style={{ position: "fixed", top: 0, right: 0, bottom: 0, width: 420, zIndex: 1050, borderRadius: 0 }}>
        <div className="card-header">
          <h3 className="card-title mb-0">集計する項目</h3>
          <button className="btn-close ms-auto" onClick={onClose} />
        </div>
        <div className="card-body" style={{ overflowY: "auto" }}>
          <p className="text-secondary small">
            docs/taxonomy.md のTaxonomy KEY（{fields.length}件）から選びます。★はこのClassの参考例のKEYです。
          </p>
          <input className="form-control form-control-sm mb-2" placeholder="検索" value={q}
            onChange={(e) => setQ(e.target.value)} />
          <div className="list-group" style={{ maxHeight: "70vh", overflowY: "auto" }}>
            {shown.map((f) => (
              <label key={f.key} className="list-group-item d-flex align-items-center gap-2 py-1">
                <input className="form-check-input mt-0" type="checkbox" checked={sel.has(f.key)}
                  onChange={() => setSel((p) => { const n = new Set(p); n.has(f.key) ? n.delete(f.key) : n.add(f.key); return n; })} />
                {f.recommended && <span className="text-warning">★</span>}
                <span className="flex-fill">{f.label ? <>{f.label} <span className="text-secondary small">({f.key})</span></> : f.key}</span>
              </label>
            ))}
          </div>
        </div>
        <div className="card-footer text-end">
          <button className="btn btn-primary" onClick={() => onApply([...sel])}>適用</button>
        </div>
      </div>
    </>
  );
}
