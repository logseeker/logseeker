import { useEffect, useState, type ReactNode } from "react";
import { api } from "../api";
import type { FilterState, Summary, Timeline } from "../types";
import { BarChart } from "./BarChart";
import { PieChart } from "./PieChart";
import { TimelineChart } from "./TimelineChart";

function Stat({ n, label }: { n: number; label: string }) {
  return (
    <div className="col-6 col-md">
      <div className="card card-sm">
        <div className="card-body">
          <div className="subheader">{label}</div>
          <div className="h1 mb-0">{n.toLocaleString()}</div>
        </div>
      </div>
    </div>
  );
}

function ChartCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="col-lg-6">
      <div className="card">
        <div className="card-header"><h3 className="card-title">{title}</h3></div>
        <div className="card-body">{children}</div>
      </div>
    </div>
  );
}

// ダッシュボードは常に全体（リセット状態）を表示する。画面の絞り込み(filter)は使わない。
const ALL: FilterState = { tax: {} };

// 推移グラフの表示レンジ（相対・現在時刻基準）。デフォルト24h。
const RANGES: Record<string, { label: string; interval: string; ms: number }> = {
  "24h": { label: "直近24時間", interval: "hour", ms: 24 * 3600 * 1000 },
  "7d":  { label: "直近1週間", interval: "day", ms: 7 * 24 * 3600 * 1000 },
  "30d": { label: "直近1ヶ月", interval: "day", ms: 30 * 24 * 3600 * 1000 },
};

export function Dashboard({ onPick }: { onPick: (k: string, v: string) => void }) {
  const [s, setS] = useState<Summary | null>(null);
  const [tl, setTl] = useState<Timeline>({ buckets: [], series: {} });
  const [range, setRange] = useState("24h");
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.summary(ALL).then(setS).catch((e) => setErr((e as Error).message));
  }, []);
  useEffect(() => {
    const r = RANGES[range];
    const end = new Date();
    const start = new Date(end.getTime() - r.ms);
    // 常に全体（tax無し）＋レンジのみ。合計の推移。
    api.timeline({ tax: {}, start: start.toISOString(), end: end.toISOString() }, r.interval)
      .then(setTl).catch(() => {});
  }, [range]);

  if (err) return <div className="alert alert-danger">取得失敗: {err}</div>;
  if (!s) return <div className="text-secondary">読み込み中…</div>;

  return (
    <div className="row row-deck row-cards">
      <div className="col-12">
        <div className="row row-cards">
          <Stat n={s.total} label="総イベント" />
          <Stat n={s.recent_24h} label="直近24時間" />
          <Stat n={s.ingest_failed} label="取り込み失敗" />
          <Stat n={s.source_count} label="ログソース数" />
          <Stat n={s.host_domain_count} label="ホスト/ドメイン数" />
        </div>
      </div>

      {/* ログソース別カード一覧 */}
      <div className="col-12">
        <div className="card">
          <div className="card-header"><h3 className="card-title">ログソース別</h3></div>
          <div className="card-body">
            <div className="row g-2">
              {s.by_source_name.map((r) => (
                <div className="col-sm-6 col-md-4 col-xl-3" key={r.value ?? "-"}>
                  <div className="card card-sm card-link" role="button" onClick={() => r.value && onPick("source_name", r.value)}>
                    <div className="card-body">
                      <div className="font-weight-medium text-truncate">{r.value ?? "Unknown"}</div>
                      <div className="text-secondary">{r.count.toLocaleString()} 件</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">イベント件数の推移</h3>
            <div className="card-actions btn-group">
              {Object.entries(RANGES).map(([k, v]) => (
                <button key={k} className={`btn btn-sm ${range === k ? "btn-primary" : "btn-outline-primary"}`}
                  onClick={() => setRange(k)}>{v.label}</button>
              ))}
            </div>
          </div>
          <div className="card-body"><TimelineChart data={tl} type="bar" interval={RANGES[range].interval} height={200} /></div>
        </div>
      </div>

      <ChartCard title="ホスト / デバイス別"><PieChart data={s.by_device} onPick={(v) => onPick("device_name", v)} /></ChartCard>
      <ChartCard title="ドメイン別"><PieChart data={s.by_domain} onPick={(v) => onPick("url_domain", v)} /></ChartCard>
      <ChartCard title="上位 送信元IP"><BarChart data={s.top_source_ip} color="#d63939" onPick={(v) => onPick("source_ip", v)} /></ChartCard>
      <ChartCard title="上位 URLパス"><BarChart data={s.top_url_path} color="#f76707" onPick={(v) => onPick("url_path", v)} /></ChartCard>
      <ChartCard title="上位 ユーザー"><BarChart data={s.top_actor_user} color="#ae3ec9" onPick={(v) => onPick("actor_user", v)} /></ChartCard>
      <ChartCard title="HTTPステータス別"><BarChart data={s.by_http_status} color="#4263eb" onPick={(v) => onPick("http_status_code", v)} /></ChartCard>
      <ChartCard title="イベント種別別"><BarChart data={s.by_event_action} color="#17a2b8" onPick={(v) => onPick("event_action", v)} /></ChartCard>
    </div>
  );
}
