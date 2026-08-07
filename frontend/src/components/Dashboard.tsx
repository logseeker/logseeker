import { useEffect, useState, type ReactNode } from "react";
import { api } from "../api";
import type { useChangelog } from "../changelog";
import { addDaysStr, todayJst } from "../dateUtils";
import type { FilterState, Summary, Timeline } from "../types";
import { BarChart } from "./BarChart";
import { PieChart } from "./PieChart";
import { TimelineChart } from "./TimelineChart";

// 未読の最新お知らせがあればダッシュボード上部に表示するバナー。閉じると、
// 次に新しいリリースが出るまで再表示しない（useChangelogのdismissロジックに従う）。
function ChangelogBanner({ changelog, onNav }: { changelog: ReturnType<typeof useChangelog>; onNav: () => void }) {
  if (!changelog.unread || !changelog.latest) return null;
  const r = changelog.latest;
  return (
    <div className="col-12">
      <div className="alert alert-primary d-flex align-items-start">
        <div className="flex-fill">
          <div className="d-flex align-items-center gap-2 mb-1">
            <strong>📢 お知らせ：{r.name}</strong>
            <span className="text-secondary small">{r.published_at?.slice(0, 10)}</span>
          </div>
          <a role="button" className="text-primary" onClick={onNav}>更新内容を見る →</a>
        </div>
        <button type="button" className="btn-close ms-2" onClick={changelog.dismiss}></button>
      </div>
    </div>
  );
}

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

type Granularity = "hourly" | "daily";

export function Dashboard({ onPick, changelog, onNavChangelog }: {
  onPick: (k: string, v: string) => void;
  changelog: ReturnType<typeof useChangelog>;
  onNavChangelog: () => void;
}) {
  const [s, setS] = useState<Summary | null>(null);
  const [tl, setTl] = useState<Timeline>({ buckets: [], series: {} });
  const [err, setErr] = useState<string | null>(null);
  const [gran, setGran] = useState<Granularity>("hourly");

  const today = todayJst();
  const [hourlyDate, setHourlyDate] = useState(today);
  const [dailyRange, setDailyRange] = useState({ start: addDaysStr(today, -29), end: today });
  const [dailyDraft, setDailyDraft] = useState(dailyRange);

  useEffect(() => {
    api.summary(ALL).then(setS).catch((e) => setErr((e as Error).message));
  }, []);
  useEffect(() => {
    const interval = gran === "hourly" ? "hour" : "day";
    const start = gran === "hourly" ? `${hourlyDate}T00:00:00+09:00` : `${dailyRange.start}T00:00:00+09:00`;
    const end = gran === "hourly"
      ? `${addDaysStr(hourlyDate, 1)}T00:00:00+09:00`
      : `${addDaysStr(dailyRange.end, 1)}T00:00:00+09:00`;
    // 常に全体（tax無し）。選択中の粒度・期間の推移のみ。
    api.timeline({ tax: {}, start, end }, interval).then(setTl).catch(() => {});
  }, [gran, hourlyDate, dailyRange]);

  const applyDailyRange = () => setDailyRange(dailyDraft);
  const setDailyPreset = (days: number) => {
    const r = { start: addDaysStr(today, -(days - 1)), end: today };
    setDailyDraft(r);
    setDailyRange(r);
  };

  if (err) return <div className="alert alert-danger">取得失敗: {err}</div>;
  if (!s) return <div className="text-secondary">読み込み中…</div>;

  return (
    <div className="row row-deck row-cards">
      <ChangelogBanner changelog={changelog} onNav={onNavChangelog} />
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
            <div className="card-actions d-flex align-items-center gap-2 flex-wrap">
              <div className="btn-group">
                <button className={`btn btn-sm ${gran === "hourly" ? "btn-primary" : "btn-outline-primary"}`}
                  onClick={() => setGran("hourly")}>時間別</button>
                <button className={`btn btn-sm ${gran === "daily" ? "btn-primary" : "btn-outline-primary"}`}
                  onClick={() => setGran("daily")}>日別</button>
              </div>
              {gran === "hourly" ? (
                <div className="d-flex align-items-center gap-1">
                  <input type="date" className="form-control form-control-sm" style={{ width: 150 }}
                    max={today} value={hourlyDate} onChange={(e) => setHourlyDate(e.target.value || today)} />
                  <button type="button" className="btn btn-sm btn-outline-secondary"
                    onClick={() => setHourlyDate(today)}>本日</button>
                </div>
              ) : (
                <div className="d-flex align-items-center gap-1">
                  <button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => setDailyPreset(7)}>直近7日</button>
                  <button type="button" className="btn btn-sm btn-outline-secondary" onClick={() => setDailyPreset(30)}>直近30日</button>
                  <input type="date" className="form-control form-control-sm" style={{ width: 150 }}
                    max={dailyDraft.end} value={dailyDraft.start}
                    onChange={(e) => setDailyDraft((d) => ({ ...d, start: e.target.value }))} />
                  <span className="text-secondary">〜</span>
                  <input type="date" className="form-control form-control-sm" style={{ width: 150 }}
                    min={dailyDraft.start} max={today} value={dailyDraft.end}
                    onChange={(e) => setDailyDraft((d) => ({ ...d, end: e.target.value }))} />
                  <button type="button" className="btn btn-sm btn-primary" onClick={applyDailyRange}>表示</button>
                </div>
              )}
            </div>
          </div>
          <div className="card-body">
            <TimelineChart data={tl} type="bar" interval={gran === "hourly" ? "hour" : "day"} height={200} />
          </div>
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
