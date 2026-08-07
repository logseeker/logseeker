import { useEffect, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api } from "../api";
import type { IngestStatus, IngestVolume } from "../types";

// バイト数を人が読みやすい単位に変換（1024基準）。
function formatBytes(n: number): string {
  if (n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

// 現在時刻のJST日付を YYYY-MM-DD で返す（date input の初期値・上限に使う）。
// Date.getTime()は常にUTC epochなのでブラウザのローカルタイムゾーンには依存しない
// （getTimezoneOffset()を絡めると二重補正になり、ブラウザがJSTの場合に日付がずれるので使わない）。
function todayJst(): string {
  const jst = new Date(Date.now() + 9 * 3600 * 1000);
  return jst.toISOString().slice(0, 10);
}

function addDaysStr(dateStr: string, days: number): string {
  const d = new Date(`${dateStr}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="col-sm-6 col-lg-3">
      <div className="card card-sm">
        <div className="card-body">
          <div className="subheader">{label}</div>
          <div className="h2 mb-0">{value}</div>
          {hint && <div className="text-secondary small">{hint}</div>}
        </div>
      </div>
    </div>
  );
}

// 転送量の推移（折れ線）。単位はMB換算した値を軸に使い、ツールチップ・軸ラベルはformatBytesで整形。
function VolumeChart({ labels, bytes }: { labels: string[]; bytes: number[] }) {
  const mb = bytes.map((b) => b / (1024 * 1024));
  const option = {
    tooltip: {
      trigger: "axis",
      formatter: (params: { dataIndex: number }[]) => {
        const p = params[0];
        return `${labels[p.dataIndex]}<br/>${formatBytes(bytes[p.dataIndex])}`;
      },
    },
    grid: { left: 60, right: 20, top: 12, bottom: 56 },
    xAxis: { type: "category", data: labels, boundaryGap: false, axisLabel: { rotate: 45, fontSize: 10 } },
    yAxis: { type: "value", name: "MB", axisLabel: { formatter: (v: number) => v.toLocaleString() } },
    series: [{
      type: "line", data: mb, itemStyle: { color: "#206bc4" },
      smooth: true, showSymbol: true, symbolSize: 5, areaStyle: { opacity: 0.08 },
    }],
  };
  return <ReactECharts option={option} style={{ height: 280 }} notMerge />;
}

type Granularity = "hourly" | "daily";

// 運用：受信ログの転送量（バイト）・取り込み状態を把握するための画面。
// 「時間別」はカレンダーで選んだ1日の1時間ごと、「日別」はカレンダーで選んだ期間の1日ごと（両方とも過去に遡って参照可）。
// 日付/時刻表示はJST基準。
export function Operations() {
  const [v, setV] = useState<IngestVolume | null>(null);
  const [st, setSt] = useState<IngestStatus | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [gran, setGran] = useState<Granularity>("hourly");

  const today = todayJst();
  const [hourlyDate, setHourlyDate] = useState(today);
  const [dailyRange, setDailyRange] = useState({ start: addDaysStr(today, -30), end: today });
  const [dailyDraft, setDailyDraft] = useState(dailyRange);

  useEffect(() => {
    api.ingestStatus().then(setSt).catch(() => setSt(null));
  }, []);

  useEffect(() => {
    setErr(null);
    api.ingestVolume({ hourlyDate, dailyStart: dailyRange.start, dailyEnd: dailyRange.end })
      .then(setV).catch((e) => setErr((e as Error).message));
  }, [hourlyDate, dailyRange]);

  const applyDailyRange = () => setDailyRange(dailyDraft);

  if (err) return <div className="alert alert-danger">取得失敗: {err}</div>;
  if (!v) return <div className="text-secondary">読み込み中…</div>;

  const hourlyLabels = v.bytes_hourly.map((h) => h.hour.slice(11, 16));
  const dailyLabels = v.bytes_daily.map((d) => d.day.slice(0, 10));
  const labels = gran === "hourly" ? hourlyLabels : dailyLabels;
  const bytesArr = gran === "hourly" ? v.bytes_hourly.map((h) => h.bytes) : v.bytes_daily.map((d) => d.bytes);

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info mb-0">
          <strong>運用</strong>：受信ログの転送量（バイト数）・取り込み状態をまとめて確認できます。
          非圧縮JSONでの受信を前提としており、受信バイト数 ≒ 実ログ量として扱っています。日時表示はJST基準です。
        </div>
      </div>

      <Stat label="累計転送量" value={formatBytes(v.total_bytes)} />
      <Stat label="平均ログサイズ" value={formatBytes(v.avg_bytes_per_event)} hint="1件あたりの平均" />
      <Stat label="前日の転送量" value={formatBytes(v.bytes_yesterday)} hint="JST基準の前日1日分" />
      <Stat label="直近5分間の転送量" value={formatBytes(v.bytes_last_5min)}
        hint={`1分あたり平均 ${formatBytes(v.avg_bytes_per_minute_last_5min)}`} />

      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">転送量の推移（JST）</h3>
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
            {labels.length > 0
              ? <VolumeChart labels={labels} bytes={bytesArr} />
              : <div className="text-secondary text-center py-4">データがありません</div>}
          </div>
        </div>
      </div>

      <div className="col-12">
        <div className="card">
          <div className="card-header"><h3 className="card-title">取り込み状態</h3></div>
          <div className="card-body">
            {!st && <div className="text-secondary">読み込み中…</div>}
            {st && (
              <>
                <div className="row g-2 mb-3">
                  <div className="col-auto"><span className="text-secondary">総イベント</span> <strong>{st.total.toLocaleString()}</strong></div>
                  <div className="col-auto"><span className="text-secondary">Dead Letter</span> <strong>{st.dead_letters.toLocaleString()}</strong></div>
                </div>
                <table className="table table-sm">
                  <thead><tr><th>チャネル</th><th>件数</th><th>最終受信</th></tr></thead>
                  <tbody>
                    {st.by_channel.map((c) => (
                      <tr key={c.channel ?? "-"}>
                        <td>{c.channel}</td><td>{c.count.toLocaleString()}</td>
                        <td>{c.last_received ? c.last_received.replace("T", " ").slice(0, 19) : "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">
              {gran === "hourly" ? `時間別転送量（JST・${hourlyDate}）` : `日別転送量（JST・${dailyRange.start} 〜 ${dailyRange.end}）`}
            </h3>
          </div>
          <div className="table-responsive" style={{ maxHeight: 360 }}>
            <table className="table table-vcenter table-sm card-table">
              <thead><tr><th>{gran === "hourly" ? "時刻" : "日付"}</th><th className="text-end">転送量</th></tr></thead>
              <tbody>
                {gran === "hourly"
                  ? v.bytes_hourly.map((h) => (
                    <tr key={h.hour}><td>{h.hour.slice(11, 16)}</td><td className="text-end">{formatBytes(h.bytes)}</td></tr>
                  ))
                  : v.bytes_daily.map((d) => (
                    <tr key={d.day}><td>{d.day.slice(0, 10)}</td><td className="text-end">{formatBytes(d.bytes)}</td></tr>
                  ))}
                {(gran === "hourly" ? v.bytes_hourly.length : v.bytes_daily.length) === 0 && (
                  <tr><td colSpan={2} className="text-secondary text-center py-4">データがありません</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
