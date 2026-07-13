import { useEffect, useState } from "react";
import ReactECharts from "echarts-for-react";
import { api } from "../api";
import type { IngestVolume } from "../types";

// バイト数を人が読みやすい単位に変換（1024基準）。
function formatBytes(n: number): string {
  if (n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
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

// 日別/月別の転送量バー。単位はMB換算した値を軸に使い、ツールチップ・軸ラベルはformatBytesで整形。
function VolumeChart({ labels, bytes }: { labels: string[]; bytes: number[] }) {
  const mb = bytes.map((b) => b / (1024 * 1024));
  const option = {
    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params: { dataIndex: number }[]) => {
        const p = params[0];
        return `${labels[p.dataIndex]}<br/>${formatBytes(bytes[p.dataIndex])}`;
      },
    },
    grid: { left: 60, right: 20, top: 12, bottom: 56 },
    xAxis: { type: "category", data: labels, axisLabel: { rotate: 45, fontSize: 10 } },
    yAxis: { type: "value", name: "MB", axisLabel: { formatter: (v: number) => v.toLocaleString() } },
    series: [{ type: "bar", data: mb, itemStyle: { color: "#206bc4" }, barMaxWidth: 28 }],
  };
  return <ReactECharts option={option} style={{ height: 280 }} notMerge />;
}

type Granularity = "daily" | "monthly";

// 運用：受信ログの転送量（バイト）を把握するための画面。件数ベースの「取り込み」画面を補う。
// 日付/月の区切り表示はJST基準。
export function Operations() {
  const [v, setV] = useState<IngestVolume | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [gran, setGran] = useState<Granularity>("daily");

  useEffect(() => {
    api.ingestVolume().then(setV).catch((e) => setErr((e as Error).message));
  }, []);

  if (err) return <div className="alert alert-danger">取得失敗: {err}</div>;
  if (!v) return <div className="text-secondary">読み込み中…</div>;

  const dailyLabels = v.bytes_daily.map((d) => d.day.slice(5, 10));
  const monthlyLabels = v.bytes_monthly.map((m) => m.month.slice(0, 7));
  const labels = gran === "daily" ? dailyLabels : monthlyLabels;
  const bytesArr = gran === "daily" ? v.bytes_daily.map((d) => d.bytes) : v.bytes_monthly.map((m) => m.bytes);

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info mb-0">
          <strong>運用</strong>：受信ログの転送量（バイト数）を集計します。件数ベースの統計は「取り込み」画面を参照してください。
          非圧縮JSONでの受信を前提としており、受信バイト数 ≒ 実ログ量として扱っています。日付・月の区切りはJST基準です。
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
            <div className="card-actions btn-group">
              <button className={`btn btn-sm ${gran === "daily" ? "btn-primary" : "btn-outline-primary"}`}
                onClick={() => setGran("daily")}>日別（直近31日）</button>
              <button className={`btn btn-sm ${gran === "monthly" ? "btn-primary" : "btn-outline-primary"}`}
                onClick={() => setGran("monthly")}>月別（直近12ヶ月）</button>
            </div>
          </div>
          <div className="card-body">
            {labels.length > 0
              ? <VolumeChart labels={labels} bytes={bytesArr} />
              : <div className="text-secondary text-center py-4">データがありません</div>}
          </div>
        </div>
      </div>

      <div className="col-12 col-lg-6">
        <div className="card">
          <div className="card-header"><h3 className="card-title">日別転送量（JST・直近31日）</h3></div>
          <div className="table-responsive" style={{ maxHeight: 360 }}>
            <table className="table table-vcenter table-sm card-table">
              <thead><tr><th>日付</th><th className="text-end">転送量</th></tr></thead>
              <tbody>
                {v.bytes_daily.map((d) => (
                  <tr key={d.day}><td>{d.day.slice(0, 10)}</td><td className="text-end">{formatBytes(d.bytes)}</td></tr>
                ))}
                {v.bytes_daily.length === 0 && (
                  <tr><td colSpan={2} className="text-secondary text-center py-4">データがありません</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="col-12 col-lg-6">
        <div className="card">
          <div className="card-header"><h3 className="card-title">月別転送量（JST・直近12ヶ月）</h3></div>
          <div className="table-responsive" style={{ maxHeight: 360 }}>
            <table className="table table-vcenter table-sm card-table">
              <thead><tr><th>年月</th><th className="text-end">転送量</th></tr></thead>
              <tbody>
                {v.bytes_monthly.map((m) => (
                  <tr key={m.month}><td>{m.month.slice(0, 7)}</td><td className="text-end">{formatBytes(m.bytes)}</td></tr>
                ))}
                {v.bytes_monthly.length === 0 && (
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
