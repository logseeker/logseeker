import ReactECharts from "echarts-for-react";
import type { Count } from "../types";

// 横棒ランキング。棒クリックで onPick(value)。
export function BarChart({
  data, onPick, color = "#3b82f6", height = 240,
}: { data: Count[]; onPick?: (v: string) => void; color?: string; height?: number }) {
  if (!data.length) return <p className="muted">データなし</p>;
  const sorted = [...data].slice(0, 12).sort((a, b) => a.count - b.count);
  const labels = sorted.map((d) => (d.value == null || d.value === "" ? "(なし)" : d.value));
  const option = {
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    grid: { left: 8, right: 36, top: 8, bottom: 24, containLabel: true },
    xAxis: { type: "value" },
    yAxis: { type: "category", data: labels, axisLabel: { fontSize: 10, width: 150, overflow: "truncate" } },
    series: [{ type: "bar", data: sorted.map((d) => d.count), itemStyle: { color },
      label: { show: true, position: "right", fontSize: 10 } }],
  };
  const onEvents: Record<string, (p: { dataIndex: number }) => void> = onPick
    ? { click: (p: { dataIndex: number }) => { const v = sorted[p.dataIndex]?.value; if (v != null) onPick(String(v)); } }
    : {};
  return <ReactECharts option={option} style={{ height }} notMerge onEvents={onEvents} />;
}
