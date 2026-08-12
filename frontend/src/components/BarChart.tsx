import ReactECharts from "echarts-for-react";
import type { Count } from "../types";

// 汎用の横棒グラフ。件数上位のCount[]（value/count）を受け取って描画するだけの
// プレゼンテーション部品（データの意味付けはDashboard.tsx側で行う）。
export function BarChart({ data, onPick, height = 220 }: {
  data: Count[]; onPick?: (value: string) => void; height?: number;
}) {
  if (!data.length) return <div className="text-secondary small py-4 text-center">データがありません</div>;
  const rows = [...data].reverse();  // echartsの横棒は下から積むため上位を上にするため逆順
  const option = {
    grid: { left: 8, right: 24, top: 8, bottom: 8, containLabel: true },
    tooltip: { trigger: "item" },
    xAxis: { type: "value" },
    yAxis: { type: "category", data: rows.map((d) => d.value ?? "(空)"), axisLabel: { fontSize: 11 } },
    series: [{ type: "bar", data: rows.map((d) => d.count), barMaxWidth: 18 }],
  };
  return (
    <ReactECharts
      option={option}
      style={{ height }}
      onEvents={onPick ? {
        click: (p: { name?: string }) => { if (p.name) onPick(p.name === "(空)" ? "" : p.name); },
      } : undefined}
    />
  );
}
