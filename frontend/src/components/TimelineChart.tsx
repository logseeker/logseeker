import ReactECharts from "echarts-for-react";
import type { Timeline } from "../types";

const PALETTE = ["#206bc4", "#d63939", "#0ca678", "#f59f00", "#ae3ec9", "#17a2b8", "#74b816", "#868e96"];

export function TimelineChart({
  data, height = 300, type = "bar", interval = "day",
}: { data: Timeline; height?: number; type?: "bar" | "line"; interval?: string }) {
  const names = Object.keys(data.series);
  const multi = !(names.length === 1 && names[0] === "count");
  // 時/分粒度は時刻まで、日以上は日付だけ表示（「00:00」のような無意味な時刻を出さない）
  const fmt = (b: string) =>
    interval === "hour" || interval === "minute"
      ? b.replace("T", " ").slice(5, 16)   // MM-DD HH:mm
      : b.slice(0, 10);                     // YYYY-MM-DD
  const series = names.map((name, i) => ({
    name,
    type,
    ...(type === "bar" ? { stack: multi ? "t" : undefined, barMaxWidth: 28 }
      : { smooth: true, showSymbol: true, symbolSize: 6, connectNulls: false, lineStyle: { width: 2 } }),
    itemStyle: { color: PALETTE[i % PALETTE.length] },
    emphasis: { focus: "series" },
    data: data.series[name],
  }));
  const option = {
    tooltip: { trigger: "axis", axisPointer: { type: type === "line" ? "line" : "shadow" } },
    legend: multi ? { type: "scroll", data: names, top: 0 } : undefined,
    grid: { left: 50, right: 20, top: multi ? 30 : 12, bottom: 56 },
    xAxis: {
      type: "category", boundaryGap: type === "bar",
      data: data.buckets.map(fmt),
      axisLabel: { rotate: 35, fontSize: 10 },
    },
    yAxis: { type: "value", name: "件数" },
    series,
  };
  return <ReactECharts option={option} style={{ height }} notMerge />;
}
