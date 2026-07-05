import ReactECharts from "echarts-for-react";
import type { Count } from "../types";

const PALETTE = ["#206bc4", "#0ca678", "#d63939", "#f76707", "#ae3ec9",
  "#4263eb", "#17a2b8", "#f59f00", "#74b816", "#e8590c", "#1098ad", "#868e96"];

// ドーナツ円グラフ。スライスクリックで onPick(value)。
export function PieChart({
  data, onPick, height = 260,
}: { data: Count[]; onPick?: (v: string) => void; height?: number }) {
  if (!data.length) return <p className="text-secondary">データなし</p>;
  const top = [...data].slice(0, 10);
  const option = {
    tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
    legend: { type: "scroll", orient: "vertical", right: 4, top: "middle", textStyle: { fontSize: 10 } },
    color: PALETTE,
    series: [{
      type: "pie", radius: ["42%", "70%"], center: ["35%", "50%"],
      avoidLabelOverlap: true,
      data: top.map((d) => ({ name: d.value == null || d.value === "" ? "(なし)" : d.value, value: d.count })),
      label: { show: false },
      emphasis: { label: { show: true, fontSize: 12, formatter: "{b}\n{d}%" } },
    }],
  };
  const onEvents: Record<string, (p: { name: string }) => void> = onPick
    ? { click: (p: { name: string }) => { if (p.name && p.name !== "(なし)") onPick(p.name); } }
    : {};
  return <ReactECharts option={option} style={{ height }} notMerge onEvents={onEvents} />;
}
