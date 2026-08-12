import ReactECharts from "echarts-for-react";
import type { Count } from "../types";

// 内訳ドーナツグラフ。Count[]（value/count）を受け取って描画するだけの部品。
export function PieChart({ data, onPick, height = 240 }: {
  data: Count[]; onPick?: (value: string) => void; height?: number;
}) {
  if (!data.length) return <div className="text-secondary small py-4 text-center">データがありません</div>;
  const option = {
    tooltip: { trigger: "item", formatter: "{b}: {c} ({d}%)" },
    legend: { orient: "vertical", right: 0, top: "middle", textStyle: { fontSize: 11 } },
    series: [{
      type: "pie",
      radius: ["45%", "70%"],
      center: ["35%", "50%"],
      avoidLabelOverlap: true,
      label: { show: false },
      data: data.map((d) => ({ name: d.value ?? "(空)", value: d.count })),
    }],
  };
  return (
    <ReactECharts option={option} style={{ height }}
      onEvents={onPick ? { click: (p: { name?: string }) => p.name && onPick(p.name) } : undefined} />
  );
}
