// 集計の対象期間セレクタ。
// エンティティ・相関・資産の集計は期間指定が無く、毎回 events を全件走査していた
// （本番147万件で1回10秒、実行計画にも全件シーケンシャルスキャンが出ていた）。
// 直近24時間なら0.14秒で、実体も十分な数が取れるため既定にしている。
// 全期間も選べるが、件数が多いと時間がかかる。
export const PERIOD_OPTIONS: { value: number; label: string }[] = [
  { value: 1, label: "過去24時間" },
  { value: 7, label: "過去7日" },
  { value: 30, label: "過去30日" },
  { value: 0, label: "全期間" },
];

export function PeriodSelect({ value, onChange }: { value: number; onChange: (v: number) => void }) {
  return (
    <select className="form-select form-select-sm w-auto" value={value}
      onChange={(e) => onChange(Number(e.target.value))} title="集計の対象期間">
      {PERIOD_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  );
}
