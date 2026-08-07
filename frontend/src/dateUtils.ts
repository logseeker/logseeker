// JST基準の日付処理ヘルパー（運用画面・ダッシュボードなど、カレンダーで過去日を選ぶ画面で共通利用）。
// Date.getTime()は常にUTC epochなのでブラウザのローカルタイムゾーンには依存しない
// （getTimezoneOffset()を絡めると二重補正になり、ブラウザがJSTの場合に日付がずれるので使わない）。
export function todayJst(): string {
  const jst = new Date(Date.now() + 9 * 3600 * 1000);
  return jst.toISOString().slice(0, 10);
}

export function addDaysStr(dateStr: string, days: number): string {
  const d = new Date(`${dateStr}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}
