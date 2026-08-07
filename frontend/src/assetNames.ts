import { useEffect, useState } from "react";
import { api } from "./api";

// IP → 表示名（アセット画面で設定した display_name。登録済みグローバルIPは
// display_name未設定時に label へフォールバック）のマップ。
// イベント一覧等の「ホスト/デバイス」列で「表示名 (IPアドレス)」形式にするために使う。
export function useAssetDisplayNames(): Map<string, string> {
  const [map, setMap] = useState<Map<string, string>>(new Map());
  useEffect(() => {
    api.assets().then((rows) => {
      const m = new Map<string, string>();
      for (const r of rows) {
        const name = r.display_name || r.label;
        if (name) m.set(r.ip, name);
      }
      setMap(m);
    }).catch(() => {});
  }, []);
  return map;
}

// device_name等の値がIPで、表示名が登録されていれば「表示名 (IP)」形式に、
// なければ元の値をそのまま返す。
export function formatHost(value: string | null | undefined, names: Map<string, string>): string {
  if (!value) return "";
  const name = names.get(value);
  return name ? `${name} (${value})` : value;
}
