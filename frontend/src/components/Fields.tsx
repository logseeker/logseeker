import { useEffect, useState } from "react";
import { api } from "../api";
import type { FieldInfo, FilterState } from "../types";

// payload キー探索（§13）。ソースごとに構造が違うJSONの実フィールドを把握する。
export function Fields({ filter }: { filter: FilterState }) {
  const [rows, setRows] = useState<FieldInfo[]>([]);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    api.fields(filter).then(setRows).catch((e) => setErr((e as Error).message));
  }, [filter]);

  if (err) return <div className="alert alert-danger">取得失敗: {err}</div>;
  return (
    <div className="card">
      <div className="card-header">
        <h3 className="card-title">payload フィールド一覧</h3>
        <span className="card-subtitle ms-2 text-secondary">現在の絞り込み内に出現する payload キーと代表値</span>
      </div>
      <div className="table-responsive">
        <table className="table table-vcenter card-table">
          <thead><tr><th>payload key</th><th>種類数</th><th>代表値</th></tr></thead>
          <tbody>
            {rows.length === 0 && <tr><td colSpan={3} className="text-secondary">なし</td></tr>}
            {rows.map((f) => (
              <tr key={f.field}>
                <td className="font-monospace">{f.field}</td>
                <td>{f.distinct}</td>
                <td className="text-truncate" style={{ maxWidth: 520 }}>
                  {f.values.map((v) => (
                    <span key={v.value ?? "-"} className="badge bg-secondary-lt me-1">
                      {(v.value ?? "(空)").slice(0, 40)} <span className="text-secondary">×{v.count}</span>
                    </span>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
