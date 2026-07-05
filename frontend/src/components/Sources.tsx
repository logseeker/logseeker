import { useEffect, useState } from "react";
import { api } from "../api";
import type { Count, FilterState } from "../types";

// ログソース別カード一覧（クリックで Events をそのソースで絞り込み）
export function Sources({ filter, onPick }: { filter: FilterState; onPick: (k: string, v: string) => void }) {
  const [rows, setRows] = useState<Count[]>([]);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    api.groupby(filter, "source_name", 100).then(setRows).catch((e) => setErr((e as Error).message));
  }, [filter]);

  if (err) return <div className="alert alert-danger">取得失敗: {err}</div>;
  return (
    <div className="row row-cards">
      {rows.length === 0 && <div className="col-12 text-secondary">データがありません。</div>}
      {rows.map((r) => (
        <div className="col-sm-6 col-lg-4" key={r.value ?? "-"}>
          <div className="card card-link" role="button" onClick={() => r.value && onPick("source_name", r.value)}>
            <div className="card-body">
              <div className="d-flex align-items-center">
                <div>
                  <div className="font-weight-medium">{r.value ?? "Unknown"}</div>
                  <div className="text-secondary">ログソース</div>
                </div>
                <div className="ms-auto"><span className="badge bg-blue-lt">{r.count.toLocaleString()} 件</span></div>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
