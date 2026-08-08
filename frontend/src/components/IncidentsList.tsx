import { useEffect, useState } from "react";
import { api } from "../api";
import { fmtTime } from "../labels";
import type { IncidentRow, Verdict } from "../types";

const VERDICT_LABEL: Record<Verdict, string> = {
  unjudged: "未判定", true_positive: "True Positive（真陽性）",
  false_positive: "誤検知", over_detection: "過検知", other: "その他",
};

// インシデント単体の一覧画面（設計書v4 4章）。ケースを経由せず左メニューから直接到達する。
// 各行は「注目」イベント単体から直接生成された事案であり、ケースには一切依存しない。
// クリックで既存の独立したインシデント詳細画面（IncidentPanel.tsx／screen==="incident"）へ遷移する。
export function IncidentsList({ onOpenIncident }: { onOpenIncident: (incidentId: number) => void }) {
  const [rows, setRows] = useState<IncidentRow[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.incidents().then(setRows).catch((e) => setErr((e as Error).message));
  }, []);

  return (
    <div className="row row-cards">
      {err && <div className="col-12"><div className="alert alert-danger">{err}</div></div>}
      <div className="col-12">
        <div className="card">
          <div className="card-header"><h3 className="card-title">インシデント</h3></div>
          <table className="table table-vcenter card-table table-hover">
            <thead>
              <tr>
                <th>タイトル</th><th>ステータス</th><th>担当者</th><th>判定結果</th>
                <th>起因アラート</th><th>最終更新</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} style={{ cursor: "pointer" }} onClick={() => onOpenIncident(r.id)}>
                  <td>{r.title}</td>
                  <td><span className="badge bg-red-lt">{r.status_name ?? "-"}</span></td>
                  <td className="text-secondary small">{r.assignee_name ?? "-"}</td>
                  <td><span className="badge bg-azure-lt">{VERDICT_LABEL[r.verdict]}</span></td>
                  <td className="text-secondary small">
                    {r.event_source_name ?? "-"}{r.event_action ? ` / ${r.event_action}` : ""}
                  </td>
                  <td className="text-secondary small">{r.updated_at ? fmtTime(r.updated_at) : "-"}</td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr><td colSpan={6} className="text-secondary text-center py-4">
                  まだありません（「注目」イベントの詳細画面から「インシデント化」できます）
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
