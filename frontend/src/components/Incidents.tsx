import { useEffect, useState } from "react";
import { api } from "../api";
import { stLabel } from "../labels";
import type { IncidentDetail, IncidentRow } from "../types";

const STATUS_LABEL: Record<string, string> = {
  open: "未対応", investigating: "調査中", benign: "問題なし",
  false_positive: "誤検知", resolved: "対応済", archived: "アーカイブ",
};

export function Incidents() {
  const [rows, setRows] = useState<IncidentRow[]>([]);
  const [sel, setSel] = useState<number | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [title, setTitle] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const reload = () => api.incidents().then(setRows).catch((e) => setErr((e as Error).message));
  useEffect(() => { reload(); }, []);
  useEffect(() => {
    if (sel == null) { setDetail(null); return; }
    api.incident(sel).then(setDetail).catch(() => setDetail(null));
  }, [sel]);

  const create = async () => {
    if (!title.trim()) return;
    const { id } = await api.createIncident({ title: title.trim() });
    setTitle(""); await reload(); setSel(id);
  };

  return (
    <div className="row row-cards">
      {err && <div className="col-12"><div className="alert alert-danger">{err}</div></div>}
      <div className="col-lg-5">
        <div className="card">
          <div className="card-header"><h3 className="card-title">インシデント</h3></div>
          <div className="card-body border-bottom">
            <div className="input-group">
              <input className="form-control" placeholder="新規インシデント名" value={title}
                onChange={(e) => setTitle(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") create(); }} />
              <button className="btn btn-primary" onClick={create}>作成</button>
            </div>
          </div>
          <table className="table table-vcenter card-table table-hover">
            <thead><tr><th>タイトル</th><th>状態</th><th className="text-end">件数</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} style={{ cursor: "pointer" }} className={sel === r.id ? "table-active" : ""}
                  onClick={() => setSel(r.id)}>
                  <td>{r.title}</td>
                  <td><span className="badge bg-azure-lt">{STATUS_LABEL[r.status] ?? r.status}</span></td>
                  <td className="text-end">{r.event_count}</td>
                </tr>
              ))}
              {rows.length === 0 && <tr><td colSpan={3} className="text-secondary text-center py-4">まだありません</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      <div className="col-lg-7">
        {!detail && <div className="card"><div className="empty"><p className="empty-title">インシデントを選択</p>
          <p className="empty-subtitle text-secondary">調査対象イベントは、各イベントの詳細「コメント」タブから追加できます。</p></div></div>}
        {detail && (
          <div className="card">
            <div className="card-header"><h3 className="card-title">{detail.title}</h3>
              <span className="badge bg-azure-lt ms-2">{STATUS_LABEL[detail.status] ?? detail.status}</span></div>
            <div className="table-responsive" style={{ maxHeight: 480 }}>
              <table className="table table-vcenter table-sm card-table">
                <thead><tr><th>時刻</th><th>ログソース</th><th>種別</th><th>イベント</th><th>メッセージ</th><th>メモ</th></tr></thead>
                <tbody>
                  {detail.events.map((e) => (
                    <tr key={e.id}>
                      <td className="text-nowrap">{e.event_time ? e.event_time.replace("T", " ").slice(0, 19) : "-"}</td>
                      <td className="text-nowrap">{e.source_name}</td>
                      <td className="text-nowrap">{stLabel(e.source_type)}</td>
                      <td className="text-nowrap">{e.event_action}</td>
                      <td className="text-truncate" style={{ maxWidth: 260 }}>{e.message}</td>
                      <td className="text-secondary">{e.note}</td>
                    </tr>
                  ))}
                  {detail.events.length === 0 && <tr><td colSpan={6} className="text-secondary text-center py-4">イベント未登録</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
