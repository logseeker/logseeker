import { useEffect, useState } from "react";
import { api } from "../api";
import type { AuditRow } from "../types";

const ROLE_LABEL: Record<string, string> = {
  viewer: "閲覧者", editor: "編集者", sysadmin: "システム管理者", admin: "管理者",
};

// 操作名はサーバー側(audit_log.py)で日本語化して返す（CSVと同じ表記にするため）。
// 成否は success/failure か HTTPステータスで入っている。
function isSuccess(s: string | null) {
  return s === "success" || !!s?.startsWith("2");
}

export function Audit() {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [total, setTotal] = useState(0);
  const [q, setQ] = useState("");
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.audit(1000).then((r) => { setRows(r.items); setTotal(r.total); })
      .catch((e) => setErr((e as Error).message));
  }, []);

  const ts = (s: string | null) => (s ? s.replace("T", " ").slice(0, 19) : "-");
  const filtered = q
    ? rows.filter((r) => JSON.stringify(r).toLowerCase().includes(q.toLowerCase()))
    : rows;

  if (err) return <div className="alert alert-danger">取得失敗: {err}</div>;

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info mb-0">
          <strong>監査ログ</strong>：ログイン/ログアウト、設定やデータの<strong>変更操作</strong>（何をどう変えたか）、
          エクスポート・ダウンロードを記録します。検索・画面の閲覧と、表示列などの個人の表示設定は記録しません。
          パスワードやAPIキーは「変更した」ことだけを記録し、値そのものは残しません。
        </div>
      </div>
      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">監査ログ</h3>
            <span className="card-subtitle ms-2 text-secondary">{total.toLocaleString()} 件</span>
            <div className="card-actions d-flex gap-2">
              <input className="form-control form-control-sm" placeholder="絞り込み（ユーザー/操作/対象/IP…）"
                value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 220 }} />
              <button className="btn btn-sm btn-outline-primary"
                onClick={() => api.downloadAuditCsv().catch((e) => setErr((e as Error).message))}>⬇ CSV</button>
              <button className="btn btn-sm btn-outline-secondary"
                onClick={() => api.downloadAuditJson().catch((e) => setErr((e as Error).message))}>⬇ JSON</button>
            </div>
          </div>
          <div className="table-responsive" style={{ maxHeight: "70vh" }}>
            <table className="table table-vcenter table-sm card-table">
              <thead><tr>
                <th>日時</th><th>ユーザー</th><th>操作</th><th>対象</th><th>内容</th><th>結果</th><th>IP</th>
              </tr></thead>
              <tbody>
                {filtered.map((r) => (
                  <tr key={r.id}>
                    <td className="text-nowrap">{ts(r.at)}</td>
                    <td className="text-nowrap">
                      {r.username ?? <span className="text-secondary">匿名</span>}
                      {r.role && <div className="small text-secondary">{ROLE_LABEL[r.role] ?? r.role}</div>}
                    </td>
                    <td className="text-nowrap" title={r.method || r.path ? `${r.method ?? ""} ${r.path ?? ""}` : undefined}>
                      <span className="badge bg-secondary-lt">{r.action_label ?? r.action}</span>
                    </td>
                    <td className="small" style={{ maxWidth: 260 }}>{r.target ?? <span className="text-secondary">-</span>}</td>
                    <td className="small" style={{ minWidth: 240 }}>
                      {/* サーバーは複数の変更点を " / " でつないで返す。1行1項目で見せる */}
                      {r.detail
                        ? r.detail.split(" / ").map((part, i) => <div key={i}>{part}</div>)
                        : <span className="text-secondary">-</span>}
                    </td>
                    <td className="text-nowrap">
                      {r.status && (
                        <span className={`badge ${isSuccess(r.status) ? "bg-green-lt" : "bg-red-lt"}`}
                          title={r.status}>
                          {isSuccess(r.status) ? "成功" : `失敗${/^\d+$/.test(r.status) ? ` (${r.status})` : ""}`}
                        </span>
                      )}
                    </td>
                    <td className="text-nowrap small text-secondary">{r.ip ?? "-"}</td>
                  </tr>
                ))}
                {filtered.length === 0 && <tr><td colSpan={7} className="text-secondary text-center py-4">記録なし</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
