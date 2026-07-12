import { useEffect, useState } from "react";
import { api } from "../api";
import type { AuditRow } from "../types";

const ACTION_LABEL: Record<string, string> = {
  login: "ログイン", logout: "ログアウト", "user.create": "ユーザー作成",
  "user.update": "ユーザー更新", "user.delete": "ユーザー削除", "auth.toggle": "認証切替",
  "sso.config": "SSO設定", "audit.download": "監査DL", "api.change": "変更操作",
};

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
          <strong>監査ログ</strong>：ログイン以降の<strong>変更操作・ログイン/ログアウト・ダウンロード</strong>を記録します
          （閲覧のみのGETは記録しません）。改ざん防止のため保存され、CSVで書き出せます。
        </div>
      </div>
      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">監査ログ</h3>
            <span className="card-subtitle ms-2 text-secondary">{total.toLocaleString()} 件</span>
            <div className="card-actions d-flex gap-2">
              <input className="form-control form-control-sm" placeholder="絞り込み（ユーザー/操作/IP…）"
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
                <th>日時</th><th>ユーザー</th><th>ロール</th><th>操作</th>
                <th>メソッド/パス</th><th>結果</th><th>対象/詳細</th><th>IP</th>
              </tr></thead>
              <tbody>
                {filtered.map((r) => (
                  <tr key={r.id}>
                    <td className="text-nowrap">{ts(r.at)}</td>
                    <td className="text-nowrap">{r.username ?? <span className="text-secondary">匿名</span>}</td>
                    <td className="text-nowrap"><span className="text-secondary">{r.role ?? "-"}</span></td>
                    <td className="text-nowrap">
                      <span className="badge bg-secondary-lt">{ACTION_LABEL[r.action] ?? r.action}</span>
                    </td>
                    <td className="text-nowrap small">
                      {r.method && <span className="text-secondary">{r.method} </span>}
                      <code>{r.path ?? ""}</code>
                    </td>
                    <td>
                      {r.status && (
                        <span className={`badge ${r.status === "success" || r.status?.startsWith("2")
                          ? "bg-green-lt" : r.status === "failure" || /^[45]/.test(r.status)
                          ? "bg-red-lt" : "bg-secondary-lt"}`}>{r.status}</span>
                      )}
                    </td>
                    <td className="small">{[r.target, r.detail].filter(Boolean).join(" / ") || "-"}</td>
                    <td className="text-nowrap small text-secondary">{r.ip ?? "-"}</td>
                  </tr>
                ))}
                {filtered.length === 0 && <tr><td colSpan={8} className="text-secondary text-center py-4">記録なし</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
