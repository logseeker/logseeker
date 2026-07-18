import { useEffect, useState } from "react";
import { api } from "../api";
import type { AssetRow, AuthStatus } from "../types";

const EMPTY_FORM = { ip: "", label: "", description: "" };

// 資産（アセット）：Entities（観測された全IP）とは別に、「自社が保有するIPかどうか」を
// 軸にした一覧。ローカルIPは登録不要で自動判定、グローバルIPは手動登録したものだけを扱う。
export function Assets({ onEntity, auth }: {
  onEntity: (type: string, value: string) => void;
  auth?: AuthStatus;
}) {
  const [rows, setRows] = useState<AssetRow[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [editing, setEditing] = useState<Record<number, { label: string; description: string }>>({});
  const canManage = !auth?.auth_required
    || auth?.user?.role === "editor" || auth?.user?.role === "sysadmin" || auth?.user?.role === "admin";

  const load = () => api.assets().then(setRows).catch((e) => setErr((e as Error).message));
  useEffect(() => { load(); }, []);

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(null), 2500); };

  const create = async () => {
    setErr(null);
    try {
      await api.createAsset({ ip: form.ip, label: form.label || undefined, description: form.description || undefined });
      setForm(EMPTY_FORM); load(); flash("資産を登録しました");
    } catch (e) { setErr((e as Error).message); }
  };
  const startEdit = (r: AssetRow) => {
    if (r.id == null) return;
    setEditing({ ...editing, [r.id]: { label: r.label ?? "", description: r.description ?? "" } });
  };
  const saveEdit = async (id: number) => {
    const v = editing[id];
    if (!v) return;
    try {
      await api.updateAsset(id, { label: v.label || undefined, description: v.description || undefined });
      const { [id]: _drop, ...rest } = editing;
      setEditing(rest); load(); flash("更新しました");
    } catch (e) { setErr((e as Error).message); }
  };
  const remove = async (r: AssetRow) => {
    if (r.id == null) return;
    if (!confirm(`資産「${r.ip}」の登録を削除しますか？`)) return;
    try { await api.deleteAsset(r.id); load(); flash("削除しました"); }
    catch (e) { setErr((e as Error).message); }
  };

  const ts = (s: string | null) => (s ? s.replace("T", " ").slice(0, 19) : "-");
  const local = rows.filter((r) => r.scope === "local");
  const registered = rows.filter((r) => r.scope === "registered_global");

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="text-secondary small mb-1">
          自社が保有するIPの一覧です。プライベートIP（10.0.0.0/8 等）は自動判定して表示するため登録不要です。
          自前のVPS/クラウド/オフィス回線などのグローバルIPは、下のフォームから手動で登録してください。
          ログ上で観測された全てのIP（アクセス元IPも含む）を調査したい場合は「エンティティ」画面を使用してください。
        </div>
      </div>

      {err && <div className="col-12"><div className="alert alert-danger">{err}</div></div>}
      {msg && <div className="col-12"><div className="alert alert-success py-2">{msg}</div></div>}

      <div className="col-12">
        <div className="card">
          <div className="card-header"><h3 className="card-title">ローカルIP（自動判定・{local.length}）</h3></div>
          <div className="table-responsive">
            <table className="table table-vcenter table-sm card-table">
              <thead><tr><th>IP</th><th>バージョン</th><th className="text-end">件数</th><th>初回</th><th>最終</th><th></th></tr></thead>
              <tbody>
                {local.map((r) => (
                  <tr key={r.ip}>
                    <td>{r.ip}</td>
                    <td><span className="badge bg-secondary-lt">{r.ip_version}</span></td>
                    <td className="text-end">{r.count.toLocaleString()}</td>
                    <td className="text-nowrap">{ts(r.first_seen)}</td>
                    <td className="text-nowrap">{ts(r.last_seen)}</td>
                    <td className="text-end">
                      <button className="btn btn-sm btn-outline-secondary" onClick={() => onEntity("ip", r.ip)}>詳細</button>
                    </td>
                  </tr>
                ))}
                {local.length === 0 && <tr><td colSpan={6} className="text-secondary text-center py-4">なし</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="col-12">
        <div className="card">
          <div className="card-header"><h3 className="card-title">登録済みグローバルIP（{registered.length}）</h3></div>
          <div className="table-responsive">
            <table className="table table-vcenter table-sm card-table">
              <thead><tr><th>IP</th><th>バージョン</th><th>ラベル</th><th>説明</th><th className="text-end">件数</th><th>最終</th><th></th></tr></thead>
              <tbody>
                {registered.map((r) => {
                  const ed = r.id != null ? editing[r.id] : undefined;
                  return (
                    <tr key={r.ip}>
                      <td>{r.ip}</td>
                      <td><span className="badge bg-blue-lt">{r.ip_version}</span></td>
                      <td>{ed
                        ? <input className="form-control form-control-sm" value={ed.label}
                            onChange={(e) => setEditing({ ...editing, [r.id!]: { ...ed, label: e.target.value } })} />
                        : (r.label || "-")}</td>
                      <td>{ed
                        ? <input className="form-control form-control-sm" value={ed.description}
                            onChange={(e) => setEditing({ ...editing, [r.id!]: { ...ed, description: e.target.value } })} />
                        : (r.description || "-")}</td>
                      <td className="text-end">{r.count.toLocaleString()}</td>
                      <td className="text-nowrap">{ts(r.last_seen)}</td>
                      <td className="text-nowrap text-end">
                        <button className="btn btn-sm btn-outline-secondary me-1" onClick={() => onEntity("ip", r.ip)}>詳細</button>
                        {canManage && (ed
                          ? <button className="btn btn-sm btn-primary me-1" onClick={() => saveEdit(r.id!)}>保存</button>
                          : <button className="btn btn-sm btn-outline-secondary me-1" onClick={() => startEdit(r)}>編集</button>)}
                        {canManage && <button className="btn btn-sm btn-outline-danger" onClick={() => remove(r)}>削除</button>}
                      </td>
                    </tr>
                  );
                })}
                {registered.length === 0 && <tr><td colSpan={7} className="text-secondary text-center py-4">なし</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {canManage && (
        <div className="col-12">
          <div className="card border-primary">
            <div className="card-header"><h3 className="card-title">グローバルIPを資産として登録</h3></div>
            <div className="card-body">
              <div className="row g-2">
                <div className="col-md-4">
                  <label className="form-label">IPアドレス（v4/v6）</label>
                  <input className="form-control" value={form.ip} onChange={(e) => setForm({ ...form, ip: e.target.value })}
                    placeholder="例: 203.0.113.10 / 2001:db8::1" />
                </div>
                <div className="col-md-3">
                  <label className="form-label">ラベル（任意）</label>
                  <input className="form-control" value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })}
                    placeholder="例: 本番VPS" />
                </div>
                <div className="col-md-5">
                  <label className="form-label">説明（任意）</label>
                  <input className="form-control" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
                </div>
              </div>
              <button className="btn btn-primary mt-3" disabled={!form.ip} onClick={create}>登録</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
