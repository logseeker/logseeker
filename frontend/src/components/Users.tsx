import { useEffect, useState } from "react";
import { api } from "../api";
import type { AuthStatus, AuthUser, CreateUserResult, Role } from "../types";

const ROLE_OPTS: { v: Role; label: string; desc: string }[] = [
  { v: "viewer", label: "閲覧者", desc: "閲覧・ダウンロード" },
  { v: "editor", label: "編集者", desc: "+ インシデント/コメント作成" },
  { v: "sysadmin", label: "システム管理者", desc: "+ ライセンス/通知/IOC/API・監査閲覧・一般ユーザー作成" },
  { v: "admin", label: "管理者", desc: "+ 全ユーザー管理・昇格・認証ON/OFF・SSO" },
];

export function Users({ auth, onChanged }: { auth: AuthStatus; onChanged: () => void }) {
  const me = auth.user;
  const isAdmin = !auth.auth_required || me?.role === "admin";
  const [users, setUsers] = useState<AuthUser[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  // メール通知が有効なら「メールアドレス必須・パスワードは自動生成してメール送信」、
  // 無効なら従来通り「初期パスワードを管理者が手入力」に切り替える。
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [nu, setNu] = useState({ username: "", display_name: "", role: "viewer" as Role, email: "", password: "" });
  const [created, setCreated] = useState<CreateUserResult | null>(null);

  // sysadmin は viewer/editor のみ扱える。admin は全部。
  const assignable = ROLE_OPTS.filter((r) => isAdmin || r.v === "viewer" || r.v === "editor");

  const load = () => api.listUsers().then(setUsers).catch((e) => setErr((e as Error).message));
  useEffect(() => { load(); }, []);
  useEffect(() => { api.notifConfig().then((c) => setEmailEnabled(c.email_enabled)).catch(() => {}); }, []);

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(null), 2500); };
  const guard = async (fn: () => Promise<unknown>) => {
    setErr(null);
    try { await fn(); load(); onChanged(); } catch (e) { setErr((e as Error).message); }
  };

  const create = () => guard(async () => {
    const r = await api.createUser(nu);
    setNu({ username: "", display_name: "", role: "viewer", email: "", password: "" });
    if (emailEnabled) setCreated(r); else flash("ユーザーを作成しました");
  });
  const canCreate = nu.username && (emailEnabled ? nu.email : nu.password);

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info mb-0">
          <strong>ユーザー管理</strong>：ロールは 管理者 / システム管理者 / 編集者 / 閲覧者 の4段階。
          操作はすべて<strong>監査ログ</strong>に記録されます。
          {!auth.auth_required && <span className="text-secondary"> ※現在ログインは任意（OFF）。「システム状態」で必須化できます。</span>}
        </div>
      </div>

      {err && <div className="col-12"><div className="alert alert-danger py-2">{err}</div></div>}
      {msg && <div className="col-12"><div className="alert alert-success py-2">{msg}</div></div>}

      <div className="col-12">
        <div className="card">
          <div className="card-header"><h3 className="card-title">ユーザー一覧（{users.length}）</h3></div>
          <div className="table-responsive">
            <table className="table table-vcenter card-table">
              <thead><tr>
                <th>ユーザー名</th><th>表示名</th><th>ロール</th><th>状態</th><th>最終ログイン</th><th></th>
              </tr></thead>
              <tbody>
                {users.map((u) => {
                  const canManage = isAdmin || u.role === "viewer" || u.role === "editor";
                  return (
                    <tr key={u.id}>
                      <td className="text-nowrap">
                        {u.username}
                        {u.is_sso && <span className="badge bg-azure-lt ms-1">SSO</span>}
                        {me?.id === u.id && <span className="badge bg-blue-lt ms-1">自分</span>}
                      </td>
                      <td>{u.display_name ?? "-"}</td>
                      <td>
                        <select className="form-select form-select-sm w-auto" value={u.role}
                          disabled={!canManage}
                          onChange={(e) => guard(async () => { await api.updateUser(u.id, { role: e.target.value as Role }); flash("ロールを変更しました"); })}>
                          {assignable.map((r) => (
                            <option key={r.v} value={r.v}>{r.label}</option>
                          ))}
                        </select>
                      </td>
                      <td>
                        <label className="form-check form-switch mb-0">
                          <input className="form-check-input" type="checkbox" checked={u.enabled}
                            disabled={!canManage || me?.id === u.id}
                            onChange={(e) => guard(async () => { await api.updateUser(u.id, { enabled: e.target.checked }); })} />
                          <span className="form-check-label">{u.enabled ? "有効" : "無効"}</span>
                        </label>
                      </td>
                      <td className="text-secondary small">{u.last_login_at ? u.last_login_at.replace("T", " ").slice(0, 19) : "-"}</td>
                      <td className="text-end">
                        <button className="btn btn-sm" disabled={!canManage}
                          onClick={() => { const p = prompt(`「${u.username}」の新しいパスワード`); if (p) guard(async () => { await api.updateUser(u.id, { password: p }); flash("パスワードを再設定しました"); }); }}>
                          パスワード再設定
                        </button>
                        <button className="btn btn-sm btn-outline-danger ms-1"
                          disabled={!canManage || me?.id === u.id}
                          onClick={() => { if (confirm(`「${u.username}」を削除しますか？`)) guard(async () => { await api.deleteUser(u.id); flash("削除しました"); }); }}>
                          削除
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="col-12 col-lg-7">
        <div className="card">
          <div className="card-header"><h3 className="card-title">ユーザーを作成</h3></div>
          <div className="card-body">
            {created && (
              <div className="alert alert-success py-2 d-flex justify-content-between align-items-start">
                <div>✅「{created.username}」を作成し、仮パスワードを指定のメールアドレスに送信しました。</div>
                <button type="button" className="btn-close" onClick={() => setCreated(null)} />
              </div>
            )}
            <div className="row g-2">
              <div className="col-md-4">
                <label className="form-label">ユーザー名</label>
                <input className="form-control" value={nu.username} onChange={(e) => setNu({ ...nu, username: e.target.value })} />
              </div>
              <div className="col-md-4">
                <label className="form-label">表示名（任意）</label>
                <input className="form-control" value={nu.display_name} onChange={(e) => setNu({ ...nu, display_name: e.target.value })} />
              </div>
              {emailEnabled ? (
                <div className="col-md-4">
                  <label className="form-label">メールアドレス</label>
                  <input className="form-control" type="email" placeholder="仮パスワードを送信します"
                    value={nu.email} onChange={(e) => setNu({ ...nu, email: e.target.value })} />
                </div>
              ) : (
                <div className="col-md-4">
                  <label className="form-label">初期パスワード</label>
                  <input className="form-control" type="text" value={nu.password} onChange={(e) => setNu({ ...nu, password: e.target.value })} />
                </div>
              )}
              <div className="col-md-8">
                <label className="form-label">ロール</label>
                <select className="form-select" value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value as Role })}>
                  {assignable.map((r) => <option key={r.v} value={r.v}>{r.label} — {r.desc}</option>)}
                </select>
              </div>
              <div className="col-md-4 d-flex align-items-end">
                <button className="btn btn-primary w-100" disabled={!canCreate} onClick={create}>作成</button>
              </div>
            </div>
            <div className="text-secondary small mt-2">
              {emailEnabled
                ? "メール通知が有効なため、初期パスワードは自動生成してメールアドレス宛にのみ送信します（画面には表示されません）。"
                : "メール通知が無効なため、初期パスワードを直接入力してください。「通知」画面でメール通知を有効にすると、メールアドレス指定に切り替わります。"}
            </div>
          </div>
        </div>
      </div>

      <div className="col-12 col-lg-5">
        <div className="card">
          <div className="card-header"><h3 className="card-title">ロールの権限</h3></div>
          <div className="list-group list-group-flush">
            {ROLE_OPTS.map((r) => (
              <div className="list-group-item" key={r.v}>
                <strong>{r.label}</strong><div className="text-secondary small">{r.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
