import { useEffect, useState } from "react";
import { api, tokenStore } from "../api";
import type { AuthUser, IpAllowEntry, IpRestrictStatus, SsoStatus } from "../types";

// 通常のログイン後画面（左メニュー）とは完全に切り離した、管理者(admin)専用の管理パネル。
// ?screen=administration でのみ到達し、左メニューには一切出さない。admin以外のロールは
// パスワードが合っていてもここでは弾く（backend: /api/auth/admin-login）。
// 既にadminロールでログイン済み（通常アプリ・別タブ問わず同じブラウザの既存セッション）なら
// 再ログインは求めず、そのまま管理パネルへ入る。
export function Administration() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [checking, setChecking] = useState(true);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!tokenStore.get()) { setChecking(false); return; }
    api.authStatus()
      .then((s) => { if (s.user?.role === "admin") setUser(s.user); })
      .catch(() => {})
      .finally(() => setChecking(false));
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      const r = await api.adminLogin(username.trim(), password);
      tokenStore.set(r.token);
      setUser(r.user);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (checking) {
    return <div className="page page-center"><div className="text-secondary">確認中…</div></div>;
  }

  if (!user) {
    return (
      <div className="page page-center">
        <div className="container container-tight py-4" style={{ maxWidth: 420 }}>
          <div className="text-center mb-4">
            <h1 className="navbar-brand-autodark mb-1">LogSeeker</h1>
            <div className="text-secondary">管理パネル</div>
          </div>
          <form className="card card-md" onSubmit={submit}>
            <div className="card-body">
              <h2 className="h3 text-center mb-3">管理者ログイン</h2>
              <div className="text-secondary small mb-3">
                通常のログイン画面とは別の入口です。管理者(admin)ロールのアカウント以外は
                ログインできません。
              </div>
              {err && <div className="alert alert-danger py-2">{err}</div>}
              <div className="mb-3">
                <label className="form-label" htmlFor="admin-username">ユーザー名</label>
                <input className="form-control" id="admin-username" name="username"
                  autoComplete="username" value={username} autoFocus
                  onChange={(e) => setUsername(e.target.value)} />
              </div>
              <div className="mb-3">
                <label className="form-label" htmlFor="admin-password">パスワード</label>
                <input className="form-control" id="admin-password" name="password"
                  type="password" autoComplete="current-password" value={password}
                  onChange={(e) => setPassword(e.target.value)} />
              </div>
              <div className="form-footer">
                <button type="submit" className="btn btn-primary w-100" disabled={busy || !username || !password}>
                  {busy ? "確認中…" : "管理者ログイン"}
                </button>
              </div>
              <div className="text-center mt-3">
                <a href="?screen=dashboard" className="text-secondary small">← 通常の画面に戻る</a>
              </div>
            </div>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="page page-center">
      <div className="container py-4" style={{ maxWidth: 900 }}>
        <div className="d-flex align-items-center mb-3">
          <h2 className="mb-0">管理パネル</h2>
          <span className="text-secondary ms-2">（{user.display_name || user.username} としてログイン中）</span>
          <a href="?screen=dashboard" className="btn btn-sm btn-outline-secondary ms-auto">通常の画面へ</a>
        </div>
        <div className="row row-cards">
          <div className="col-12"><AdminSecurity /></div>
          <div className="col-12"><AdminIpRestrict /></div>
        </div>
      </div>
    </div>
  );
}

// ログイン必須ON/OFF と SSO 設定（admin専用）
function AdminSecurity() {
  const [authRequired, setAuthRequired] = useState(false);
  const [sso, setSso] = useState<SsoStatus | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [form, setForm] = useState({ issuer: "", client_id: "", client_secret: "", redirect_uri: "", allowed_domains: "", auto_provision_role: "viewer", enabled: false });

  const loadAuthStatus = () => api.authStatus().then((s) => setAuthRequired(s.auth_required)).catch(() => {});

  useEffect(() => {
    loadAuthStatus();
    api.getSso().then((s) => {
      setSso(s);
      setForm({ issuer: s.issuer, client_id: s.client_id, client_secret: "", redirect_uri: s.redirect_uri, allowed_domains: s.allowed_domains, auto_provision_role: s.auto_provision_role, enabled: s.enabled });
    }).catch(() => {});
  }, []);

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(null), 2500); };
  const toggleAuth = async (enabled: boolean) => {
    setErr(null);
    try { await api.toggleAuth(enabled); loadAuthStatus(); flash(enabled ? "ログイン必須にしました" : "ログイン不要にしました"); }
    catch (e) { setErr((e as Error).message); }
  };
  const saveSso = async () => {
    setErr(null);
    try { const r = await api.saveSso(form); flash(r.note); api.getSso().then(setSso); }
    catch (e) { setErr((e as Error).message); }
  };

  return (
    <div className="card border-primary">
      <div className="card-header"><h3 className="card-title">🔐 セキュリティ設定</h3></div>
      <div className="card-body">
        {err && <div className="alert alert-danger py-2">{err}</div>}
        {msg && <div className="alert alert-success py-2">{msg}</div>}

        <div className="mb-4">
          <label className="form-check form-switch">
            <input className="form-check-input" type="checkbox" checked={authRequired}
              onChange={(e) => toggleAuth(e.target.checked)} />
            <span className="form-check-label">
              <strong>ログインを必須にする</strong>
              <div className="text-secondary small">
                OFF＝誰でも全操作可（デモ）。ON＝ロールで制御。ONにする前に
                <a href="?screen=users" className="text-primary"> ユーザー管理画面</a>でユーザーを作成してください。
              </div>
            </span>
          </label>
        </div>

        <hr />
        <h4 className="mb-1">SSO（OIDC）</h4>
        <div className="text-secondary small mb-3">
          {sso?.implemented
            ? "有効化するとログイン画面にSSOボタンが出ます。"
            : "現バージョンは設定の保管のみ（実接続は未実装）。Google/Azure AD(Entra)/Keycloak等のOIDCを想定。"}
        </div>
        <div className="row g-2">
          <div className="col-md-6">
            <label className="form-label">Issuer (discovery URL)</label>
            <input className="form-control" placeholder="https://accounts.google.com" value={form.issuer}
              onChange={(e) => setForm({ ...form, issuer: e.target.value })} />
          </div>
          <div className="col-md-6">
            <label className="form-label">Client ID</label>
            <input className="form-control" value={form.client_id} onChange={(e) => setForm({ ...form, client_id: e.target.value })} />
          </div>
          <div className="col-md-6">
            <label className="form-label">Client Secret {sso?.has_secret && <span className="text-secondary small">(設定済み・変更時のみ入力)</span>}</label>
            <input className="form-control" type="password" value={form.client_secret} onChange={(e) => setForm({ ...form, client_secret: e.target.value })} />
          </div>
          <div className="col-md-6">
            <label className="form-label">Redirect URI</label>
            <input className="form-control" placeholder="https://<自分のホスト>/api/sso/callback" value={form.redirect_uri}
              onChange={(e) => setForm({ ...form, redirect_uri: e.target.value })} />
          </div>
          <div className="col-md-6">
            <label className="form-label">許可ドメイン（任意・カンマ区切り）</label>
            <input className="form-control" placeholder="example.co.jp" value={form.allowed_domains}
              onChange={(e) => setForm({ ...form, allowed_domains: e.target.value })} />
          </div>
          <div className="col-md-3">
            <label className="form-label">自動作成ロール</label>
            <select className="form-select" value={form.auto_provision_role} onChange={(e) => setForm({ ...form, auto_provision_role: e.target.value })}>
              <option value="viewer">閲覧者</option><option value="editor">編集者</option>
            </select>
          </div>
          <div className="col-md-3 d-flex align-items-end">
            <label className="form-check form-switch mb-2">
              <input className="form-check-input" type="checkbox" checked={form.enabled}
                onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
              <span className="form-check-label">SSO有効</span>
            </label>
          </div>
        </div>
        <button className="btn btn-primary mt-3" onClick={saveSso}>SSO設定を保存</button>
      </div>
    </div>
  );
}

// 管理パネル(?screen=administration)へのアクセスそのもののIP制限（アプリ層。admin専用）。
// SSHのAllowUsers/送信元制限や、WordPress管理画面のIP制限と同じ発想＝「そもそもログイン試行自体を
// そのIP以外弾く」もの。通常のログイン後画面（ユーザー管理・監査ログ等）はロール(sysadmin以上)だけで
// 守り、この対象外。
function AdminIpRestrict() {
  const [st, setSt] = useState<IpRestrictStatus | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [entries, setEntries] = useState<IpAllowEntry[]>([]);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const load = () => api.getIpRestrict().then((s) => {
    setSt(s);
    setEnabled(s.enabled);
    setEntries(s.allowlist.length ? s.allowlist : []);
  }).catch((e) => setErr((e as Error).message));

  useEffect(() => { load(); }, []);

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(null), 3000); };
  const addEntry = () => setEntries((prev) => [...prev, { cidr: "", label: "" }]);
  const updateEntry = (i: number, patch: Partial<IpAllowEntry>) =>
    setEntries((prev) => prev.map((e, idx) => (idx === i ? { ...e, ...patch } : e)));
  const removeEntry = (i: number) => setEntries((prev) => prev.filter((_, idx) => idx !== i));
  const addMyIp = () => {
    if (!st?.your_ip) return;
    setEntries((prev) => [...prev, { cidr: `${st.your_ip}/32`, label: "自分のIP" }]);
  };

  const save = async () => {
    setErr(null);
    setSaving(true);
    try {
      const result = await api.saveIpRestrict({
        enabled,
        allowlist: entries.filter((e) => e.cidr.trim()),
      });
      setSt(result);
      setEnabled(result.enabled);
      setEntries(result.allowlist);
      flash("保存しました");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  if (!st) {
    return (
      <div className="card border-primary">
        <div className="card-header"><h3 className="card-title">🌐 IPアクセス制限（任意）</h3></div>
        <div className="card-body">
          {err ? <div className="alert alert-danger py-2 mb-0">取得失敗: {err}</div>
               : <div className="text-secondary">読み込み中…</div>}
        </div>
      </div>
    );
  }

  return (
    <div className="card border-primary">
      <div className="card-header"><h3 className="card-title">🌐 IPアクセス制限（任意）</h3></div>
      <div className="card-body">
        {err && <div className="alert alert-danger py-2">{err}</div>}
        {msg && <div className="alert alert-success py-2">{msg}</div>}
        <div className="text-secondary small mb-3">
          この管理パネル（このログイン画面自体）へのアクセスを、許可したIP/CIDR以外は
          拒否できます。SSHの送信元IP制限やWordPress管理画面のIP制限と同じ発想です。
          通常のログイン後画面（ユーザー管理・監査ログ等）はロールだけで守られ、この対象外です。
          既定はOFF＝無効。
        </div>
        <div className="mb-3">
          現在検出しているあなたのIP：
          {st.your_ip
            ? <code className="ms-1">{st.your_ip}</code>
            : <span className="text-danger ms-1">検出できません（リバースプロキシがX-Forwarded-Forを転送しているか確認してください）</span>}
          {st.your_ip && <button className="btn btn-sm btn-outline-primary ms-2" onClick={addMyIp}>許可リストに追加</button>}
        </div>

        <div className="mb-4">
          <label className="form-check form-switch">
            <input className="form-check-input" type="checkbox" checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)} />
            <span className="form-check-label">
              <strong>管理パネルへのIPアクセス制限を有効にする</strong>
              <div className="text-secondary small">
                ONにする前に、下の許可リストに少なくとも今のあなたのIPを追加してください
                （自分自身がロックアウトされるのを防ぐため）。
              </div>
            </span>
          </label>
        </div>

        <div className="mb-2">
          <label className="form-label">許可IP / CIDR一覧</label>
          {entries.map((e, i) => (
            <div className="row g-2 mb-2" key={i}>
              <div className="col-md-4">
                <input className="form-control" placeholder="例: 203.0.113.5/32 または 192.168.1.0/24"
                  value={e.cidr} onChange={(ev) => updateEntry(i, { cidr: ev.target.value })} />
              </div>
              <div className="col-md-5">
                <input className="form-control" placeholder="ラベル（任意・例: 事務所）"
                  value={e.label} onChange={(ev) => updateEntry(i, { label: ev.target.value })} />
              </div>
              <div className="col-md-3">
                <button className="btn btn-outline-danger" onClick={() => removeEntry(i)}>削除</button>
              </div>
            </div>
          ))}
          <button className="btn btn-sm btn-outline-secondary" onClick={addEntry}>+ IP/CIDRを追加</button>
        </div>

        <button className="btn btn-primary mt-3" onClick={save} disabled={saving}>
          {saving ? "保存中…" : "IPアクセス制限を保存"}
        </button>
      </div>
    </div>
  );
}
