import { useState } from "react";
import { api, tokenStore } from "../api";
import type { AuthUser, SsoStatus } from "../types";

export function Login({ onLoggedIn, sso }: {
  onLoggedIn: (u: AuthUser) => void;
  sso?: SsoStatus;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null); setBusy(true);
    try {
      const r = await api.login(username.trim(), password);
      tokenStore.set(r.token);
      onLoggedIn(r.user);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page page-center">
      <div className="container container-tight py-4" style={{ maxWidth: 420 }}>
        <div className="text-center mb-4">
          <h1 className="navbar-brand-autodark mb-1">LogSeeker</h1>
          <div className="text-secondary">ログシーカー — ログイン</div>
        </div>
        <form className="card card-md" onSubmit={submit}>
          <div className="card-body">
            <h2 className="h3 text-center mb-3">アカウントにログイン</h2>
            {err && <div className="alert alert-danger py-2">{err}</div>}
            <div className="mb-3">
              <label className="form-label" htmlFor="login-username">ユーザー名</label>
              <input className="form-control" id="login-username" name="username"
                autoComplete="username" value={username} autoFocus
                onChange={(e) => setUsername(e.target.value)} />
            </div>
            <div className="mb-3">
              <label className="form-label" htmlFor="login-password">パスワード</label>
              <input className="form-control" id="login-password" name="password"
                type="password" autoComplete="current-password" value={password}
                onChange={(e) => setPassword(e.target.value)} />
            </div>
            <div className="form-footer">
              <button type="submit" className="btn btn-primary w-100" disabled={busy || !username || !password}>
                {busy ? "確認中…" : "ログイン"}
              </button>
            </div>
            {sso?.enabled && sso?.configured && (
              <div className="text-center mt-3">
                {sso.implemented
                  ? <a className="btn btn-outline-secondary w-100" href="/api/sso/login">SSOでログイン</a>
                  : <span className="text-secondary small">SSOは設定済みですが現バージョンでは未接続です</span>}
              </div>
            )}
          </div>
        </form>
        <div className="text-center mt-3">
          <a href="?screen=administration" className="text-secondary small">管理者用ログインはこちら</a>
        </div>
      </div>
    </div>
  );
}
