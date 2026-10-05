import { useState } from "react";
import { api, tokenStore } from "../api";
import type { AuthUser, SsoStatus } from "../types";

// SSO失敗時の理由コード（backend: sso.py の SsoError.reason）→ 利用者向けの説明
const SSO_ERRORS: Record<string, string> = {
  not_registered: "このアカウントはLogSeekerに登録されていません。管理者にSSOユーザーとしての登録を依頼してください。",
  ambiguous: "このメールアドレスに一致するユーザーが複数あります。管理者に連絡してください。",
  domain: "このアカウントのドメインはログインを許可されていません。組織のアカウントでログインしてください。",
  email: "アカウントのメールアドレスを確認できませんでした。",
  disabled: "このアカウントは無効化されています。管理者に連絡してください。",
  idp: "ログインがキャンセルされたか、ログイン先で拒否されました。",
  state: "ログインの有効期限が切れたか、不正なリクエストです。もう一度お試しください。",
  expired: "ログインの有効期限が切れました。もう一度お試しください。",
  token: "ログイン先からの応答を確認できませんでした。もう一度お試しください。",
  config: "SSOの設定に問題があります。管理者に連絡してください。",
};

export function Login({ onLoggedIn, sso, ssoError }: {
  onLoggedIn: (u: AuthUser) => void;
  sso?: SsoStatus;
  ssoError?: string | null;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(
    ssoError ? (SSO_ERRORS[ssoError] ?? "SSOでのログインに失敗しました。") : null);
  const [busy, setBusy] = useState(false);
  const providers = sso?.providers ?? [];

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
            {providers.length > 0 && (
              <>
                {/* ブラウザの画面遷移でIdPへ移る（fetchではない）。戻りは /?sso_code=... → App が交換する */}
                {providers.map((p) => (
                  <a key={p.id} className="btn btn-outline-secondary w-100 mb-2" href={`/api/sso/${p.id}/login`}>
                    {p.label} でログイン
                  </a>
                ))}
                <div className="hr-text my-3">またはパスワードで</div>
              </>
            )}
            <div className="mb-3">
              <label className="form-label" htmlFor="login-username">ユーザー名</label>
              <input className="form-control" id="login-username" name="username"
                autoComplete="username" value={username} autoFocus={providers.length === 0}
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
          </div>
        </form>
        <div className="text-center mt-3">
          <a href="?screen=administration" className="text-secondary small">管理者用ログインはこちら</a>
        </div>
      </div>
    </div>
  );
}
