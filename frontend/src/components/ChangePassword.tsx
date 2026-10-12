import { useState } from "react";
import { api } from "../api";
import { isPasswordCompliant, PasswordChecklist } from "../passwordPolicy";
import type { AuthUser } from "../types";

// パスワードが要件を満たしていない／仮パスワードの管理者に出す、変更必須の画面
// （backend: password_policy.py。変更するまで他のAPIは 403 になる）。
export function ChangePassword({ user, onDone, onLogout }: {
  user: AuthUser;
  onDone: (u: AuthUser) => void;
  onLogout: () => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const mismatch = confirm.length > 0 && next !== confirm;
  const can = current && isPasswordCompliant(next) && next === confirm && !busy;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null); setBusy(true);
    try {
      const r = await api.changePassword(current, next);
      onDone(r.user);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page page-center">
      <div className="container container-tight py-4" style={{ maxWidth: 460 }}>
        <div className="text-center mb-4">
          <h1 className="navbar-brand-autodark mb-1">LogSeeker</h1>
          <div className="text-secondary">パスワードの変更</div>
        </div>
        <form className="card card-md" onSubmit={submit}>
          <div className="card-body">
            <h2 className="h3 mb-2">パスワードを変更してください</h2>
            <div className="text-secondary small mb-3">
              「{user.username}」のパスワードは、要件を満たしていないか、仮のパスワードです。
              変更するまで他の操作はできません。
            </div>
            {err && <div className="alert alert-danger py-2">{err}</div>}
            <div className="mb-3">
              <label className="form-label" htmlFor="pw-current">現在のパスワード</label>
              <input className="form-control" id="pw-current" type="password" autoComplete="current-password"
                autoFocus value={current} onChange={(e) => setCurrent(e.target.value)} />
            </div>
            <div className="mb-2">
              <label className="form-label" htmlFor="pw-new">新しいパスワード</label>
              <input className="form-control" id="pw-new" type="password" autoComplete="new-password"
                value={next} onChange={(e) => setNext(e.target.value)} />
            </div>
            <div className="mb-3"><PasswordChecklist password={next} /></div>
            <div className="mb-3">
              <label className="form-label" htmlFor="pw-confirm">新しいパスワード（確認）</label>
              <input className={`form-control ${mismatch ? "is-invalid" : ""}`} id="pw-confirm" type="password"
                autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
              {mismatch && <div className="invalid-feedback">新しいパスワードと一致しません</div>}
            </div>
            <button type="submit" className="btn btn-primary w-100" disabled={!can}>
              {busy ? "変更中…" : "変更する"}
            </button>
            <div className="text-center mt-3">
              <button type="button" className="btn btn-link btn-sm text-secondary" onClick={onLogout}>ログアウト</button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
