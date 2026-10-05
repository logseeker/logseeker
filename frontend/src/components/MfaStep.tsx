import { useEffect, useState } from "react";
import { api } from "../api";
import type { AuthUser, MfaSetupInfo } from "../types";

// 管理者ログインの2段階目（backend: mfa.py）。パスワードが通った後に表示する。
//  mode="verify": 認証アプリの6桁コード（またはリカバリーコード）を入力
//  mode="setup" : 初回／リセット後。QRコードを読み取って登録 → リカバリーコードを控えてもらう
export function MfaStep({ mfaToken, mode, onDone, onCancel }: {
  mfaToken: string;
  mode: "verify" | "setup";
  onDone: (token: string, user: AuthUser) => void;
  onCancel: () => void;
}) {
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [setup, setSetup] = useState<MfaSetupInfo | null>(null);
  const [showKey, setShowKey] = useState(false);
  // 登録完了後、リカバリーコードを控えてもらってから画面に入る
  const [done, setDone] = useState<{ token: string; user: AuthUser; recovery: string[] } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [expired, setExpired] = useState(false);
  const [busy, setBusy] = useState(false);

  const fail = (e: unknown) => {
    const m = (e as Error).message;
    setErr(m);
    if (m.includes("有効期限") || m.includes("やり直") || m.includes("ロック")) setExpired(true);
  };

  useEffect(() => {
    if (mode === "setup") api.mfaSetupStart(mfaToken).then(setSetup).catch(fail);
  }, [mfaToken, mode]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null); setBusy(true);
    try {
      if (mode === "setup") {
        const r = await api.mfaSetupConfirm(mfaToken, code);
        setDone({ token: r.token, user: r.user, recovery: r.recovery_codes });
      } else {
        const r = await api.mfaVerify(mfaToken, code);
        if (r.recovery_codes_left !== undefined && r.recovery_codes_left <= 3) {
          alert(`リカバリーコードの残りが${r.recovery_codes_left}個です。ユーザー管理で「MFAリセット」を行い、認証アプリを登録し直してください。`);
        }
        onDone(r.token, r.user);
      }
    } catch (e) {
      fail(e);
      setCode("");
    } finally {
      setBusy(false);
    }
  };

  if (done) {
    return (
      <div className="card-body">
        <h2 className="h3 mb-2">リカバリーコードを保管してください</h2>
        <div className="text-secondary small mb-3">
          スマートフォンを紛失した時など、認証アプリが使えない時に1回ずつ使えるコードです。
          <strong>この画面を閉じると二度と表示できません。</strong>パスワード管理ツールや紙に控えて、安全な場所に保管してください。
        </div>
        <pre className="bg-light p-3 rounded font-monospace text-center mb-3" style={{ columns: 2 }}>
          {done.recovery.join("\n")}
        </pre>
        <button type="button" className="btn btn-primary w-100" onClick={() => onDone(done.token, done.user)}>
          控えました。続ける
        </button>
      </div>
    );
  }

  return (
    <form className="card-body" onSubmit={submit}>
      <h2 className="h3 text-center mb-2">{mode === "setup" ? "認証アプリの登録" : "2段階認証"}</h2>
      {err && <div className="alert alert-danger py-2">{err}</div>}
      {expired ? (
        <button type="button" className="btn btn-outline-secondary w-100" onClick={onCancel}>最初からやり直す</button>
      ) : (
        <>
          {mode === "setup" ? (
            <>
              <div className="text-secondary small mb-2">
                管理者アカウントは2段階認証が必須です。Google Authenticator / Microsoft Authenticator 等の
                認証アプリでQRコードを読み取り、表示された6桁のコードを入力してください。
              </div>
              {setup ? (
                <div className="text-center mb-2">
                  <img src={setup.qr_svg} alt="認証アプリ登録用のQRコード" width={200} height={200} />
                  <div>
                    <button type="button" className="btn btn-link btn-sm" onClick={() => setShowKey((v) => !v)}>
                      QRコードを読み取れない場合（キーを手入力）
                    </button>
                  </div>
                  {showKey && <code className="d-block user-select-all">{setup.secret.match(/.{1,4}/g)?.join(" ")}</code>}
                </div>
              ) : !err && <div className="text-secondary text-center my-4">準備中…</div>}
            </>
          ) : (
            <div className="text-secondary small mb-2">
              {useRecovery
                ? "控えておいたリカバリーコード（xxxx-xxxx-xxxx）を入力してください。1つにつき1回だけ使えます。"
                : "認証アプリに表示されている6桁のコードを入力してください。"}
            </div>
          )}
          <div className="mb-3">
            <input className="form-control form-control-lg text-center font-monospace" autoFocus
              autoComplete="one-time-code" inputMode={useRecovery ? "text" : "numeric"}
              placeholder={useRecovery ? "xxxx-xxxx-xxxx" : "123456"} maxLength={useRecovery ? 20 : 6}
              value={code} onChange={(e) => setCode(useRecovery ? e.target.value : e.target.value.replace(/\D/g, ""))} />
          </div>
          <button type="submit" className="btn btn-primary w-100"
            disabled={busy || (useRecovery ? code.length < 12 : code.length !== 6) || (mode === "setup" && !setup)}>
            {busy ? "確認中…" : mode === "setup" ? "登録する" : "確認"}
          </button>
          <div className="d-flex justify-content-between mt-2">
            {mode === "verify" ? (
              <button type="button" className="btn btn-link btn-sm px-0"
                onClick={() => { setUseRecovery((v) => !v); setCode(""); setErr(null); }}>
                {useRecovery ? "認証アプリのコードを使う" : "認証アプリが使えない場合"}
              </button>
            ) : <span />}
            <button type="button" className="btn btn-link btn-sm px-0 text-secondary" onClick={onCancel}>キャンセル</button>
          </div>
        </>
      )}
    </form>
  );
}
