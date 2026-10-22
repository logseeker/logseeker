import { useEffect, useState } from "react";
import { api } from "../api";
import type { M365Status, M365TestResult } from "../types";
import { fmtTime } from "../labels";

// Management Activity API のコンテンツ種別 → 画面の表示名
const TYPE_LABEL: Record<string, string> = {
  "Audit.AzureActiveDirectory": "Entra ID（サインイン・ユーザー/アプリの管理操作）",
  "Audit.Exchange": "Exchange（メールボックスの操作・管理コマンド）",
  "Audit.SharePoint": "SharePoint / OneDrive（ファイルの操作・共有）",
  "Audit.General": "その他（Teams・Copilot・Defender 等）",
  "DLP.All": "DLP（機密情報の検出。権限 ActivityFeed.ReadDlp が別に必要）",
};

const SUB_BADGE: Record<string, string> = { enabled: "bg-green-lt", disabled: "bg-yellow-lt" };

// 外部連携（コネクタ）。現在は Microsoft 365 の統合監査ログのみ（backend/app/m365_connector.py）。
export function Connectors() {
  const [st, setSt] = useState<M365Status | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [form, setForm] = useState({ enabled: false, tenant_id: "", client_id: "", client_secret: "",
    content_types: [] as string[], interval_min: 15 });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [test, setTest] = useState<M365TestResult | null>(null);

  const apply = (s: M365Status) => {
    setSt(s);
    setForm({ enabled: s.enabled, tenant_id: s.tenant_id, client_id: s.client_id, client_secret: "",
      content_types: s.content_types, interval_min: s.interval_min });
  };
  const load = () => api.m365Status().then(apply).catch((e) => setErr((e as Error).message));
  useEffect(() => { load(); }, []);

  // 取得中は状態を数秒おきに取り直す（取得はサーバー側のバックグラウンドで動く）
  useEffect(() => {
    if (!st?.running) return;
    const t = setInterval(() => api.m365Status().then(setSt).catch(() => {}), 3000);
    return () => clearInterval(t);
  }, [st?.running]);

  const toggleType = (t: string) => setForm((f) => ({
    ...f, content_types: f.content_types.includes(t) ? f.content_types.filter((x) => x !== t) : [...f.content_types, t],
  }));

  const save = async () => {
    setBusy(true); setMsg(null);
    try {
      apply(await api.m365Save({ ...form, client_secret: form.client_secret || undefined }));
      setMsg("保存しました");
    } catch (e) { setMsg((e as Error).message); }
    finally { setBusy(false); }
  };
  const runTest = async () => {
    setBusy(true); setTest(null);
    try { setTest(await api.m365Test()); }
    catch (e) { setTest({ ok: false, message: (e as Error).message }); }
    finally { setBusy(false); }
  };
  const runNow = async () => {
    setMsg(null);
    try {
      const r = await api.m365Run();
      setMsg(r.started ? "取得を開始しました（完了すると最終取得の欄が更新されます）" : "すでに取得中です");
      load();
    } catch (e) { setMsg((e as Error).message); }
  };

  if (err) return <div className="alert alert-danger">取得失敗: {err}</div>;
  if (!st) return <div className="text-secondary">読み込み中…</div>;
  const dirty = form.enabled !== st.enabled || form.tenant_id !== st.tenant_id || form.client_id !== st.client_id
    || !!form.client_secret || form.interval_min !== st.interval_min
    || form.content_types.join() !== st.content_types.join();

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Microsoft 365 監査ログ</h3>
            <div className="card-actions d-flex gap-2">
              {st.running && <span className="badge bg-blue-lt">取得中…</span>}
              {st.enabled ? <span className="badge bg-green-lt">自動取得: 有効</span> : <span className="badge bg-secondary-lt">自動取得: 無効</span>}
            </div>
          </div>
          <div className="card-body d-flex flex-wrap gap-4">
            <div><div className="subheader">取り込み済み</div><div className="h2 mb-0">{st.event_count.toLocaleString()} 件</div></div>
            <div><div className="subheader">直近24時間</div><div className="h2 mb-0">{st.event_count_24h.toLocaleString()} 件</div></div>
            <div className="flex-fill">
              <div className="subheader">最終取得</div>
              <div>{st.last_run_at ? fmtTime(st.last_run_at) : "未実行"}</div>
              {st.last_status && <div className={`small ${st.last_ok ? "text-secondary" : "text-danger"}`}>{st.last_status}</div>}
            </div>
          </div>
        </div>
      </div>

      <div className="col-lg-7">
        <div className="card">
          <div className="card-header"><h3 className="card-title">接続設定</h3></div>
          <div className="card-body">
            <label className="form-label">テナントID（ディレクトリID）</label>
            <input className="form-control mb-2" value={form.tenant_id} placeholder="00000000-0000-0000-0000-000000000000"
              onChange={(e) => setForm({ ...form, tenant_id: e.target.value })} />
            <label className="form-label">クライアントID（アプリケーションID）</label>
            <input className="form-control mb-2" value={form.client_id} placeholder="00000000-0000-0000-0000-000000000000"
              onChange={(e) => setForm({ ...form, client_id: e.target.value })} />
            <label className="form-label">クライアントシークレット</label>
            <input type="password" className="form-control mb-3" value={form.client_secret} autoComplete="new-password"
              placeholder={st.has_secret ? "●●●（変更する場合のみ入力）" : "シークレットの値を入力"}
              onChange={(e) => setForm({ ...form, client_secret: e.target.value })} />

            <div className="form-label">取得するログ</div>
            {st.all_content_types.map((t) => (
              <label className="form-check" key={t}>
                <input className="form-check-input" type="checkbox" checked={form.content_types.includes(t)} onChange={() => toggleType(t)} />
                <span className="form-check-label">{TYPE_LABEL[t] ?? t}</span>
              </label>
            ))}

            <div className="d-flex flex-wrap align-items-center gap-3 mt-3">
              <label className="ctl">取得間隔
                <select className="form-select" value={form.interval_min} onChange={(e) => setForm({ ...form, interval_min: Number(e.target.value) })}>
                  {st.intervals.map((m) => <option key={m} value={m}>{m}分ごと</option>)}
                </select>
              </label>
              <label className="form-check form-switch mb-0">
                <input className="form-check-input" type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />
                <span className="form-check-label">自動取得を有効にする</span>
              </label>
            </div>
          </div>
          <div className="card-footer d-flex flex-wrap gap-2 align-items-center">
            <button className="btn btn-primary" onClick={save} disabled={busy || !dirty}>保存</button>
            <button className="btn btn-outline-secondary" onClick={runTest} disabled={busy || dirty}
              title={dirty ? "先に保存してください" : ""}>接続テスト</button>
            <button className="btn btn-outline-primary" onClick={runNow} disabled={busy || dirty || st.running}
              title={dirty ? "先に保存してください" : ""}>今すぐ取得</button>
            {msg && <span className="text-secondary small">{msg}</span>}
          </div>
          {test && (
            <div className={`card-body border-top ${test.ok ? "" : "text-danger"}`}>
              <div>{test.ok ? "✓ " : "✗ "}{test.message}</div>
              {test.subscriptions && (
                <div className="mt-2 d-flex flex-wrap gap-2">
                  {Object.entries(test.subscriptions).map(([t, s]) => (
                    <span key={t} className={`badge ${SUB_BADGE[s] ?? "bg-secondary-lt"}`}>{t}: {s}</span>
                  ))}
                </div>
              )}
              {test.ok && <div className="text-secondary small mt-2">「未購読」の種別は、最初の取得のときに購読を開始します（開始してから実際にログが届くまで最大12時間ほどかかります）。</div>}
            </div>
          )}
        </div>
      </div>

      <div className="col-lg-5">
        <div className="card">
          <div className="card-header"><h3 className="card-title">Entra ID 側の準備</h3></div>
          <div className="card-body small">
            <ol className="ps-3 mb-2">
              <li>Microsoft Purview で監査が有効になっていることを確認する（既定で有効）</li>
              <li>Entra 管理センター →「アプリの登録」→「新規登録」（名前は任意。リダイレクトURIは不要）</li>
              <li>「APIのアクセス許可」→「アクセス許可の追加」→「Office 365 Management APIs」→「アプリケーションの許可」で <code>ActivityFeed.Read</code> を追加（DLPも取るなら <code>ActivityFeed.ReadDlp</code>）</li>
              <li>「&lt;テナント名&gt; に管理者の同意を与えます」を押す</li>
              <li>「証明書とシークレット」→「新しいクライアントシークレット」を作り、<strong>値</strong>をこの画面に入れる（シークレットIDではない）</li>
              <li>「概要」のアプリケーションIDとディレクトリIDを入れて保存 →「接続テスト」</li>
            </ol>
            <div className="text-secondary">
              取得できるのは過去7日分までです。それより前のログは、Purview の監査ログ検索からCSVをエクスポートし、
              サーバーで <code>python -m app.tools.import_m365_csv &lt;CSV&gt;</code> を実行して取り込めます（取り込み済みのものは二重に入りません）。
              シークレットには有効期限があるため、期限が来る前に作り直して入れ替えてください。詳細は docs/m365.md。
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
