import { useEffect, useState } from "react";
import { api } from "../api";
import { stLabel } from "../labels";
import type { AdminOverview, AuthStatus, Screen, SsoStatus } from "../types";

const COUNT_LABEL: Record<string, string> = {
  events: "イベント", normalized: "正規化レコード", entities: "エンティティ",
  incidents: "インシデント", ioc: "脅威情報(IOC)", dead_letters: "取り込み失敗",
};

// 管理：システム全体の状態を一望する運用ダッシュボード。admin は認証ON/OFF・SSO設定も。
export function Admin({ onNav, auth, onAuthChanged }: {
  onNav: (s: Screen) => void; auth: AuthStatus; onAuthChanged: () => void;
}) {
  const [ov, setOv] = useState<AdminOverview | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const isAdmin = !auth.auth_required || auth.user?.role === "admin";

  useEffect(() => {
    api.adminOverview().then(setOv).catch((e) => setErr((e as Error).message));
  }, []);

  if (err) return <div className="alert alert-danger">取得失敗: {err}</div>;
  if (!ov) return <div className="text-secondary">読み込み中…</div>;

  const ts = (s: string | null) => (s ? s.replace("T", " ").slice(0, 19) : "-");

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info mb-0">
          <strong>システム状態</strong>：取り込み件数・パース状況・受信経路・ライセンス等の
          <strong>稼働状況を一望する運用ビュー</strong>です（読み取り専用）。
          <span className="text-secondary">
            ※「ユーザー/アカウント管理」はまだありません。本ツールは現在ログイン機能を持たず、
            公開時は nginx 側の認証で保護する設計です（<code>docs/security.md</code>）。
            アカウント管理はログイン機能の導入時に追加予定です。
          </span>
        </div>
      </div>

      {/* 件数サマリ */}
      <div className="col-12">
        <div className="row row-cards">
          {Object.entries(ov.counts).map(([k, v]) => (
            <div className="col-6 col-md-4 col-xl-2" key={k}>
              <div className="card">
                <div className="card-body text-center">
                  <div className="h1 m-0">{v.toLocaleString()}</div>
                  <div className="text-secondary">
                    {k === "dead_letters" && v > 0
                      ? <a role="button" className="text-danger" onClick={() => onNav("deadletters")}>{COUNT_LABEL[k]}</a>
                      : (COUNT_LABEL[k] ?? k)}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ライセンス & 取り込み設定 */}
      <div className="col-lg-6">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">ライセンス</h3>
            <div className="card-actions"><button className="btn btn-sm" onClick={() => onNav("license")}>管理 →</button></div>
          </div>
          <div className="card-body">
            <div className="datagrid">
              <div className="datagrid-item"><div className="datagrid-title">状態</div>
                <div className="datagrid-content">
                  <span className={`badge ${ov.license.source === "applied" ? "bg-green" : "bg-secondary"}`}>
                    {ov.license.source === "applied" ? "適用済み" : "既定（未適用）"}
                  </span> {ov.license.licensee}
                </div></div>
              <div className="datagrid-item"><div className="datagrid-title">ティア</div>
                <div className="datagrid-content">Tier {ov.license.tier}</div></div>
              <div className="datagrid-item"><div className="datagrid-title">APIオプション</div>
                <div className="datagrid-content">{ov.license.api_enabled ? "有効" : "無効"}</div></div>
              <div className="datagrid-item"><div className="datagrid-title">残り日数</div>
                <div className="datagrid-content">{ov.license.days_left != null ? `${ov.license.days_left}日` : "無期限"}</div></div>
            </div>
          </div>
        </div>

        <div className="card mt-3">
          <div className="card-header"><h3 className="card-title">取り込み設定</h3></div>
          <div className="card-body">
            <div className="datagrid">
              <div className="datagrid-item"><div className="datagrid-title">TCP受信ポート</div>
                <div className="datagrid-content">{ov.ingest.tcp_port ?? "無効"}</div></div>
              <div className="datagrid-item"><div className="datagrid-title">/ingest 認証</div>
                <div className="datagrid-content">{ov.ingest.auth_enabled
                  ? <span className="badge bg-green-lt">トークン必須</span>
                  : <span className="badge bg-yellow-lt">認証なし（ローカル用）</span>}</div></div>
              <div className="datagrid-item"><div className="datagrid-title">IOC自動同期</div>
                <div className="datagrid-content">{ov.ioc_sync_hours}時間ごと</div></div>
              <div className="datagrid-item"><div className="datagrid-title">ログ未達監視</div>
                <div className="datagrid-content">{ov.silence_hours}時間データが来なければ検知</div></div>
            </div>
          </div>
        </div>

        <div className="card mt-3">
          <div className="card-header"><h3 className="card-title">データ保持期間</h3></div>
          <div className="card-body">
            <div className="datagrid">
              <div className="datagrid-item"><div className="datagrid-title">保持期間</div>
                <div className="datagrid-content">
                  {ov.retention.unlimited
                    ? <span className="badge bg-green-lt">無制限</span>
                    : `${ov.retention.days} 日（超過分は自動削除）`}
                </div></div>
              <div className="datagrid-item"><div className="datagrid-title">最古のイベント</div>
                <div className="datagrid-content text-secondary small">
                  {ov.retention.oldest_event_at ? ov.retention.oldest_event_at.replace("T", " ").slice(0, 19) : "-"}
                </div></div>
            </div>
            <div className="text-secondary small mt-2">
              ※ あくまでこのアプリのDBから削除するだけです。送信元機器のログには一切触れません。
              延長（1年/3年/無制限）は拡張ライセンスで設定できます。
            </div>
          </div>
        </div>
      </div>

      {/* パースステータス & 受信経路 */}
      <div className="col-lg-6">
        <div className="card">
          <div className="card-header"><h3 className="card-title">パース状態</h3></div>
          <div className="table-responsive">
            <table className="table table-vcenter card-table table-sm">
              <tbody>
                {Object.entries(ov.parse_status).map(([k, v]) => (
                  <tr key={k}>
                    <td>
                      <span className={`badge ${k === "success" ? "bg-green-lt" : k === "failed" ? "bg-red-lt" : "bg-yellow-lt"}`}>{k}</span>
                    </td>
                    <td className="text-end">{v.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card mt-3">
          <div className="card-header"><h3 className="card-title">受信経路</h3></div>
          <div className="table-responsive">
            <table className="table table-vcenter card-table table-sm">
              <thead><tr><th>経路</th><th className="text-end">件数</th><th>最終受信</th></tr></thead>
              <tbody>
                {ov.by_channel.map((c) => (
                  <tr key={c.channel ?? "?"}>
                    <td><span className="badge bg-secondary-lt">{c.channel ?? "-"}</span></td>
                    <td className="text-end">{c.count.toLocaleString()}</td>
                    <td className="text-secondary small">{ts(c.last_received)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* 種別別件数 */}
      <div className="col-12">
        <div className="card">
          <div className="card-header"><h3 className="card-title">ログ種別ごとの件数</h3></div>
          <div className="table-responsive">
            <table className="table table-vcenter card-table table-sm">
              <thead><tr><th>種別</th><th>source_type</th><th className="text-end">件数</th></tr></thead>
              <tbody>
                {ov.by_source_type.map((s) => (
                  <tr key={s.source_type ?? "null"}>
                    <td>{stLabel(s.source_type)}</td>
                    <td><code className="text-secondary">{s.source_type ?? "-"}</code></td>
                    <td className="text-end">{s.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {isAdmin && (
        <div className="col-12">
          <AdminSecurity auth={auth} onAuthChanged={onAuthChanged} onNav={onNav} />
        </div>
      )}
    </div>
  );
}

// 管理者(root)専用：ログイン必須ON/OFF と SSO 設定
function AdminSecurity({ auth, onAuthChanged, onNav }: {
  auth: AuthStatus; onAuthChanged: () => void; onNav: (s: Screen) => void;
}) {
  const [sso, setSso] = useState<SsoStatus | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [form, setForm] = useState({ issuer: "", client_id: "", client_secret: "", redirect_uri: "", allowed_domains: "", auto_provision_role: "viewer", enabled: false });

  useEffect(() => {
    api.getSso().then((s) => {
      setSso(s);
      setForm({ issuer: s.issuer, client_id: s.client_id, client_secret: "", redirect_uri: s.redirect_uri, allowed_domains: s.allowed_domains, auto_provision_role: s.auto_provision_role, enabled: s.enabled });
    }).catch(() => {});
  }, []);

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(null), 2500); };
  const toggleAuth = async (enabled: boolean) => {
    setErr(null);
    try { await api.toggleAuth(enabled); onAuthChanged(); flash(enabled ? "ログイン必須にしました" : "ログイン不要にしました"); }
    catch (e) { setErr((e as Error).message); }
  };
  const saveSso = async () => {
    setErr(null);
    try { const r = await api.saveSso(form); flash(r.note); api.getSso().then(setSso); }
    catch (e) { setErr((e as Error).message); }
  };

  return (
    <div className="card border-primary">
      <div className="card-header"><h3 className="card-title">🔐 セキュリティ設定（管理者のみ）</h3></div>
      <div className="card-body">
        {err && <div className="alert alert-danger py-2">{err}</div>}
        {msg && <div className="alert alert-success py-2">{msg}</div>}

        <div className="mb-4">
          <label className="form-check form-switch">
            <input className="form-check-input" type="checkbox" checked={auth.auth_required}
              onChange={(e) => toggleAuth(e.target.checked)} />
            <span className="form-check-label">
              <strong>ログインを必須にする</strong>
              <div className="text-secondary small">
                OFF＝誰でも全操作可（デモ）。ON＝ロールで制御。ONにする前に
                <a role="button" className="text-primary" onClick={() => onNav("users")}> ユーザー</a>を作成してください。
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
