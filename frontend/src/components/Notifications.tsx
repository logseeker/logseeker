import { useEffect, useState } from "react";
import { api } from "../api";
import type { NotificationConfig } from "../types";

const EMPTY: NotificationConfig = {
  email_enabled: false, email_host: "", email_port: 587,
  email_user: "", email_pass: "", email_from: "", email_to: "",
  slack_enabled: false, slack_webhook: "", min_severity: "high",
};

// ここでの重大度は「検知ルールの重大度」（＝ルール/注意喚起の判定結果）であり、
// イベント一覧の「重大度」(INFO/NOTICE/WARNING…＝ログ自身のレベル)とは別物。
const SEV_OPTIONS = [
  { v: "critical", label: "重大のみ（IOC一致 など）" },
  { v: "high",     label: "高 以上（総当たり・危険パス・rootSSH 等）" },
  { v: "warning",  label: "警告 以上（Webスキャン・認証失敗 等）" },
];

export function Notifications() {
  const [cfg, setCfg] = useState<NotificationConfig>(EMPTY);
  const [saved, setSaved] = useState(false);
  const [emailResult, setEmailResult] = useState<string | null>(null);
  const [slackResult, setSlackResult] = useState<string | null>(null);
  const [nowResult, setNowResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.notifConfig().then(setCfg).catch(() => {});
  }, []);

  const set = (k: keyof NotificationConfig, v: unknown) =>
    setCfg((p) => ({ ...p, [k]: v }));

  const save = async () => {
    setLoading(true); setSaved(false);
    await api.saveNotifConfig(cfg).catch(() => {});
    setLoading(false); setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const testEmail = async () => {
    setEmailResult("送信中…");
    const r = await api.testEmail().catch((e: Error) => ({ ok: false, error: e.message }));
    setEmailResult(r.ok ? "✅ 送信成功" : `❌ ${r.error ?? "失敗"}`);
  };
  const testSlack = async () => {
    setSlackResult("送信中…");
    const r = await api.testSlack().catch((e: Error) => ({ ok: false, error: e.message }));
    setSlackResult(r.ok ? "✅ 送信成功" : `❌ ${r.error ?? "失敗"}`);
  };
  const sendNow = async () => {
    setNowResult("送信中…");
    const r = await api.notifyNow().catch((e: Error) => ({ hits: 0, result: { error: e.message } }));
    setNowResult(`${r.hits} 件のルールヒット → ${JSON.stringify(r.result)}`);
  };

  return (
    <div className="row row-cards">
      {/* メール通知 */}
      <div className="col-12 col-md-6">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">📧 メール通知（SMTP）</h3>
            <div className="card-actions">
              <label className="form-check form-switch mb-0">
                <input className="form-check-input" type="checkbox"
                  checked={cfg.email_enabled}
                  onChange={(e) => set("email_enabled", e.target.checked)} />
                <span className="form-check-label">{cfg.email_enabled ? "有効" : "無効"}</span>
              </label>
            </div>
          </div>
          <div className="card-body">
            <div className="row g-2">
              <div className="col-8">
                <label className="form-label">SMTPホスト</label>
                <input className="form-control" placeholder="smtp.example.com"
                  value={cfg.email_host} onChange={(e) => set("email_host", e.target.value)} />
              </div>
              <div className="col-4">
                <label className="form-label">ポート</label>
                <input className="form-control" type="number" placeholder="587"
                  value={cfg.email_port} onChange={(e) => set("email_port", Number(e.target.value))} />
              </div>
              <div className="col-6">
                <label className="form-label">ユーザー名</label>
                <input className="form-control" placeholder="user@example.com"
                  value={cfg.email_user} onChange={(e) => set("email_user", e.target.value)} />
              </div>
              <div className="col-6">
                <label className="form-label">パスワード</label>
                <input className="form-control" type="password" placeholder="（変更する場合のみ入力）"
                  value={cfg.email_pass} onChange={(e) => set("email_pass", e.target.value)} />
              </div>
              <div className="col-6">
                <label className="form-label">送信元アドレス</label>
                <input className="form-control" placeholder="logseeker@example.com"
                  value={cfg.email_from} onChange={(e) => set("email_from", e.target.value)} />
              </div>
              <div className="col-6">
                <label className="form-label">送信先アドレス</label>
                <input className="form-control" placeholder="admin@example.com（カンマ区切り複数可）"
                  value={cfg.email_to} onChange={(e) => set("email_to", e.target.value)} />
              </div>
            </div>
            <div className="mt-3 d-flex gap-2 align-items-center">
              <button className="btn btn-sm btn-outline-primary" onClick={testEmail}>テスト送信</button>
              {emailResult && <span className="text-secondary small">{emailResult}</span>}
            </div>
          </div>
        </div>
      </div>

      {/* Slack通知 */}
      <div className="col-12 col-md-6">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">💬 Slack / Webhook 通知</h3>
            <div className="card-actions">
              <label className="form-check form-switch mb-0">
                <input className="form-check-input" type="checkbox"
                  checked={cfg.slack_enabled}
                  onChange={(e) => set("slack_enabled", e.target.checked)} />
                <span className="form-check-label">{cfg.slack_enabled ? "有効" : "無効"}</span>
              </label>
            </div>
          </div>
          <div className="card-body">
            <label className="form-label">Webhook URL</label>
            <input className="form-control" placeholder="https://hooks.slack.com/services/..."
              value={cfg.slack_webhook} onChange={(e) => set("slack_webhook", e.target.value)} />
            <div className="text-secondary small mt-1">
              Slack: アプリ設定 → Incoming Webhooks で取得。Teams/Discordなど他のWebhookも対応。
            </div>
            <div className="mt-3 d-flex gap-2 align-items-center">
              <button className="btn btn-sm btn-outline-primary" onClick={testSlack}>テスト送信</button>
              {slackResult && <span className="text-secondary small">{slackResult}</span>}
            </div>
          </div>
        </div>
      </div>

      {/* 共通設定 */}
      <div className="col-12">
        <div className="card">
          <div className="card-header"><h3 className="card-title">⚙️ 通知条件・タイミング</h3></div>
          <div className="card-body">
            <div className="row g-3">
              <div className="col-auto">
                <label className="form-label">通知する最低重大度</label>
                <select className="form-select" value={cfg.min_severity}
                  onChange={(e) => set("min_severity", e.target.value)}>
                  {SEV_OPTIONS.map((o) => <option key={o.v} value={o.v}>{o.label}</option>)}
                </select>
              </div>
              <div className="col-auto d-flex align-items-end">
                <div className="text-secondary small">
                  IOC同期スケジュールに合わせて自動送信（脅威インテリ画面で間隔設定）
                </div>
              </div>
            </div>
            <div className="alert alert-secondary mt-3 mb-0 py-2 small">
              ここでの重大度は<strong>検知ルールの重大度</strong>（「ルール / 注意喚起」画面に出るもの）です。
              重大＝IOC一致、高＝総当たり/危険パス/rootSSH、警告＝Webスキャン/認証失敗。
              <br />
              ※ イベント一覧のプルダウンにある「重大度」は<strong>ログ自身のレベル</strong>（INFO / NOTICE / WARNING …）で、
              これとは別物です。通知は「攻撃の検知」に対して飛びます。
            </div>
            {cfg.last_notified && (
              <div className="mt-2 text-secondary small">
                最終通知: {cfg.last_notified.replace("T", " ").slice(0, 19)} UTC
              </div>
            )}
          </div>
          <div className="card-footer d-flex gap-2 align-items-center">
            <button className="btn btn-primary" onClick={save} disabled={loading}>
              {loading ? "保存中…" : "設定を保存"}
            </button>
            {saved && <span className="text-success">✅ 保存しました</span>}
            <div className="ms-auto d-flex gap-2 align-items-center">
              <button className="btn btn-outline-warning btn-sm" onClick={sendNow}>
                今すぐ通知テスト（現在の全ルールヒットを送信）
              </button>
              {nowResult && <span className="text-secondary small">{nowResult}</span>}
            </div>
          </div>
        </div>
      </div>

      {/* 説明カード */}
      <div className="col-12">
        <div className="card bg-blue-lt">
          <div className="card-body">
            <h4 className="mb-2">🔌 Slack以外の外部連携について</h4>
            <p className="mb-1">Webhook URLを使えば以下のサービスとも連携可能です（テキスト送信）：</p>
            <ul className="mb-0">
              <li><strong>Microsoft Teams</strong>: チャンネル → コネクタ → Incoming Webhook で URL 取得</li>
              <li><strong>Discord</strong>: サーバー設定 → 連携サービス → ウェブフック で URL 取得</li>
              <li><strong>Chatwork / LINE Notify</strong>: 各サービスのWebhook URLをそのまま設定</li>
              <li><strong>独自API</strong>: POSTリクエストを受けるエンドポイントのURLを設定</li>
            </ul>
            <p className="mt-2 mb-0 text-secondary small">
              ※ 本機能は全ライセンスティアで使用可能です。
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
