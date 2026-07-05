import { useEffect, useState } from "react";
import { api } from "../api";
import type { IocFeed, IocFeedsInfo } from "../types";

const FEED_META: Record<string, { label: string; help: string; url: string }> = {
  abuseipdb: {
    label: "AbuseIPDB",
    help: "アカウント作成 → API → API Key を発行（無料枠あり）。blacklistエンドポイントから悪性IPを取得。",
    url: "https://www.abuseipdb.com/account/api",
  },
  otx: {
    label: "AlienVault OTX",
    help: "OTXアカウント → Settings → OTX Key を取得（無料）。購読パルスの指標(IP/ドメイン)を取得。",
    url: "https://otx.alienvault.com/api",
  },
};

function FeedCard({ feed, onSaved }: { feed: IocFeed; onSaved: () => void }) {
  const meta = FEED_META[feed.name] ?? { label: feed.name, help: "", url: "" };
  const [key, setKey] = useState("");
  const [enabled, setEnabled] = useState(feed.enabled);
  const [busy, setBusy] = useState(false);

  const save = async () => {
    setBusy(true);
    try {
      await api.updateFeed({ name: feed.name, api_key: key || undefined, enabled });
      setKey("");
      onSaved();
    } finally { setBusy(false); }
  };

  return (
    <div className="col-lg-6">
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">{meta.label}</h3>
          <div className="card-actions">
            {feed.has_key ? <span className="badge bg-green-lt">キー登録済</span> : <span className="badge bg-secondary-lt">キー未登録</span>}
          </div>
        </div>
        <div className="card-body">
          <p className="text-secondary small">{meta.help}{" "}
            {meta.url && <a href={meta.url} target="_blank" rel="noreferrer">キー取得ページ ↗</a>}</p>
          <label className="form-label">APIキー</label>
          <input type="password" className="form-control mb-2"
            placeholder={feed.has_key ? "●●●（変更する場合のみ入力）" : "APIキーを入力"}
            value={key} onChange={(e) => setKey(e.target.value)} />
          <label className="form-check form-switch">
            <input className="form-check-input" type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            <span className="form-check-label">自動同期を有効化</span>
          </label>
          <div className="mt-2 text-secondary small">
            取得済IOC: <strong>{feed.ioc_count.toLocaleString()}</strong> 件 ／
            最終同期: {feed.last_synced_at ? feed.last_synced_at.replace("T", " ").slice(0, 19) : "未"} ／
            {feed.last_status ?? "-"}
          </div>
        </div>
        <div className="card-footer">
          <button className="btn btn-primary" onClick={save} disabled={busy}>保存</button>
        </div>
      </div>
    </div>
  );
}

export function ThreatIntel() {
  const [info, setInfo] = useState<IocFeedsInfo | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = () => api.iocFeeds().then(setInfo).catch((e) => setErr((e as Error).message));
  useEffect(() => { load(); }, []);

  const setHours = async (h: number) => { await api.iocSettings(h); load(); };
  const syncNow = async () => {
    setSyncing(true); setMsg(null);
    try {
      const r = await api.iocSyncNow();
      setMsg(r.results.length ? r.results.map((x) => `${x.name}: ${x.status}`).join(" / ") : "有効なフィード（キー登録＋有効化）がありません");
      load();
    } catch (e) { setMsg((e as Error).message); }
    finally { setSyncing(false); }
  };

  if (err) return <div className="alert alert-danger">取得失敗: {err}</div>;
  if (!info) return <div className="text-secondary">読み込み中…</div>;

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="card"><div className="card-body d-flex align-items-center flex-wrap gap-3">
          <div><div className="subheader">登録IOC合計</div><div className="h2 mb-0">{info.total_ioc.toLocaleString()} 件</div></div>
          <label className="ctl ms-3">自動同期間隔
            <select className="form-select" value={info.sync_hours} onChange={(e) => setHours(Number(e.target.value))}>
              <option value={3}>3時間ごと</option>
              <option value={6}>6時間ごと</option>
              <option value={12}>12時間ごと</option>
              <option value={24}>24時間ごと</option>
            </select>
          </label>
          <button className="btn btn-outline-primary ms-auto" onClick={syncNow} disabled={syncing}>
            {syncing ? "同期中…" : "今すぐ同期"}
          </button>
        </div>
        {msg && <div className="card-body border-top py-2"><span className="text-secondary">{msg}</span></div>}
        </div>
      </div>

      {info.feeds.map((f) => <FeedCard key={f.name} feed={f} onSaved={load} />)}

      <div className="col-12">
        <div className="alert alert-info">
          仕組み：外部フィードを定期取得してローカルの脅威情報DBに保存し、取り込んだログのIP/ドメインと
          <strong>オフラインで突合</strong>します。一致は「ルール / 注意喚起」とイベントの脅威=IOCに表示。
          照合のたびに外部APIは叩きません（レート制限・遅延・オフライン不可を避けるため）。詳細は docs/threat-intel.md。
        </div>
      </div>
    </div>
  );
}
