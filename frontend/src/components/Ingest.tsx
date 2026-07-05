import { useEffect, useState } from "react";
import { api } from "../api";
import type { IngestStatus } from "../types";

// API/TCP 連携の案内＋取り込み状態（§5, §12.10）。ファイルアップロードUIは作らない。
export function Ingest() {
  const [st, setSt] = useState<IngestStatus | null>(null);
  useEffect(() => { api.ingestStatus().then(setSt).catch(() => setSt(null)); }, []);

  const origin = (import.meta.env.VITE_API_BASE as string) || window.location.origin;
  const host = window.location.hostname;
  const tcpPort = st?.tcp_port ?? 516;

  const curl = `curl -X POST "${origin}/ingest?source=myapp&source_type=web_access" \\
  -H "Content-Type: application/json" \\
  -d '{"vhost":"example.com","client":"203.0.113.5","time":"2026-06-26T19:00:00+09:00",
       "request":"GET /login HTTP/1.1","status":"200","user_agent":"curl"}'`;
  const ndjson = `# 1行 = 1 JSONイベント（NDJSON）を TCP ${tcpPort} に送る
printf '%s\\n' '{"source":"router","source_type":"router","time":"2026/04/06 00:18:51","tag":"DHCPD","message":"..."}' \\
  | nc ${host} ${tcpPort}`;

  return (
    <div className="row row-cards">
      <div className="col-lg-6">
        <div className="card">
          <div className="card-header"><h3 className="card-title">REST API で送る</h3></div>
          <div className="card-body">
            <p className="text-secondary">JSON イベントを POST します。単一オブジェクトでも配列でも可。</p>
            <table className="table table-sm">
              <tbody>
                <tr><td><code>POST /ingest</code></td><td className="text-secondary">JSONイベント受信</td></tr>
                <tr><td><code>POST /ingest/&#123;source&#125;</code></td><td className="text-secondary">source指定で受信</td></tr>
                <tr><td><code>POST /ingest/bulk</code></td><td className="text-secondary">複数一括</td></tr>
              </tbody>
            </table>
            <p className="text-secondary small mb-1">クエリ <code>?source=</code> <code>&amp;source_type=</code> で由来/種別を付けられます。</p>
            <pre className="bg-light p-2 rounded border" style={{ fontSize: 12 }}>{curl}</pre>
            <p className="text-secondary small mb-0">認証: 環境変数 <code>INGEST_TOKEN</code> を設定すると <code>Authorization: Bearer &lt;token&gt;</code> が必須になります（未設定ならローカルは認証なし）。</p>
          </div>
        </div>
      </div>

      <div className="col-lg-6">
        <div className="card">
          <div className="card-header"><h3 className="card-title">TCP (NDJSON) で送る</h3></div>
          <div className="card-body">
            <p className="text-secondary">改行区切りJSON（1行=1イベント）を TCP で送信します。</p>
            <table className="table table-sm">
              <tbody>
                <tr><td>ホスト</td><td><code>{host}</code></td></tr>
                <tr><td>ポート</td><td><code>{tcpPort}</code></td></tr>
                <tr><td>形式</td><td>NDJSON（1行1イベント）</td></tr>
              </tbody>
            </table>
            <pre className="bg-light p-2 rounded border" style={{ fontSize: 12 }}>{ndjson}</pre>
            <p className="text-secondary small mb-0">JSON内に <code>source</code> / <code>source_type</code> があれば使います。不正な行は Dead Letter に保存されます。</p>
          </div>
        </div>
      </div>

      <div className="col-12">
        <div className="card">
          <div className="card-header"><h3 className="card-title">取り込み状態</h3></div>
          <div className="card-body">
            {!st && <div className="text-secondary">読み込み中…</div>}
            {st && (
              <>
                <div className="row g-2 mb-3">
                  <div className="col-auto"><span className="text-secondary">総イベント</span> <strong>{st.total.toLocaleString()}</strong></div>
                  <div className="col-auto"><span className="text-secondary">Dead Letter</span> <strong>{st.dead_letters.toLocaleString()}</strong></div>
                </div>
                <table className="table table-sm">
                  <thead><tr><th>チャネル</th><th>件数</th><th>最終受信</th></tr></thead>
                  <tbody>
                    {st.by_channel.map((c) => (
                      <tr key={c.channel ?? "-"}>
                        <td>{c.channel}</td><td>{c.count.toLocaleString()}</td>
                        <td>{c.last_received ? c.last_received.replace("T", " ").slice(0, 19) : "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
