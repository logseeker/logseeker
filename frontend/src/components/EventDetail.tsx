import { useEffect, useState } from "react";
import { api } from "../api";
import { stLabel } from "../labels";
import { adviseForEvent } from "../advice";
import type { EventDetail as Detail, EventRow } from "../types";

const TABS = ["概要", "Payload", "正規化", "エンティティ", "相関", "Parser"] as const;
type Tab = (typeof TABS)[number];

// 正規化フィールド → [表示名, エンティティ種別]（エンティティ＝資産/主体のみ）
const PIVOTS: [string, string, string][] = [
  ["source_ip", "送信元IP", "ip"], ["actor_user", "ユーザー", "user"],
  ["device_name", "ホスト/デバイス", "host"], ["url_domain", "ドメイン", "domain"],
];

function KV({ obj }: { obj: Record<string, unknown> }) {
  const entries = Object.entries(obj).filter(([, v]) => v !== null && v !== "" && v !== undefined);
  if (!entries.length) return <div className="text-secondary">なし</div>;
  return (
    <div>
      {entries.map(([k, v]) => (
        <div key={k} className="row mb-1">
          <div className="col-5 text-secondary text-break">{k}</div>
          <div className="col-7 text-break">{typeof v === "object" ? JSON.stringify(v) : String(v)}</div>
        </div>
      ))}
    </div>
  );
}

function MiniEvents({ items }: { items: EventRow[] }) {
  if (!items.length) return <div className="text-secondary">関連イベントなし</div>;
  return (
    <table className="table table-sm table-vcenter">
      <thead><tr><th>時刻</th><th>ソース</th><th>種別</th><th>イベント</th><th>メッセージ</th></tr></thead>
      <tbody>
        {items.map((e) => (
          <tr key={e.id}>
            <td className="text-nowrap">{e.event_time ? e.event_time.replace("T", " ").slice(0, 19) : "-"}</td>
            <td className="text-nowrap">{e.source_name}</td>
            <td className="text-nowrap">{stLabel(e.source_type)}</td>
            <td className="text-nowrap">{e.event_action}</td>
            <td className="text-truncate" style={{ maxWidth: 240 }}>{e.message}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function EventDetail({ id, onClose, onPivot, onEntity }:
  { id: number; onClose: () => void; onPivot: (taxKey: string, value: string) => void;
    onEntity?: (entityType: string, value: string) => void }) {
  const [d, setD] = useState<Detail | null>(null);
  const [tab, setTab] = useState<Tab>("概要");
  const [related, setRelated] = useState<{ keys: { entity_type: string; entity_value: string }[]; items: EventRow[] }>({ keys: [], items: [] });

  useEffect(() => {
    api.eventDetail(id).then(setD).catch(() => setD(null));
    api.related(id).then(setRelated).catch(() => setRelated({ keys: [], items: [] }));
  }, [id]);

  const n = (d?.normalized ?? {}) as Record<string, unknown>;
  const advice = d ? adviseForEvent({
    event_category: n.event_category as string | null, event_result: n.event_result as string | null,
    event_severity: n.event_severity as string | null, actor_user: n.actor_user as string | null,
    url_path: n.url_path as string | null, http_status_code: n.http_status_code as string | null,
    source_type: d.source_type,
  }) : null;

  return (
    <>
      <div className="offcanvas offcanvas-end show" tabIndex={-1} style={{ visibility: "visible", width: 600 }}>
        <div className="offcanvas-header">
          <h2 className="offcanvas-title">イベント #{id}</h2>
          <button type="button" className="btn-close" onClick={onClose}></button>
        </div>
        <div className="offcanvas-body">
          <ul className="nav nav-tabs mb-3 flex-nowrap overflow-auto">
            {TABS.map((t) => (
              <li className="nav-item" key={t}>
                <a className={`nav-link text-nowrap ${tab === t ? "active" : ""}`} role="button" onClick={() => setTab(t)}>{t}</a>
              </li>
            ))}
          </ul>
          {!d && <div className="text-secondary">読み込み中…</div>}

          {d && tab === "概要" && (
            <>
              {advice && (
                <div className={`alert alert-${advice.level === "danger" ? "danger" : "warning"} py-2`}>
                  <div className="fw-bold mb-1">🛡 {advice.title}</div>
                  <div className="small mb-1">{advice.rec}</div>
                  <div className="d-flex flex-wrap gap-1">
                    {advice.actions.map((a) => <span key={a} className="badge bg-azure-lt">{a}</span>)}
                  </div>
                </div>
              )}
              <KV obj={{
                時刻: n.event_time, ログソース: n.source_name, 種別: stLabel(d.source_type as string),
                "ホスト/デバイス": n.device_name ?? "-", "ドメイン": n.url_domain ?? "-",
                送信元IP: n.source_ip, ユーザー: n.actor_user, イベント: n.event_action, 結果: n.event_result,
                重大度: n.event_severity ?? "-",
                URL: n.url_path, ステータス: n.http_status_code, メッセージ: n.message,
              }} />
            </>
          )}
          {d && tab === "Payload" && (
            <>
              <div className="text-secondary small mb-1">受信JSON（無改変）</div>
              {d.payload && Object.keys(d.payload).length > 0 ? (
                <pre className="bg-dark text-white p-2 rounded" style={{ fontSize: 12, overflow: "auto", maxHeight: "60vh" }}>{JSON.stringify(d.payload, null, 2)}</pre>
              ) : (
                <div className="text-secondary">payload がありません</div>
              )}
            </>
          )}
          {d && tab === "正規化" && <KV obj={d.normalized} />}

          {d && tab === "エンティティ" && (
            <table className="table table-sm table-vcenter">
              <thead><tr><th>項目</th><th>値</th><th></th></tr></thead>
              <tbody>
                {PIVOTS.map(([key, label, etype]) => {
                  const v = n[key];
                  if (!v) return null;
                  return (
                    <tr key={key}>
                      <td className="text-secondary">{label}</td>
                      <td className="text-break">{String(v)}</td>
                      <td className="text-end text-nowrap">
                        <button className="btn btn-sm btn-outline-primary me-1"
                          onClick={() => { onPivot(key, String(v)); onClose(); }}>Eventsで絞込</button>
                        {onEntity && (
                          <button className="btn btn-sm btn-outline-dark"
                            onClick={() => { onEntity(etype, String(v)); onClose(); }}>調査</button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}

          {d && tab === "相関" && (
            <>
              <div className="mb-2 text-secondary small">
                共有キー：{related.keys.map((k) => <span key={k.entity_type + k.entity_value} className="badge bg-secondary-lt me-1">{k.entity_type}={k.entity_value}</span>)}
              </div>
              <MiniEvents items={related.items} />
            </>
          )}

          {d && tab === "Parser" && (
            <KV obj={{
              parser_name: d.parser_name, parser_version: d.parser_version, parse_status: d.parse_status,
              parse_error: d.parse_error, ingest_channel: d.ingest_channel, source: d.source,
              source_type: d.source_type, received_at: d.received_at, receiver_ip: d.receiver_ip,
            }} />
          )}
        </div>
      </div>
      <div className="offcanvas-backdrop fade show" onClick={onClose}></div>
    </>
  );
}
