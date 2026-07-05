import { useEffect, useState } from "react";
import { api } from "../api";
import { stLabel } from "../labels";
import type { EntityDetail, EntityRow, EventRow } from "../types";

const TYPES = ["", "ip", "user", "host", "domain", "mac", "email"];
const TYPE_LABEL: Record<string, string> = {
  "": "すべて", ip: "IP", user: "ユーザー", host: "ホスト", domain: "ドメイン",
  mac: "MAC", email: "メール",
};
// entity_type → Events のタクソノミー列（Eventsで絞り込むため）
const PIVOT: Record<string, string> = {
  ip: "source_ip", user: "actor_user", host: "device_name", domain: "url_domain",
};

export function Entities({ onPick, initial }: {
  onPick: (k: string, v: string) => void;
  initial?: { type: string; value: string; nonce?: number };
}) {
  const [type, setType] = useState(initial?.type ?? "");
  const [q, setQ] = useState("");
  const [rows, setRows] = useState<EntityRow[]>([]);
  const [sel, setSel] = useState<{ type: string; value: string } | null>(
    initial ? { type: initial.type, value: initial.value } : null);

  // 他画面（イベント詳細など）から指定されたエンティティを開く
  useEffect(() => {
    if (initial) { setType(initial.type); setSel({ type: initial.type, value: initial.value }); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initial?.nonce]);
  const [detail, setDetail] = useState<EntityDetail | null>(null);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.entities(type || undefined, q || undefined).then(setRows).catch((e) => setErr((e as Error).message));
  }, [type, q]);

  useEffect(() => {
    if (!sel) { setDetail(null); setEvents([]); return; }
    api.entity(sel.type, sel.value).then(setDetail).catch(() => setDetail(null));
    api.entityEvents(sel.type, sel.value).then(setEvents).catch(() => setEvents([]));
  }, [sel]);

  const ts = (s: string | null) => (s ? s.replace("T", " ").slice(0, 19) : "-");

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="card"><div className="card-body">
          <div className="d-flex gap-2 align-items-center flex-wrap">
            <ul className="nav nav-pills">
              {TYPES.map((t) => (
                <li className="nav-item" key={t || "all"}>
                  <a className={`nav-link ${type === t ? "active" : ""}`} role="button" onClick={() => { setType(t); setSel(null); }}>{TYPE_LABEL[t]}</a>
                </li>
              ))}
            </ul>
            <input className="form-control ms-auto" style={{ maxWidth: 280 }} placeholder="値で検索"
              value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
        </div></div>
      </div>

      {err && <div className="col-12"><div className="alert alert-danger">取得失敗: {err}</div></div>}

      <div className="col-lg-5">
        <div className="card">
          <div className="card-header"><h3 className="card-title">エンティティ（{rows.length}）</h3></div>
          <table className="table table-vcenter table-sm card-table table-hover">
            <thead><tr><th>種別</th><th>値</th><th className="text-end">件数</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={`${r.entity_type}:${r.entity_value}`} style={{ cursor: "pointer" }}
                  className={sel?.value === r.entity_value && sel?.type === r.entity_type ? "table-active" : ""}
                  onClick={() => setSel({ type: r.entity_type, value: r.entity_value })}>
                  <td><span className="badge bg-secondary-lt">{TYPE_LABEL[r.entity_type] ?? r.entity_type}</span></td>
                  <td className="text-truncate" style={{ maxWidth: 240 }}>{r.entity_value}</td>
                  <td className="text-end">{r.count.toLocaleString()}</td>
                </tr>
              ))}
              {rows.length === 0 && <tr><td colSpan={3} className="text-secondary text-center py-4">なし</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      <div className="col-lg-7">
        {!sel && <div className="card"><div className="empty"><p className="empty-title">エンティティを選択</p>
          <p className="empty-subtitle text-secondary">左の一覧から IP やユーザーを選ぶと、出現状況と関連イベントを表示します。</p></div></div>}
        {sel && detail && (
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">{TYPE_LABEL[sel.type] ?? sel.type}: {sel.value}</h3>
              {PIVOT[sel.type] && (
                <button className="btn btn-sm btn-primary ms-auto" onClick={() => onPick(PIVOT[sel.type], sel.value)}>
                  このエンティティで Events を絞り込む
                </button>
              )}
            </div>
            <div className="card-body">
              <div className="row g-2 mb-3">
                <div className="col-auto"><span className="text-secondary">出現回数</span> <strong>{detail.count.toLocaleString()}</strong></div>
                <div className="col-auto"><span className="text-secondary">初回</span> {ts(detail.first_seen)}</div>
                <div className="col-auto"><span className="text-secondary">最終</span> {ts(detail.last_seen)}</div>
              </div>
              <div className="mb-2">
                <span className="text-secondary">関連ログソース：</span>
                {detail.source_names.map((s) => <span key={s} className="badge bg-blue-lt me-1">{s}</span>)}
              </div>
            </div>
            <div className="table-responsive" style={{ maxHeight: 420 }}>
              <table className="table table-vcenter table-sm card-table">
                <thead><tr><th>時刻</th><th>ログソース</th><th>種別</th><th>イベント</th><th>対象</th><th>メッセージ</th></tr></thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.id}>
                      <td className="text-nowrap">{e.event_time ? ts(e.event_time) : "（時刻なし）"}</td>
                      <td className="text-nowrap">{e.source_name}</td>
                      <td className="text-nowrap">{stLabel(e.source_type)}</td>
                      <td className="text-nowrap">{e.event_action}</td>
                      <td className="text-truncate" style={{ maxWidth: 200 }}>{e.url_path || "-"}</td>
                      <td className="text-truncate" style={{ maxWidth: 280 }}>{e.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
