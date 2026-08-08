import { useEffect, useState } from "react";
import { api } from "../api";
import { fmtTime, stLabel } from "../labels";
import { adviseForEvent } from "../advice";
import { useAssetDisplayNames, formatHost } from "../assetNames";
import type { Annotation, CaseRow, EventDetail as Detail, EventRow } from "../types";

const TABS = ["概要", "Payload", "正規化", "エンティティ", "相関", "コメント", "Parser"] as const;
type Tab = (typeof TABS)[number];

// このイベント単体に対する調査メモ・気づきの記録のみ（ケースへの紐付けは
// 独立した「ケースに追加」ボタンに分離している）。
function CommentsTab({ eventId }: { eventId: number }) {
  const [notes, setNotes] = useState<Annotation[]>([]);
  const [comment, setComment] = useState("");
  const [tags, setTags] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const loadNotes = () => api.annotations(eventId).then(setNotes).catch(() => {});
  useEffect(() => {
    loadNotes();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eventId]);

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(null), 2500); };

  const addComment = async () => {
    setErr(null);
    try {
      await api.addAnnotation(eventId, { comment: comment.trim() || undefined, tags: tags.trim() || undefined });
      setComment(""); setTags(""); loadNotes(); flash("コメントを追加しました");
    } catch (e) { setErr((e as Error).message); }
  };

  return (
    <div>
      {err && <div className="alert alert-danger py-2">{err}</div>}
      {msg && <div className="alert alert-success py-2">{msg}</div>}

      <div className="mb-3">
        <div className="text-secondary small mb-2">このイベント単体に対する調査メモ・気づいたことを記録します。</div>
        <label className="form-label">コメント</label>
        <textarea className="form-control mb-2" rows={2} placeholder="調査メモ・気づいたことなど"
          value={comment} onChange={(e) => setComment(e.target.value)} />
        <label className="form-label">タグ（カンマ区切り・任意）</label>
        <input className="form-control mb-2" placeholder="例: 要監視, 誤検知"
          value={tags} onChange={(e) => setTags(e.target.value)} />
        <button className="btn btn-primary btn-sm" disabled={!comment.trim() && !tags.trim()} onClick={addComment}>
          コメントを追加
        </button>
      </div>

      <div className="mb-3">
        {notes.length === 0 && <div className="text-secondary small">まだコメントはありません。</div>}
        {notes.map((a) => (
          <div key={a.id} className="border rounded p-2 mb-1">
            {a.comment && <div className="text-break">{a.comment}</div>}
            {a.tags && <div className="mt-1">{a.tags.split(",").map((t) => t.trim()).filter(Boolean).map((t) => <span key={t} className="badge bg-azure-lt me-1">{t}</span>)}</div>}
            <div className="text-secondary small mt-1">
              {a.created_by ? `${a.created_by} · ` : ""}{a.created_at ? fmtTime(a.created_at) : ""}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// 独立した「ケースに追加」ボタン（v1「インシデントに追加」から改称）。既にいずれかのケースに
// 紐付いている場合はリンクに変わりクリックでそのケースを開く（v1は非活性テキスト止まりだった実装漏れの修正）。
// ケースは「注目」以外のイベントも自由に保持できるため、注目判定によるボタンの出し分けはしない
// （設計書v4 3章：v3までの注目イベント限定制限は撤廃）。
function AddToCase({ eventId, linked, onLinked, onOpenCase }: {
  eventId: number; linked: { id: number; title: string } | null;
  onLinked: () => void; onOpenCase: (id: number) => void;
}) {
  const [open, setOpen] = useState(false);
  const [cases, setCases] = useState<CaseRow[]>([]);
  const [caseId, setCaseId] = useState<number | "">("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const openPicker = () => {
    setErr(null);
    api.cases().then(setCases).catch(() => setCases([]));
    setOpen(true);
  };

  const attach = async () => {
    if (caseId === "") return;
    setErr(null);
    setBusy(true);
    try {
      await api.addCaseEvent(Number(caseId), { event_id: eventId, note: note.trim() || undefined });
      setOpen(false); setNote(""); setCaseId("");
      onLinked();
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };

  if (linked) {
    return (
      <button className="btn btn-outline-secondary btn-sm w-100 mb-3" onClick={() => onOpenCase(linked.id)}>
        ケース #{linked.id} に追加済み
      </button>
    );
  }

  return (
    <div className="mb-3">
      {!open ? (
        <button className="btn btn-outline-primary btn-sm w-100" onClick={openPicker}>ケースに追加</button>
      ) : (
        <div className="border rounded p-2">
          {err && <div className="alert alert-danger py-2">{err}</div>}
          {cases.length === 0 ? (
            <div className="text-secondary small">ケースがありません。「ケース」画面で作成してください。</div>
          ) : (
            <>
              <select className="form-select form-select-sm mb-2" value={caseId}
                onChange={(e) => setCaseId(e.target.value ? Number(e.target.value) : "")}>
                <option value="">ケースを選択…</option>
                {cases.map((c) => <option key={c.id} value={c.id}>{c.title}</option>)}
              </select>
              <input className="form-control form-control-sm mb-2" placeholder="メモ（任意）"
                value={note} onChange={(e) => setNote(e.target.value)} />
              <div className="d-flex gap-2">
                <button className="btn btn-primary btn-sm" disabled={caseId === "" || busy} onClick={attach}>
                  このイベントを追加
                </button>
                <button className="btn btn-link btn-sm text-secondary" onClick={() => setOpen(false)}>キャンセル</button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// 独立した「インシデント化」ボタン（既存の「ケースに追加」とは別の独立ボタン。設計書v4 5-1節）。
// 「注目」イベントの時のみ表示する（インシデントは注目アラートから直接生成する。設計書v4 4章）。
// 既にインシデント化済みなら、そのインシデントを開くボタンに変わる。
function CreateIncident({ eventId, isAttention, linked, onCreated, onOpenIncident }: {
  eventId: number; isAttention: boolean; linked: { id: number; title: string } | null;
  onCreated: () => void; onOpenIncident: (incidentId: number) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  if (!isAttention && !linked) return null;

  if (linked) {
    return (
      <button className="btn btn-outline-danger btn-sm w-100 mb-3" onClick={() => onOpenIncident(linked.id)}>
        インシデント #{linked.id} で対応中
      </button>
    );
  }

  const create = async () => {
    setErr(null);
    setBusy(true);
    try {
      const { id } = await api.createIncidentFromEvent(eventId);
      onCreated();
      onOpenIncident(id);
    } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };

  return (
    <div className="mb-3">
      {err && <div className="alert alert-danger py-2">{err}</div>}
      <button className="btn btn-danger btn-sm w-100" disabled={busy} onClick={create}>インシデント化</button>
    </div>
  );
}

// イベント単体の対応済み/未対応トグル（ケースへの追加有無とは独立。設計書v2 2章）
function ResolvedToggle({ resolved, onChange }: { resolved: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="form-check form-switch mb-3">
      <input className="form-check-input" type="checkbox" checked={resolved}
        onChange={(e) => onChange(e.target.checked)} />
      <span className="form-check-label">{resolved ? "対応済み" : "未対応"}</span>
    </label>
  );
}

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
            <td className="text-nowrap">{e.event_time ? fmtTime(e.event_time) : "-"}</td>
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

export function EventDetail({ id, onClose, onPivot, onEntity, onOpenCase, onOpenIncident }:
  { id: number; onClose: () => void; onPivot: (taxKey: string, value: string) => void;
    onEntity?: (entityType: string, value: string) => void; onOpenCase?: (caseId: number) => void;
    onOpenIncident?: (incidentId: number) => void }) {
  const [d, setD] = useState<Detail | null>(null);
  const [tab, setTab] = useState<Tab>("概要");
  const [related, setRelated] = useState<{ keys: { entity_type: string; entity_value: string }[]; items: EventRow[] }>({ keys: [], items: [] });
  const assetNames = useAssetDisplayNames();

  const loadDetail = () => api.eventDetail(id).then(setD).catch(() => setD(null));
  useEffect(() => {
    loadDetail();
    api.related(id).then(setRelated).catch(() => setRelated({ keys: [], items: [] }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const n = (d?.normalized ?? {}) as Record<string, unknown>;
  const advice = d ? adviseForEvent({
    event_category: n.event_category as string | null, event_result: n.event_result as string | null,
    event_severity: n.event_severity as string | null, actor_user: n.actor_user as string | null,
    url_path: n.url_path as string | null, url_query: n.url_query as string | null,
    http_status_code: n.http_status_code as string | null,
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
          {d && (
            <>
              <ResolvedToggle resolved={d.resolved} onChange={(v) => api.setEventResolved(id, v).then(loadDetail)} />
              <AddToCase eventId={id} linked={d.linked_case} onLinked={loadDetail}
                onOpenCase={(caseId) => { onOpenCase?.(caseId); onClose(); }} />
              <CreateIncident eventId={id} isAttention={d.is_attention} linked={d.linked_incident} onCreated={loadDetail}
                onOpenIncident={(incidentId) => { onOpenIncident?.(incidentId); onClose(); }} />
            </>
          )}
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
                時刻: fmtTime(n.event_time as string | null), ログソース: n.source_name, 種別: stLabel(d.source_type as string),
                "ホスト/デバイス": n.device_name ? formatHost(n.device_name as string, assetNames) : "-", "ドメイン": n.url_domain ?? "-",
                送信元IP: n.source_ip ? formatHost(n.source_ip as string, assetNames) : n.source_ip, ユーザー: n.actor_user, イベント: n.event_action, 結果: n.event_result,
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

          {d && tab === "コメント" && <CommentsTab eventId={id} />}

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
