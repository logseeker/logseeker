import { useEffect, useState } from "react";
import { api } from "../api";
import { fmtTime, stLabel } from "../labels";
import { EventDetail } from "./EventDetail";
import type { AuthStatus, CaseCommentItem, CaseDetail, CaseRow, Role } from "../types";

const ROLE_RANK: Record<Role, number> = { viewer: 1, editor: 2, sysadmin: 3, admin: 4 };

// ケース＝複数イベントを束ねる調査ワークスペース（設計書v4 3章）。ステータス・判定結果・
// 担当者は持たず、インシデントへの「昇格」概念も無い（インシデントとは完全に独立した概念）。
// そのため本画面には「インシデント管理機能」のUIは一切配置しない（設計書v4 5-2節）。
export function Cases({ auth, initial, onOpenIncident }: {
  auth?: AuthStatus; initial?: { id: number; nonce: number }; onOpenIncident?: (incidentId: number) => void;
}) {
  const [rows, setRows] = useState<CaseRow[]>([]);
  const [sel, setSel] = useState<number | null>(null);
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [title, setTitle] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [openEventId, setOpenEventId] = useState<number | null>(null);

  const effRole: Role = (!auth || !auth.auth_required) ? "admin" : (auth.user?.role ?? "viewer");
  const isEditor = ROLE_RANK[effRole] >= ROLE_RANK.editor;

  const reload = () => api.cases().then(setRows).catch((e) => setErr((e as Error).message));
  const reloadDetail = (id: number) => api.case(id).then(setDetail).catch(() => setDetail(null));

  useEffect(() => { reload(); }, []);
  useEffect(() => { if (sel != null) reloadDetail(sel); else setDetail(null); }, [sel]);
  useEffect(() => { if (initial) setSel(initial.id); }, [initial]);

  const create = async () => {
    if (!title.trim()) return;
    setErr(null);
    try {
      const { id } = await api.createCase(title.trim());
      setTitle(""); await reload(); setSel(id);
    } catch (e) { setErr((e as Error).message); }
  };

  return (
    <div className="row row-cards">
      {err && <div className="col-12"><div className="alert alert-danger">{err}</div></div>}

      <div className="col-lg-5">
        <div className="card">
          <div className="card-header"><h3 className="card-title">ケース</h3></div>
          {isEditor && (
            <div className="card-body border-bottom">
              <div className="input-group">
                <input className="form-control" placeholder="新規ケース名" value={title}
                  onChange={(e) => setTitle(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter") create(); }} />
                <button className="btn btn-primary" onClick={create}>作成</button>
              </div>
            </div>
          )}
          <table className="table table-vcenter card-table table-hover">
            <thead><tr><th>タイトル</th><th className="text-end">件数</th><th>最終更新</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} style={{ cursor: "pointer" }} className={sel === r.id ? "table-active" : ""}
                  onClick={() => setSel(r.id)}>
                  <td>{r.title}</td>
                  <td className="text-end">{r.event_count}</td>
                  <td className="text-secondary small">{r.updated_at ? fmtTime(r.updated_at) : "-"}</td>
                </tr>
              ))}
              {rows.length === 0 && <tr><td colSpan={3} className="text-secondary text-center py-4">まだありません</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      <div className="col-lg-7">
        {!detail && (
          <div className="card"><div className="empty">
            <p className="empty-title">ケースを選択</p>
            <p className="empty-subtitle text-secondary">
              調査対象イベントは、各イベント詳細の「ケースに追加」ボタンから追加できます。
            </p>
          </div></div>
        )}
        {detail && (
          <CaseDetailPane detail={detail}
            onChanged={() => { reload(); reloadDetail(detail.id); }}
            onOpenEvent={setOpenEventId} />
        )}
      </div>

      {openEventId != null && (
        <EventDetail id={openEventId} onClose={() => setOpenEventId(null)} onPivot={() => {}}
          onOpenCase={(caseId) => setSel(caseId)} onOpenIncident={onOpenIncident} />
      )}
    </div>
  );
}

function CaseDetailPane({ detail, onChanged, onOpenEvent }: {
  detail: CaseDetail; onChanged: () => void; onOpenEvent: (id: number) => void;
}) {
  const [tab, setTab] = useState<"events" | "comments">("events");
  const [editingTitle, setEditingTitle] = useState(false);
  const [titleDraft, setTitleDraft] = useState(detail.title);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => { setTitleDraft(detail.title); setEditingTitle(false); }, [detail.id, detail.title]);

  const guard = async (fn: () => Promise<unknown>) => {
    setErr(null);
    try { await fn(); onChanged(); } catch (e) { setErr((e as Error).message); }
  };

  const saveTitle = async () => {
    if (!titleDraft.trim() || titleDraft === detail.title) { setEditingTitle(false); return; }
    await guard(() => api.updateCaseTitle(detail.id, titleDraft.trim()));
    setEditingTitle(false);
  };

  return (
    <div className="card">
      <div className="card-header d-block">
        {err && <div className="alert alert-danger py-2">{err}</div>}
        {!editingTitle ? (
          <h3 className="card-title mb-2" role="button" title="クリックして編集" onClick={() => setEditingTitle(true)}>
            {detail.title}
          </h3>
        ) : (
          <div className="input-group mb-2" style={{ maxWidth: 480 }}>
            <input className="form-control" value={titleDraft} autoFocus
              onChange={(e) => setTitleDraft(e.target.value)}
              onBlur={saveTitle}
              onKeyDown={(e) => { if (e.key === "Enter") saveTitle(); if (e.key === "Escape") setEditingTitle(false); }} />
            <button className="btn btn-primary" onClick={saveTitle}>保存</button>
          </div>
        )}
        <div className="text-secondary small mt-2">
          作成: {detail.created_at ? fmtTime(detail.created_at) : "-"} / 最終更新: {detail.updated_at ? fmtTime(detail.updated_at) : "-"}
        </div>
      </div>
      <div className="card-body">
        <ul className="nav nav-tabs mb-3">
          <li className="nav-item">
            <a className={`nav-link ${tab === "events" ? "active" : ""}`} role="button" onClick={() => setTab("events")}>関連イベント</a>
          </li>
          <li className="nav-item">
            <a className={`nav-link ${tab === "comments" ? "active" : ""}`} role="button" onClick={() => setTab("comments")}>コメント</a>
          </li>
        </ul>
        {tab === "events" && <CaseEventsTab detail={detail} onChanged={onChanged} onOpenEvent={onOpenEvent} />}
        {tab === "comments" && <CaseCommentsTab caseId={detail.id} />}
      </div>
    </div>
  );
}

function CaseEventsTab({ detail, onChanged, onOpenEvent }: {
  detail: CaseDetail; onChanged: () => void; onOpenEvent: (id: number) => void;
}) {
  const [notes, setNotes] = useState<Record<number, string>>({});
  useEffect(() => {
    setNotes(Object.fromEntries(detail.events.map((e) => [e.id, e.note ?? ""])));
  }, [detail.events]);

  const saveNote = (eventId: number) => {
    api.updateCaseEventNote(detail.id, eventId, notes[eventId]?.trim() || null).catch(() => {});
  };
  const unlink = async (eventId: number) => {
    if (!confirm("このイベントの紐付けを解除しますか？（イベント自体は削除されません）")) return;
    try { await api.removeCaseEvent(detail.id, eventId); onChanged(); } catch { /* noop */ }
  };

  return (
    <div className="table-responsive" style={{ maxHeight: 480 }}>
      <table className="table table-vcenter table-sm card-table">
        <thead><tr><th>時刻</th><th>ログソース</th><th>種別</th><th>イベント</th><th>メッセージ</th><th>メモ</th><th></th></tr></thead>
        <tbody>
          {detail.events.map((e) => (
            <tr key={e.id}>
              <td className="text-nowrap">{e.event_time ? fmtTime(e.event_time) : "-"}</td>
              <td className="text-nowrap">{e.source_name}</td>
              <td className="text-nowrap">{stLabel(e.source_type)}</td>
              <td className="text-nowrap">
                <a role="button" onClick={() => onOpenEvent(e.id)}>{e.event_action ?? `#${e.id}`}</a>
              </td>
              <td className="text-truncate" style={{ maxWidth: 200 }}>{e.message}</td>
              <td>
                <input className="form-control form-control-sm" value={notes[e.id] ?? ""}
                  onChange={(ev) => setNotes((p) => ({ ...p, [e.id]: ev.target.value }))}
                  onBlur={() => saveNote(e.id)}
                  onKeyDown={(ev) => { if (ev.key === "Enter") (ev.target as HTMLInputElement).blur(); }} />
              </td>
              <td className="text-end">
                <button className="btn btn-sm btn-outline-danger" onClick={() => unlink(e.id)}>解除</button>
              </td>
            </tr>
          ))}
          {detail.events.length === 0 && <tr><td colSpan={7} className="text-secondary text-center py-4">イベント未登録</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

// ケース側は監査ログを持たず、調査メモとしてのコメントのみ（設計書v4 3章）。
function CaseCommentsTab({ caseId }: { caseId: number }) {
  const [items, setItems] = useState<CaseCommentItem[]>([]);
  const [body, setBody] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const load = () => api.caseComments(caseId).then(setItems).catch((e) => setErr((e as Error).message));
  useEffect(() => { load(); }, [caseId]);

  const addComment = async () => {
    if (!body.trim()) return;
    setErr(null);
    try { await api.addCaseComment(caseId, body.trim()); setBody(""); load(); } catch (e) { setErr((e as Error).message); }
  };

  return (
    <div>
      {err && <div className="alert alert-danger py-2">{err}</div>}
      <div className="mb-3">
        <textarea className="form-control mb-2" rows={2} placeholder="調査メモ・気づいたことなど"
          value={body} onChange={(e) => setBody(e.target.value)} />
        <button className="btn btn-primary btn-sm" disabled={!body.trim()} onClick={addComment}>コメントを追加</button>
      </div>
      <div style={{ maxHeight: 420, overflow: "auto" }}>
        {items.length === 0 && <div className="text-secondary small">まだコメントはありません。</div>}
        {items.map((c) => (
          <div key={c.id} className="border rounded p-2 mb-1">
            <div className="text-break">{c.body}</div>
            <div className="text-secondary small mt-1">
              {c.actor_name ? `${c.actor_name} · ` : ""}{c.created_at ? fmtTime(c.created_at) : ""}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
