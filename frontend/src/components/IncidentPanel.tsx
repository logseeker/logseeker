import { useEffect, useState } from "react";
import { api } from "../api";
import { fmtTime, stLabel } from "../labels";
import { EventDetail } from "./EventDetail";
import type {
  AssignableUser, IncidentActivityItem, IncidentDetail, IncidentResponseActionTypeDef, IncidentStatusDef,
  Role, Verdict,
} from "../types";

const VERDICT_OPTS: { v: Verdict; label: string }[] = [
  { v: "unjudged", label: "未判定" },
  { v: "true_positive", label: "True Positive（真陽性）" },
  { v: "false_positive", label: "誤検知" },
  { v: "over_detection", label: "過検知" },
  { v: "other", label: "その他" },
];

const ROLE_RANK: Record<Role, number> = { viewer: 1, editor: 2, sysadmin: 3, admin: 4 };

// バックエンド incident_status.py の can_transition と同じロジック（表示上の選択肢絞り込み用。
// 実際の権限判定はAPI側が必ず行うため、ここはUX目的の補助でしかない）。
function canTransition(fromSpecial: string | null | undefined, toSpecial: string | null | undefined, role: Role): boolean {
  if (fromSpecial === "unassigned") return true;
  if (toSpecial === "unassigned") return ROLE_RANK[role] >= ROLE_RANK.sysadmin;
  if (toSpecial === "done") return true;
  if (fromSpecial === "done" && toSpecial === "reopened") return ROLE_RANK[role] >= ROLE_RANK.sysadmin;
  return true;
}

const ACTION_LABEL: Record<string, string> = {
  "incident.create": "インシデント作成", status_change: "ステータス変更",
  assignee_change: "担当者変更", verdict_change: "判定結果変更", "response_action.add": "対応アクション追加",
  "status_master.create": "ステータス追加", "status_master.visibility": "ステータス表示切替",
  "response_action_type.create": "対応アクション種別追加", "response_action_type.visibility": "対応アクション種別表示切替",
};

// インシデント＝アラート単位の確定事案の詳細画面（設計書v4 4章）。独立した画面(screen==="incident")
// としてApp.tsxから直接描画される（v1〜v2初期実装では「ケース」画面のサブビューとしてstateで
// 出し分けていたため、ヘッダー・パンくずが常に「ケース」のままになる不整合があった）。
// ケースには一切依存しない（設計書v4：ケースとインシデントは完全に独立した概念）ため、
// 元ケースへのリンクは廃止し、代わりに起因となった「主役アラート情報」を上部に固定表示する。
// マスタ管理UI（ステータス/対応アクション種別）はこの画面に同居させず、独立した
// MasterSettings.tsx に分離している（設計書v3 7章）。
export function IncidentPanel({ incidentId, effRole }: {
  incidentId: number; effRole: Role;
}) {
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [statuses, setStatuses] = useState<IncidentStatusDef[]>([]);
  const [actionTypes, setActionTypes] = useState<IncidentResponseActionTypeDef[]>([]);
  const [users, setUsers] = useState<AssignableUser[]>([]);
  const [tab, setTab] = useState<"alert" | "activity">("alert");
  const [err, setErr] = useState<string | null>(null);
  const [openEventId, setOpenEventId] = useState<number | null>(null);

  const reloadDetail = () => api.incident(incidentId).then(setDetail).catch(() => setDetail(null));
  const reloadStatuses = () => api.incidentStatuses().then(setStatuses).catch(() => {});
  const reloadActionTypes = () => api.responseActionTypes().then(setActionTypes).catch(() => {});

  useEffect(() => { reloadDetail(); reloadStatuses(); reloadActionTypes(); },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [incidentId]);
  useEffect(() => { api.incidentAssignableUsers().then(setUsers).catch(() => setUsers([])); }, []);

  if (!detail) {
    return <div className="card"><div className="card-body text-secondary">読み込み中…</div></div>;
  }

  const fromStatus = statuses.find((s) => s.id === detail.status_id) ?? null;
  const guard = async (fn: () => Promise<unknown>) => {
    setErr(null);
    try { await fn(); reloadDetail(); } catch (e) { setErr((e as Error).message); }
  };
  // タイトル編集APIはインシデントには設けていない（ケースからの複製のみ。表示専用）。

  return (
    <>
    <div className="card">
      <div className="card-header d-block">
        {err && <div className="alert alert-danger py-2">{err}</div>}
        <h3 className="card-title mb-1">{detail.title}</h3>
        <div className="row g-2">
          <div className="col-auto">
            <label className="form-label small text-secondary mb-1">ステータス</label>
            <select className="form-select form-select-sm" value={detail.status_id ?? ""}
              onChange={(e) => guard(() => api.updateIncidentStatus(detail.id, Number(e.target.value)))}>
              {statuses
                .filter((s) => s.is_visible || s.id === detail.status_id)
                .filter((s) => s.id === detail.status_id || canTransition(fromStatus?.special_type, s.special_type, effRole))
                .map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </div>
          <div className="col-auto">
            <label className="form-label small text-secondary mb-1">担当者</label>
            <select className="form-select form-select-sm" value={detail.assignee_user_id ?? ""}
              onChange={(e) => guard(() => api.updateIncidentAssignee(detail.id, e.target.value ? Number(e.target.value) : null))}>
              <option value="">未割り当て</option>
              {users.map((u) => <option key={u.id} value={u.id}>{u.display_name || u.username}</option>)}
            </select>
          </div>
          <div className="col-auto">
            <label className="form-label small text-secondary mb-1">判定結果</label>
            <select className="form-select form-select-sm" value={detail.verdict}
              onChange={(e) => guard(() => api.updateIncidentVerdict(detail.id, e.target.value as Verdict))}>
              {VERDICT_OPTS.map((v) => <option key={v.v} value={v.v}>{v.label}</option>)}
            </select>
          </div>
        </div>
        <div className="text-secondary small mt-2">
          作成: {detail.created_at ? fmtTime(detail.created_at) : "-"} / 最終更新: {detail.updated_at ? fmtTime(detail.updated_at) : "-"}
        </div>
      </div>
      <div className="card-body">
        <ul className="nav nav-tabs mb-3">
          <li className="nav-item">
            <a className={`nav-link ${tab === "alert" ? "active" : ""}`} role="button" onClick={() => setTab("alert")}>主役アラート情報</a>
          </li>
          <li className="nav-item">
            <a className={`nav-link ${tab === "activity" ? "active" : ""}`} role="button" onClick={() => setTab("activity")}>対応履歴</a>
          </li>
        </ul>
        {tab === "alert" && <IncidentAlertTab event={detail.event} onOpenEvent={() => setOpenEventId(detail.event_id)} />}
        {tab === "activity" && (
          <IncidentActivityTab incidentId={detail.id} actionTypes={actionTypes} onActionAdded={reloadDetail} />
        )}
      </div>
    </div>
    {openEventId != null && (
      <EventDetail id={openEventId} onClose={() => setOpenEventId(null)} onPivot={() => {}} />
    )}
    </>
  );
}

// このインシデントの起因となった唯一のアラート（主役アラート情報）を固定表示する
// （設計書v4 5-3節：元ケースへのリンクは廃止し、代わりにこれを表示する）。
function IncidentAlertTab({ event, onOpenEvent }: {
  event: IncidentDetail["event"]; onOpenEvent: () => void;
}) {
  if (!event) return <div className="text-secondary text-center py-4">アラート情報を取得できません</div>;
  return (
    <div>
      <div className="row mb-1"><div className="col-3 text-secondary">時刻</div><div className="col-9">{event.event_time ? fmtTime(event.event_time) : "-"}</div></div>
      <div className="row mb-1"><div className="col-3 text-secondary">ログソース</div><div className="col-9">{event.source_name ?? "-"}</div></div>
      <div className="row mb-1"><div className="col-3 text-secondary">種別</div><div className="col-9">{stLabel(event.source_type)}</div></div>
      <div className="row mb-1"><div className="col-3 text-secondary">イベント</div><div className="col-9">{event.event_action ?? "-"}</div></div>
      <div className="row mb-1"><div className="col-3 text-secondary">結果</div><div className="col-9">{event.event_result ?? "-"}</div></div>
      <div className="row mb-1"><div className="col-3 text-secondary">重大度</div><div className="col-9">{event.event_severity ?? "-"}</div></div>
      <div className="row mb-2"><div className="col-3 text-secondary">メッセージ</div><div className="col-9 text-break">{event.message ?? "-"}</div></div>
      <button className="btn btn-outline-primary btn-sm" onClick={onOpenEvent}>イベント詳細を見る（Payload・正規化・相関など）</button>
    </div>
  );
}

// 対応履歴：コメント・対応アクション・監査ログを統合表示（設計書v2 4-4節）
// TODO: コメント欄と対応アクション欄が横並びの別入力になっているが、将来的には
// 1つの入力導線に一体化する可能性がある（今回はリリース優先のため見送り）。
function IncidentActivityTab({ incidentId, actionTypes, onActionAdded }: {
  incidentId: number; actionTypes: IncidentResponseActionTypeDef[]; onActionAdded: () => void;
}) {
  const [items, setItems] = useState<IncidentActivityItem[]>([]);
  const [body, setBody] = useState("");
  const [actionTypeId, setActionTypeId] = useState<number | "">("");
  const [actionDetail, setActionDetail] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const load = () => api.incidentActivity(incidentId).then(setItems).catch((e) => setErr((e as Error).message));
  useEffect(() => { load(); }, [incidentId]);

  const addComment = async () => {
    if (!body.trim()) return;
    setErr(null);
    try { await api.addIncidentComment(incidentId, body.trim()); setBody(""); load(); } catch (e) { setErr((e as Error).message); }
  };
  const addAction = async () => {
    if (actionTypeId === "") return;
    setErr(null);
    try {
      await api.addIncidentResponseAction(incidentId, { action_type_id: Number(actionTypeId), detail: actionDetail.trim() || undefined });
      setActionTypeId(""); setActionDetail(""); load(); onActionAdded();
    } catch (e) { setErr((e as Error).message); }
  };

  return (
    <div>
      {err && <div className="alert alert-danger py-2">{err}</div>}
      <div className="row g-3 mb-3">
        <div className="col-md-6">
          <label className="form-label">コメント</label>
          <textarea className="form-control mb-2" rows={2} placeholder="調査進捗・担当者間の連絡など"
            value={body} onChange={(e) => setBody(e.target.value)} />
          <button className="btn btn-primary btn-sm" disabled={!body.trim()} onClick={addComment}>コメントを追加</button>
        </div>
        <div className="col-md-6">
          <label className="form-label">対応アクションを記録</label>
          <select className="form-select form-select-sm mb-2" value={actionTypeId}
            onChange={(e) => setActionTypeId(e.target.value ? Number(e.target.value) : "")}>
            <option value="">種別を選択…</option>
            {actionTypes.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
          <input className="form-control form-control-sm mb-2" placeholder="詳細メモ（任意）"
            value={actionDetail} onChange={(e) => setActionDetail(e.target.value)} />
          <button className="btn btn-outline-danger btn-sm" disabled={actionTypeId === ""} onClick={addAction}>
            対応アクションを追加
          </button>
        </div>
      </div>
      <div style={{ maxHeight: 420, overflow: "auto" }}>
        {items.length === 0 && <div className="text-secondary small">まだ活動記録はありません。</div>}
        {items.map((it) => (
          <div key={it.id} className="border rounded p-2 mb-1">
            {it.type === "comment" ? (
              <div className="text-break">{it.body}</div>
            ) : it.type === "response_action" ? (
              <div>
                <span className="badge bg-red-lt me-1">対応: {it.after_value}</span>
                {it.body && <span className="text-break">{it.body}</span>}
              </div>
            ) : (
              <div className="text-secondary">
                <span className="badge bg-secondary-lt me-1">{ACTION_LABEL[it.type] ?? it.type}</span>
                {it.before_value && it.after_value ? `${it.before_value} → ${it.after_value}`
                  : it.after_value ?? it.before_value ?? ""}
              </div>
            )}
            <div className="text-secondary small mt-1">
              {it.actor_name ? `${it.actor_name} · ` : ""}{it.created_at ? fmtTime(it.created_at) : ""}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

