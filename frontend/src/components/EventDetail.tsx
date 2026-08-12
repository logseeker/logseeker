import { useEffect, useState } from "react";
import { api } from "../api";
import { fmtTime } from "../labels";
import type { EventDetailData, EventRow } from "../types";

type Props = {
  id: number;
  onClose: () => void;
  onPivot: (key: string, value: string) => void;      // この値でEventsを絞り込む
  onEntity?: (entityType: string, value: string) => void;
  onOpenCase?: (caseId: number) => void;
  onOpenIncident?: (incidentId: number) => void;
  // "panel" ＝ Events画面の右側にそのまま埋め込む（既定の導線）
  // "modal" ＝ 中央ポップアップ。Cases.tsx / IncidentPanel.tsx からの従来の呼び出し用
  variant?: "modal" | "panel";
};

type Related = { keys: { entity_type: string; entity_value: string }[]; items: EventRow[] };

// イベント詳細。表示するのは受信フィールド（payload内でTaxonomy KEYと完全一致するKEY）だけで、
// Taxonomy外KEYは件数のみ知らせて中身を出さない（v12 §10.3）。
export function EventDetail({ id, onClose, onPivot, onEntity, onOpenCase, onOpenIncident,
  variant = "modal" }: Props) {
  const [viewId, setViewId] = useState(id);
  const [d, setD] = useState<EventDetailData | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [related, setRelated] = useState<Related>({ keys: [], items: [] });
  const [cases, setCases] = useState<{ id: number; title: string }[]>([]);
  const [picker, setPicker] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => { setViewId(id); }, [id]);

  const load = () => {
    setD(null);
    api.eventDetail(viewId).then(setD).catch((e) => setErr((e as Error).message));
    api.related(viewId).then(setRelated).catch(() => setRelated({ keys: [], items: [] }));
  };
  useEffect(load, [viewId]);

  const pivot = (key: string, value: unknown) => {
    if (value === null || value === undefined || value === "") return;
    onPivot(key, String(value));
    if (variant === "modal") onClose();
  };

  const openInNewTab = () => {
    const u = new URL(window.location.href);
    u.search = `?screen=events&event=${viewId}`;
    window.open(u.toString(), "_blank");
  };

  const body = (
    <>
      <div className="modal-header">
        <h5 className="modal-title mb-0">
          イベント #{viewId}
          {d?.class_value && <span className="badge bg-blue-lt ms-2">{d.class_value}</span>}
          {d?.is_attention && <span className="badge bg-red-lt ms-2">注目</span>}
          {d?.resolved && <span className="badge bg-green-lt ms-2">対応済み</span>}
        </h5>
        <div className="ms-auto d-flex align-items-center gap-1">
          <button className="btn btn-sm btn-ghost-secondary" title="新規タブで開く" onClick={openInNewTab}>⤢</button>
          <button className="btn-close" aria-label="閉じる" onClick={onClose} />
        </div>
      </div>

      {err && <div className="alert alert-danger m-3 mb-0">{err}</div>}

      {!d ? <div className="p-5 text-center text-secondary">読み込み中...</div> : (
        <div className="modal-body" style={{ overflowY: "auto" }}>
          <div className="d-flex flex-wrap gap-2 mb-3">
            <button className="btn btn-sm btn-outline-primary"
              onClick={() => api.setEventResolved(d.id, !d.resolved).then(load)}>
              {d.resolved ? "未対応に戻す" : "対応済みにする"}
            </button>
            {d.linked_case ? (
              <button className="btn btn-sm btn-outline-secondary" onClick={() => onOpenCase?.(d.linked_case!.id)}>
                ケース「{d.linked_case.title}」を開く
              </button>
            ) : (
              <button className="btn btn-sm btn-outline-secondary"
                onClick={() => { api.cases().then(setCases).catch(() => setCases([])); setPicker(true); }}>
                ケースに追加
              </button>
            )}
            {d.linked_incident ? (
              <button className="btn btn-sm btn-outline-danger" onClick={() => onOpenIncident?.(d.linked_incident!.id)}>
                インシデント「{d.linked_incident.title}」を開く
              </button>
            ) : d.is_attention ? (
              <button className="btn btn-sm btn-outline-danger" disabled={busy}
                onClick={() => {
                  setBusy(true);
                  api.createIncidentFromEvent(viewId)
                    .then((r) => { load(); onOpenIncident?.(r.id); })
                    .catch((e) => setErr((e as Error).message)).finally(() => setBusy(false));
                }}>インシデント化</button>
            ) : null}
          </div>

          {picker && (
            <div className="card mb-3">
              <div className="card-body">
                <div className="d-flex justify-content-between align-items-center mb-2">
                  <strong>追加先のケース</strong>
                  <button className="btn btn-sm btn-link" onClick={() => setPicker(false)}>閉じる</button>
                </div>
                {cases.length === 0 ? <div className="text-secondary small">ケースがありません</div> : (
                  <div className="list-group">
                    {cases.map((c) => (
                      <button key={c.id} disabled={busy} className="list-group-item list-group-item-action"
                        onClick={() => {
                          setBusy(true);
                          api.addCaseEvent(c.id, { event_id: viewId })
                            .then(() => { setPicker(false); load(); })
                            .catch((e) => setErr((e as Error).message)).finally(() => setBusy(false));
                        }}>{c.title}</button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* 受信フィールド：Taxonomy KEY完全一致分のみ。値クリックでその値に絞り込む */}
          <div className="d-flex align-items-center mb-1">
            <strong className="small">受信フィールド</strong>
            <span className="text-secondary small ms-2">{d.fields.length}件</span>
          </div>
          {d.fields.length === 0 ? (
            <div className="text-secondary small mb-3">
              taxonomy.mdのTaxonomy KEYと一致する受信フィールドがありません。
            </div>
          ) : (
            <div className="list-group list-group-flush mb-2">
              {d.fields.map((f) => (
                <div key={f.key} className="list-group-item px-0 py-1 d-flex align-items-start gap-2">
                  <div className="text-secondary small" style={{ minWidth: 170 }}>
                    {f.label ? <>{f.label}<span className="ms-1">({f.key})</span></> : f.key}
                  </div>
                  <button className="btn btn-sm btn-link p-0 text-start text-wrap flex-fill"
                    title="この値でEventsを絞り込む" onClick={() => pivot(f.key, f.value)}>
                    {typeof f.value === "object" ? JSON.stringify(f.value) : String(f.value)}
                  </button>
                </div>
              ))}
            </div>
          )}
          {d.taxonomy_outside_count > 0 && (
            <div className="text-secondary small mb-3">
              このイベントにはTaxonomy外KEYが{d.taxonomy_outside_count}件あります（DBには無改変で
              保存されていますが、画面には表示しません）。
            </div>
          )}

          <div className="text-secondary small mb-3">
            受信時刻 {fmtTime(d.received_at)} ・ 取り込み {d.ingest_channel}
            {d.source && <> ・ ログソース {d.source}</>}
          </div>

          {related.keys.length > 0 && (
            <>
              <strong className="small">関連エンティティ</strong>
              <div className="d-flex flex-wrap gap-1 my-1">
                {related.keys.map((k) => (
                  <button key={`${k.entity_type}:${k.entity_value}`} className="btn btn-sm btn-outline-secondary"
                    onClick={() => onEntity?.(k.entity_type, k.entity_value)}>
                    {k.entity_type}: {k.entity_value}
                  </button>
                ))}
              </div>
            </>
          )}
          {related.items.length > 1 && (
            <>
              <strong className="small">関連イベント</strong>
              <div className="list-group mt-1">
                {related.items.filter((it) => it.id !== viewId).slice(0, 20).map((it) => (
                  <button key={it.id} className="list-group-item list-group-item-action py-1 small d-flex justify-content-between"
                    onClick={() => setViewId(it.id)}>
                    <span>{fmtTime(it.event_time)}</span><span className="text-secondary">#{it.id}</span>
                  </button>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </>
  );

  if (variant === "panel") {
    return <div className="card d-flex flex-column" style={{ maxHeight: "calc(100vh - 120px)" }}>{body}</div>;
  }
  return (
    <div>
      <div className="modal-backdrop show" style={{ position: "fixed", inset: 0, zIndex: 1040 }} onClick={onClose} />
      <div className="modal d-block" style={{ position: "fixed", inset: 0, zIndex: 1050, overflowY: "auto" }} role="dialog">
        <div className="modal-dialog modal-lg modal-dialog-scrollable" onClick={(e) => e.stopPropagation()}>
          <div className="modal-content">{body}</div>
        </div>
      </div>
    </div>
  );
}
