import { useEffect, useState } from "react";
import { api } from "../api";
import type { IncidentResponseActionTypeDef, IncidentStatusDef } from "../types";

// マスタ設定画面（設計書v3 7章）。インシデント/ケース詳細画面にマスタ編集UIを同居させない、
// という禁止事項を受け、独立した画面として新設した（システム管理者以上のみ。App.tsxのMIN_ROLEで
// 画面自体をゲートしているため、このコンポーネント自身は権限チェックを行わない）。
export function MasterSettings() {
  const [statuses, setStatuses] = useState<IncidentStatusDef[]>([]);
  const [actionTypes, setActionTypes] = useState<IncidentResponseActionTypeDef[]>([]);

  const reloadStatuses = () => api.incidentStatuses(true).then(setStatuses).catch(() => {});
  const reloadActionTypes = () => api.responseActionTypes(true).then(setActionTypes).catch(() => {});

  useEffect(() => { reloadStatuses(); reloadActionTypes(); }, []);

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info mb-0">
          <strong>マスタ設定</strong>：インシデントのステータス・対応アクション種別の選択肢を管理します。
          追加・非表示化はシステム管理者以上のみ行えます。
        </div>
      </div>
      <div className="col-lg-6">
        <div className="card">
          <div className="card-body">
            <StatusMasterAdmin statuses={statuses} onChanged={reloadStatuses} />
          </div>
        </div>
      </div>
      <div className="col-lg-6">
        <div className="card">
          <div className="card-body">
            <ResponseActionTypeAdmin actionTypes={actionTypes} onChanged={reloadActionTypes} />
          </div>
        </div>
      </div>
    </div>
  );
}

// システム管理者以上のみ：ステータスマスタの追加・非表示化
function StatusMasterAdmin({ statuses, onChanged }: { statuses: IncidentStatusDef[]; onChanged: () => void }) {
  const [name, setName] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const create = async () => {
    if (!name.trim()) return;
    setErr(null);
    try { await api.createIncidentStatus(name.trim()); setName(""); onChanged(); } catch (e) { setErr((e as Error).message); }
  };
  const toggle = async (s: IncidentStatusDef) => {
    setErr(null);
    try { await api.setIncidentStatusVisibility(s.id, !s.is_visible); onChanged(); } catch (e) { setErr((e as Error).message); }
  };

  return (
    <div>
      <h4>ステータスマスタ管理</h4>
      {err && <div className="alert alert-danger py-2">{err}</div>}
      <div className="text-secondary small mb-2">
        「未対応」「完了」「再オープン」は特別ステータスとして遷移ルールが固定されています。
        非表示にしても、過去にそのステータスが設定されたインシデントの表示は維持されます。
      </div>
      <table className="table table-sm table-vcenter">
        <thead><tr><th>名前</th><th>表示</th><th></th></tr></thead>
        <tbody>
          {statuses.map((s) => (
            <tr key={s.id}>
              <td>{s.name}</td>
              <td>{s.is_visible ? "表示" : "非表示"}</td>
              <td className="text-end">
                <button className="btn btn-sm btn-outline-secondary" onClick={() => toggle(s)}>
                  {s.is_visible ? "非表示にする" : "表示する"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="input-group mt-2">
        <input className="form-control" placeholder="新規ステータス名" value={name} onChange={(e) => setName(e.target.value)} />
        <button className="btn btn-outline-primary" onClick={create}>追加</button>
      </div>
    </div>
  );
}

// システム管理者以上のみ：対応アクション種別マスタの追加・非表示化（設計書v2 4-4節）
function ResponseActionTypeAdmin({ actionTypes, onChanged }: {
  actionTypes: IncidentResponseActionTypeDef[]; onChanged: () => void;
}) {
  const [name, setName] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const create = async () => {
    if (!name.trim()) return;
    setErr(null);
    try { await api.createResponseActionType(name.trim()); setName(""); onChanged(); } catch (e) { setErr((e as Error).message); }
  };
  const toggle = async (t: IncidentResponseActionTypeDef) => {
    setErr(null);
    try { await api.setResponseActionTypeVisibility(t.id, !t.is_visible); onChanged(); } catch (e) { setErr((e as Error).message); }
  };

  return (
    <div>
      <h4>対応アクション種別マスタ管理</h4>
      {err && <div className="alert alert-danger py-2">{err}</div>}
      <table className="table table-sm table-vcenter">
        <thead><tr><th>名前</th><th>表示</th><th></th></tr></thead>
        <tbody>
          {actionTypes.map((t) => (
            <tr key={t.id}>
              <td>{t.name}</td>
              <td>{t.is_visible ? "表示" : "非表示"}</td>
              <td className="text-end">
                <button className="btn btn-sm btn-outline-secondary" onClick={() => toggle(t)}>
                  {t.is_visible ? "非表示にする" : "表示する"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="input-group mt-2">
        <input className="form-control" placeholder="新規種別名" value={name} onChange={(e) => setName(e.target.value)} />
        <button className="btn btn-outline-primary" onClick={create}>追加</button>
      </div>
    </div>
  );
}
