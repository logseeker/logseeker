import { useEffect, useState } from "react";
import { api } from "../api";
import type { AuthStatus, CustomRule, FilterState, RuleDef, RuleHit } from "../types";

const SEV: Record<string, { cls: string; label: string }> = {
  critical: { cls: "danger", label: "重大" },
  high: { cls: "warning", label: "高" },
  warning: { cls: "info", label: "警告" },
  info: { cls: "secondary", label: "情報" },
};

const FIELD_LABEL: Record<string, string> = {
  message: "メッセージ", url_path: "URLパス", url_domain: "ドメイン", actor_user: "ユーザー",
  source_ip: "送信元IP", device_name: "ホスト/デバイス", event_category: "カテゴリ",
  event_action: "アクション", event_result: "結果", http_status_code: "HTTPステータス",
  service_name: "サービス", source_country: "国コード", host_name: "ホスト名",
  source_asn: "AS番号", source_as_org: "AS組織名",
};

const EMPTY_FORM = {
  name: "", description: "", severity: "warning", match_field: "message", match_op: "contains",
  match_value: "", group_by: "", min_count: 1, recommendation: "",
};

// 注意喚起（ルールヒット）＋対策。IOC一致など攻撃の兆候を提示し、ブロック等を推奨。
export function Rules({ filter, onPick, auth }: {
  filter: FilterState; onPick: (k: string, v: string) => void; auth?: AuthStatus;
}) {
  const [hits, setHits] = useState<RuleHit[]>([]);
  const [defs, setDefs] = useState<RuleDef[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const canManage = !auth?.auth_required || auth?.user?.role === "sysadmin" || auth?.user?.role === "admin";

  useEffect(() => {
    api.ruleHits(filter).then((r) => setHits(r.hits)).catch((e) => setErr((e as Error).message));
    api.rules().then(setDefs).catch(() => {});
  }, [filter]);

  if (err) return <div className="alert alert-danger">取得失敗: {err}</div>;

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="card">
          <div className="card-header"><h3 className="card-title">監視ルール一覧</h3></div>
          <div className="table-responsive">
            <table className="table table-vcenter card-table">
              <thead><tr><th>ルール</th><th>重大度</th><th>説明</th><th>対策</th></tr></thead>
              <tbody>
                {defs.map((d) => {
                  const sv = SEV[d.severity] ?? SEV.info;
                  return (
                    <tr key={d.id}>
                      <td className="text-nowrap">{d.name}</td>
                      <td><span className={`badge bg-${sv.cls}-lt`}>{sv.label}</span></td>
                      <td>{d.description}</td>
                      <td className="text-secondary">{d.recommendation}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {canManage && <div className="col-12"><CustomRulesPanel /></div>}
      {canManage && <div className="col-12"><SilencePanel /></div>}

      <div className="col-12">
        <h3 className="mb-2">検出された注意喚起（{hits.length}）</h3>
        {hits.length === 0 && (
          <div className="card"><div className="empty">
            <p className="empty-title">該当なし</p>
            <p className="empty-subtitle text-secondary">現在のデータで閾値を超える兆候はありません。</p>
          </div></div>
        )}
        {hits.map((h, i) => {
          const sv = SEV[h.severity] ?? SEV.info;
          return (
            <div key={i} className={`alert alert-${sv.cls} mb-2`}>
              <div className="d-flex align-items-start">
                <div className="flex-fill">
                  <div className="d-flex align-items-center gap-2 mb-1">
                    <span className={`badge bg-${sv.cls}`}>{sv.label}</span>
                    <strong>{h.title}</strong>
                    <span className="text-secondary small">［{h.rule_name}］</span>
                  </div>
                  <div className="small mb-1">{h.evidence}</div>
                  <div className="small"><strong>対策：</strong>{h.recommendation}</div>
                </div>
                {h.pivot && (
                  <button className="btn btn-sm btn-outline-dark ms-2 text-nowrap"
                    onClick={() => onPick(h.pivot!.field, h.pivot!.value)}>
                    関連イベントを見る
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// カスタムルール管理（sysadmin以上）。任意コード実行はせず、既存の正規化フィールドへの
// 部分一致/完全一致＋件数しきい値のみ扱う安全な設計。
function CustomRulesPanel() {
  const [rows, setRows] = useState<CustomRule[]>([]);
  const [fields, setFields] = useState<string[]>([]);
  const [groupFields, setGroupFields] = useState<string[]>([]);
  const [form, setForm] = useState(EMPTY_FORM);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = () => api.customRules().then((r) => {
    setRows(r.items); setFields(r.match_fields); setGroupFields(r.groupby_fields);
  }).catch((e) => setErr((e as Error).message));
  useEffect(() => { load(); }, []);

  const flash = (m: string) => { setMsg(m); setTimeout(() => setMsg(null), 2500); };

  const create = async () => {
    setErr(null);
    try {
      await api.createCustomRule({
        ...form,
        group_by: form.group_by || undefined,
        description: form.description || undefined,
        recommendation: form.recommendation || undefined,
      });
      setForm(EMPTY_FORM); load(); flash("ルールを作成しました");
    } catch (e) { setErr((e as Error).message); }
  };
  const toggle = async (r: CustomRule) => {
    try { await api.updateCustomRule(r.id, { enabled: !r.enabled }); load(); }
    catch (e) { setErr((e as Error).message); }
  };
  const remove = async (r: CustomRule) => {
    if (!confirm(`「${r.name}」を削除しますか？`)) return;
    try { await api.deleteCustomRule(r.id); load(); flash("削除しました"); }
    catch (e) { setErr((e as Error).message); }
  };

  return (
    <div className="card border-primary">
      <div className="card-header"><h3 className="card-title">🔧 カスタムルール（自分で検知条件を追加）</h3></div>
      <div className="card-body">
        {err && <div className="alert alert-danger py-2">{err}</div>}
        {msg && <div className="alert alert-success py-2">{msg}</div>}
        <div className="text-secondary small mb-3">
          既存フィールドへの部分一致/完全一致＋件数しきい値のみ（任意コード実行はできない安全設計）。
          「集計軸」を指定すると、その項目ごとに件数を数えてしきい値を超えたら検知します（例: 送信元IPごとに5件以上）。
        </div>

        {rows.length > 0 && (
          <div className="table-responsive mb-3">
            <table className="table table-vcenter table-sm card-table">
              <thead><tr><th>有効</th><th>名前</th><th>重大度</th><th>条件</th><th>しきい値</th><th></th></tr></thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <label className="form-check form-switch mb-0">
                        <input className="form-check-input" type="checkbox" checked={r.enabled} onChange={() => toggle(r)} />
                      </label>
                    </td>
                    <td className="text-nowrap">{r.name}</td>
                    <td><span className={`badge bg-${SEV[r.severity]?.cls ?? "secondary"}-lt`}>{SEV[r.severity]?.label ?? r.severity}</span></td>
                    <td className="small">
                      {FIELD_LABEL[r.match_field] ?? r.match_field} が「{r.match_value}」に{r.match_op === "contains" ? "部分一致" : "完全一致"}
                      {r.group_by && <> / 集計軸: {FIELD_LABEL[r.group_by] ?? r.group_by}</>}
                    </td>
                    <td className="text-nowrap">{r.min_count} 件以上</td>
                    <td className="text-end"><button className="btn btn-sm btn-outline-danger" onClick={() => remove(r)}>削除</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="row g-2">
          <div className="col-md-4">
            <label className="form-label">ルール名</label>
            <input className="form-control" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="例: 特定の攻撃文字列の検知" />
          </div>
          <div className="col-md-4">
            <label className="form-label">対象フィールド</label>
            <select className="form-select" value={form.match_field} onChange={(e) => setForm({ ...form, match_field: e.target.value })}>
              {fields.map((f) => <option key={f} value={f}>{FIELD_LABEL[f] ?? f}</option>)}
            </select>
          </div>
          <div className="col-md-4">
            <label className="form-label">重大度</label>
            <select className="form-select" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
              <option value="critical">重大</option><option value="high">高</option><option value="warning">警告</option>
            </select>
          </div>
          <div className="col-md-3">
            <label className="form-label">条件</label>
            <select className="form-select" value={form.match_op} onChange={(e) => setForm({ ...form, match_op: e.target.value })}>
              <option value="contains">含む（部分一致）</option><option value="equals">完全一致</option>
            </select>
          </div>
          <div className="col-md-5">
            <label className="form-label">一致させる値</label>
            <input className="form-control" value={form.match_value} onChange={(e) => setForm({ ...form, match_value: e.target.value })} placeholder="例: eval-stdin" />
          </div>
          <div className="col-md-4">
            <label className="form-label">集計軸（任意）</label>
            <select className="form-select" value={form.group_by} onChange={(e) => setForm({ ...form, group_by: e.target.value })}>
              <option value="">指定しない（総数で判定）</option>
              {groupFields.map((f) => <option key={f} value={f}>{FIELD_LABEL[f] ?? f}</option>)}
            </select>
          </div>
          <div className="col-md-3">
            <label className="form-label">しきい値（件数以上）</label>
            <input className="form-control" type="number" min={1} value={form.min_count}
              onChange={(e) => setForm({ ...form, min_count: Math.max(1, Number(e.target.value)) })} />
          </div>
          <div className="col-md-9">
            <label className="form-label">対策（任意・表示される推奨アクション）</label>
            <input className="form-control" value={form.recommendation} onChange={(e) => setForm({ ...form, recommendation: e.target.value })} placeholder="例: 該当IPを遮断し、WAFルールを追加" />
          </div>
        </div>
        <button className="btn btn-primary mt-3" disabled={!form.name || !form.match_value} onClick={create}>ルールを作成</button>
      </div>
    </div>
  );
}

// ログ未達（送信元停止）監視のしきい値
function SilencePanel() {
  const [hours, setHours] = useState(24);
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => { api.silenceSettings().then((r) => setHours(r.hours)).catch(() => {}); }, []);
  const save = async () => {
    await api.saveSilenceSettings(hours);
    setMsg("保存しました"); setTimeout(() => setMsg(null), 2000);
  };
  return (
    <div className="card">
      <div className="card-header"><h3 className="card-title">📡 ログ未達監視</h3></div>
      <div className="card-body">
        <div className="text-secondary small mb-2">
          継続的に送信していたログソースが、指定時間データを送ってこなくなったら「ログ未達」として検知・通知します
          （エージェント停止・ネットワーク障害・設定ミス等の早期発見）。
        </div>
        <div className="d-flex align-items-end gap-2">
          <div>
            <label className="form-label">未達とみなす時間</label>
            <div className="input-group" style={{ width: 200 }}>
              <input className="form-control" type="number" min={1} value={hours} onChange={(e) => setHours(Math.max(1, Number(e.target.value)))} />
              <span className="input-group-text">時間</span>
            </div>
          </div>
          <button className="btn btn-primary" onClick={save}>保存</button>
          {msg && <span className="text-success">{msg}</span>}
        </div>
      </div>
    </div>
  );
}
