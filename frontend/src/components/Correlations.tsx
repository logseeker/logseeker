import { useEffect, useState } from "react";
import { api } from "../api";
import { stLabel } from "../labels";
import type { CorrelationItem } from "../types";

// 相関分析＝AIなし。同じ資産/主体（IP・ユーザー）が複数のログソース種別に
// またがって出現する度合いをSQL集計で出す。横断数が多いほど“複数システムを触った”＝要調査。
const ENTITY_TABS = [
  { v: "ip", label: "IPアドレス" },
  { v: "user", label: "ユーザー" },
  { v: "domain", label: "ドメイン" },
];

export function Correlations({ onPick, onEntity }: {
  onPick: (k: string, v: string) => void;
  onEntity: (type: string, value: string) => void;
}) {
  const [etype, setEtype] = useState("ip");
  const [minSources, setMinSources] = useState(1);
  const [items, setItems] = useState<CorrelationItem[]>([]);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setErr(null);
    api.correlations(etype, minSources, 150).then((r) => setItems(r.items))
      .catch((e) => setErr((e as Error).message));
  }, [etype, minSources]);

  const pivotCol: Record<string, string> = {
    ip: "source_ip", user: "actor_user", domain: "url_domain",
  };
  const ts = (s: string | null) => (s ? s.replace("T", " ").slice(0, 16) : "-");
  const crossCount = items.filter((i) => i.source_type_count >= 2).length;

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info">
          <strong>相関分析</strong>：同じ{ENTITY_TABS.find((t) => t.v === etype)?.label}が
          <strong>複数の種類のログソースにまたがって出現</strong>しているかを集計します（AI不使用・SQL集計）。
          横断システム数が多いものは「Webも叩きSSHも試した」等、<strong>複数システムを触った可能性</strong>があり優先調査対象です。
        </div>
      </div>

      <div className="col-12">
        <div className="card"><div className="card-body">
          <div className="d-flex gap-3 align-items-center flex-wrap">
            <ul className="nav nav-pills">
              {ENTITY_TABS.map((t) => (
                <li className="nav-item" key={t.v}>
                  <a className={`nav-link ${etype === t.v ? "active" : ""}`} role="button"
                    onClick={() => setEtype(t.v)}>{t.label}</a>
                </li>
              ))}
            </ul>
            <div className="ms-auto d-flex align-items-center gap-2">
              <span className="text-secondary small">横断システム数</span>
              <select className="form-select form-select-sm w-auto" value={minSources}
                onChange={(e) => setMinSources(Number(e.target.value))}>
                <option value={1}>すべて（1以上）</option>
                <option value={2}>2以上（相関あり）</option>
                <option value={3}>3以上（高相関）</option>
              </select>
            </div>
          </div>
        </div></div>
      </div>

      {err && <div className="col-12"><div className="alert alert-danger">取得失敗: {err}</div></div>}

      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">相関結果（{items.length}）</h3>
            <span className="card-subtitle ms-2 text-secondary">
              うち複数システム横断: <strong className="text-danger">{crossCount}</strong> 件
            </span>
          </div>
          <div className="table-responsive">
            <table className="table table-vcenter card-table table-hover">
              <thead><tr>
                <th>値</th><th className="text-center">横断システム数</th><th>ログソース種別</th>
                <th className="text-end">イベント数</th><th className="text-end">失敗数</th>
                <th>初回〜最終</th><th></th>
              </tr></thead>
              <tbody>
                {items.map((it) => (
                  <tr key={it.value} className={it.source_type_count >= 2 ? "table-warning" : ""}>
                    <td className="text-nowrap">
                      <a role="button" className="text-primary fw-bold"
                        onClick={() => onEntity(etype, it.value)}>{it.value}</a>
                      {it.is_ioc && <span className="badge bg-red ms-2">IOC</span>}
                    </td>
                    <td className="text-center">
                      <span className={`badge ${it.source_type_count >= 3 ? "bg-red" : it.source_type_count >= 2 ? "bg-orange" : "bg-secondary-lt"}`}>
                        {it.source_type_count}
                      </span>
                    </td>
                    <td>
                      {it.source_types.map((s) => (
                        <span key={s} className="badge bg-blue-lt me-1">{stLabel(s)}</span>
                      ))}
                    </td>
                    <td className="text-end">{it.event_count.toLocaleString()}</td>
                    <td className="text-end">
                      {it.failure_count > 0
                        ? <span className="text-danger">{it.failure_count.toLocaleString()}</span>
                        : <span className="text-secondary">0</span>}
                    </td>
                    <td className="text-nowrap text-secondary small">{ts(it.first_seen)} 〜 {ts(it.last_seen)}</td>
                    <td className="text-end">
                      <button className="btn btn-sm btn-outline-primary text-nowrap"
                        onClick={() => onPick(pivotCol[etype], it.value)}>
                        Events
                      </button>
                    </td>
                  </tr>
                ))}
                {items.length === 0 && (
                  <tr><td colSpan={7} className="text-secondary text-center py-4">該当なし</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
