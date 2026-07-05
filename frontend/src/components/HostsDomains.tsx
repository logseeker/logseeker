import { useEffect, useState } from "react";
import { api } from "../api";
import type { Count, FilterState } from "../types";

function ListCard({ title, field, rows, onPick }:
  { title: string; field: string; rows: Count[]; onPick: (k: string, v: string) => void }) {
  return (
    <div className="col-lg-6">
      <div className="card">
        <div className="card-header"><h3 className="card-title">{title}</h3></div>
        <div className="table-responsive">
          <table className="table table-vcenter card-table table-hover">
            <thead><tr><th>{field}</th><th className="text-end">件数</th></tr></thead>
            <tbody>
              {rows.length === 0 && <tr><td colSpan={2} className="text-secondary">なし</td></tr>}
              {rows.map((r) => (
                <tr key={r.value ?? "-"} role="button" onClick={() => r.value && onPick(field, r.value)}>
                  <td>{r.value ?? "Unknown"}</td>
                  <td className="text-end">{r.count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export function HostsDomains({ filter, onPick }: { filter: FilterState; onPick: (k: string, v: string) => void }) {
  const [hosts, setHosts] = useState<Count[]>([]);
  const [domains, setDomains] = useState<Count[]>([]);
  useEffect(() => {
    api.groupby(filter, "device_name", 100).then(setHosts).catch(() => {});
    api.groupby(filter, "url_domain", 100).then(setDomains).catch(() => {});
  }, [filter]);
  return (
    <div className="row row-cards">
      <ListCard title="ホスト / デバイス別" field="device_name" rows={hosts} onPick={onPick} />
      <ListCard title="ドメイン別" field="url_domain" rows={domains} onPick={onPick} />
    </div>
  );
}
