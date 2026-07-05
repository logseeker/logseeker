import { useEffect, useState } from "react";
import { api } from "../api";
import type { MappingGroup } from "../types";

// マッピング：受信JSON（NXLog等）のキー → 正規化フィールドへの対応表。
// 「どのキーが取り込まれ、どの列に出るか」を可視化。CSVダウンロード可・ブラウザ印刷でPDF保存可。
export function Mappings() {
  const [groups, setGroups] = useState<MappingGroup[]>([]);
  const [note, setNote] = useState("");
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.mappings().then((r) => { setGroups(r.groups); setNote(r.note); })
      .catch((e) => setErr((e as Error).message));
  }, []);

  if (err) return <div className="alert alert-danger">取得失敗: {err}</div>;

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">正規化マッピング（JSONキー → 正規化フィールド）</h3>
            <div className="card-actions d-flex gap-2 d-print-none">
              <a className="btn btn-sm btn-outline-primary" href={api.mappingsCsvUrl()}>⬇ CSVダウンロード</a>
              <button className="btn btn-sm btn-outline-secondary" onClick={() => window.print()}>🖨 印刷 / PDF保存</button>
            </div>
          </div>
          <div className="card-body">
            <p className="text-secondary mb-0">{note}</p>
          </div>
        </div>
      </div>

      {groups.map((g) => (
        <div className="col-12 col-xl-6" key={g.source_type}>
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">{g.source_type_label}</h3>
              <span className="card-subtitle ms-2 text-secondary">{g.source_type}</span>
            </div>
            <div className="table-responsive">
              <table className="table table-vcenter table-sm card-table">
                <thead><tr>
                  <th style={{ width: "40%" }}>正規化フィールド</th>
                  <th>候補キー（優先順・受信JSON側）</th>
                </tr></thead>
                <tbody>
                  {g.fields.map((f) => (
                    <tr key={f.field}>
                      <td>
                        <div>{f.field_label}</div>
                        <code className="text-secondary small">{f.field}</code>
                      </td>
                      <td>
                        {f.candidate_keys.map((k, i) => (
                          <span key={k}>
                            <code className={i === 0 ? "text-primary" : "text-secondary"}>{k}</code>
                            {i < f.candidate_keys.length - 1 && <span className="text-secondary"> → </span>}
                          </span>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
