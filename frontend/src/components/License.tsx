import { useEffect, useState } from "react";
import { api } from "../api";
import type { LicenseInfo } from "../types";

export function License() {
  const [info, setInfo] = useState<LicenseInfo | null>(null);
  const [key, setKey] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = () => api.license().then(setInfo).catch((e) => setErr((e as Error).message));
  useEffect(() => { load(); }, []);

  const apply = async () => {
    setMsg(null);
    try {
      const r = await api.applyLicense(key.trim());
      if (r.error) setMsg({ ok: false, text: r.error });
      else { setMsg({ ok: true, text: "ライセンスを適用しました" }); setKey(""); load(); }
    } catch (e) { setMsg({ ok: false, text: (e as Error).message }); }
  };

  if (err) return <div className="alert alert-danger">取得失敗: {err}</div>;
  if (!info) return <div className="text-secondary">読み込み中…</div>;

  return (
    <div className="row row-cards">
      <div className="col-lg-6">
        <div className="card">
          <div className="card-header"><h3 className="card-title">現在のライセンス</h3></div>
          <div className="card-body">
            <div className="mb-2">
              <span className={`badge ${info.source === "applied" ? "bg-green" : "bg-secondary"} me-2`}>
                {info.source === "applied" ? "適用済み" : "既定（未適用）"}
              </span>
              {info.licensee && <span className="text-secondary">{info.licensee}</span>}
            </div>
            <div className="datagrid">
              <div className="datagrid-item"><div className="datagrid-title">有効期限</div>
                <div className="datagrid-content">
                  {info.expires_at ? (
                    <>
                      {info.expires_at.slice(0, 10)}{" "}
                      {info.days_left != null && (
                        <span className={`badge ms-1 ${info.days_left < 30 ? "bg-red" : "bg-green-lt"}`}>
                          {info.days_left >= 30 ? `残り約${Math.floor(info.days_left / 30)}ヶ月（${info.days_left}日）` : `残り${info.days_left}日`}
                        </span>
                      )}
                    </>
                  ) : "無期限"}
                </div></div>
              <div className="datagrid-item"><div className="datagrid-title">データ保持期間</div>
                <div className="datagrid-content">
                  {info.retention_unlimited
                    ? <span className="badge bg-green-lt">無制限</span>
                    : <>{info.retention_days} 日</>}
                  <span className="text-secondary small ms-2">（超過分はDBから自動削除。既定90日）</span>
                </div></div>
            </div>
          </div>
          <div className="card-body border-top">
            <label className="form-label">ライセンスキーを適用（データ保持期間の延長）</label>
            <textarea className="form-control mb-2" rows={3} placeholder="発行されたライセンスキーを貼り付け"
              value={key} onChange={(e) => setKey(e.target.value)} />
            <button className="btn btn-primary" onClick={apply} disabled={!key.trim()}>適用</button>
            {msg && <div className={`alert ${msg.ok ? "alert-success" : "alert-danger"} mt-2 py-2`}>{msg.text}</div>}
          </div>
        </div>
      </div>
    </div>
  );
}
