import { useEffect, useState } from "react";
import { api } from "../api";
import type { DeadLetterRow } from "../types";

// 取り込み失敗（Dead Letter）：不正JSONや正規化に失敗した受信を原文つきで保持。
// 「なぜ入らなかったか」を監査し、パーサ修正や再送の判断に使う。
export function DeadLetters() {
  const [items, setItems] = useState<DeadLetterRow[]>([]);
  const [total, setTotal] = useState(0);
  const [sel, setSel] = useState<DeadLetterRow | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.deadLetters().then((r) => { setItems(r.items); setTotal(r.total); })
      .catch((e) => setErr((e as Error).message));
  }, []);

  const ts = (s: string | null) => (s ? s.replace("T", " ").slice(0, 19) : "-");

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info">
          <strong>取り込み失敗（Dead Letter）</strong>とは、受信したが
          <strong>JSONとして不正</strong>／<strong>正規化に失敗</strong>して通常のイベントに保存できなかったデータです。
          原文と失敗理由を保持しているので、パーサ修正や送信側の設定見直し、再送の判断に使えます。
          <span className="text-secondary">（正常に取り込めていれば、ここは空になります）</span>
        </div>
      </div>

      {err && <div className="col-12"><div className="alert alert-danger">取得失敗: {err}</div></div>}

      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">取り込み失敗一覧</h3>
            <span className="card-subtitle ms-2 text-secondary">{total.toLocaleString()} 件</span>
          </div>
          {items.length === 0 ? (
            <div className="empty">
              <p className="empty-title">失敗はありません 🎉</p>
              <p className="empty-subtitle text-secondary">すべての受信が正常に取り込まれています。</p>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="table table-vcenter card-table table-hover">
                <thead><tr>
                  <th>受信時刻</th><th>経路</th><th>source</th><th>種別</th>
                  <th>送信元IP</th><th>エラー種別</th><th>エラー内容</th><th></th>
                </tr></thead>
                <tbody>
                  {items.map((d) => (
                    <tr key={d.id}>
                      <td className="text-nowrap">{ts(d.received_at)}</td>
                      <td><span className="badge bg-secondary-lt">{d.ingest_channel ?? "-"}</span></td>
                      <td className="text-nowrap">{d.source ?? "-"}</td>
                      <td className="text-nowrap">{d.source_type ?? "-"}</td>
                      <td className="text-nowrap">{d.receiver_ip ?? "-"}</td>
                      <td className="text-nowrap"><span className="badge bg-red-lt">{d.error_type ?? "-"}</span></td>
                      <td className="text-truncate" style={{ maxWidth: 280 }}>{d.error_message ?? "-"}</td>
                      <td><button className="btn btn-sm" onClick={() => setSel(d)}>原文</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {sel && (
        <div className="modal modal-blur show d-block" tabIndex={-1} style={{ background: "rgba(0,0,0,.4)" }}
          onClick={() => setSel(null)}>
          <div className="modal-dialog modal-lg modal-dialog-centered" onClick={(e) => e.stopPropagation()}>
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">受信原文（Dead Letter #{sel.id}）</h5>
                <button className="btn-close" onClick={() => setSel(null)} />
              </div>
              <div className="modal-body">
                <div className="mb-2 text-secondary small">
                  {sel.error_type}: {sel.error_message}
                </div>
                <pre className="bg-dark text-white p-3 rounded" style={{ maxHeight: 400, overflow: "auto" }}>
                  {sel.raw_text || "(原文なし)"}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
