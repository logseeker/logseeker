import { useEffect, useState } from "react";
import { api } from "../api";
import type { MappingsResponse, LogSample } from "../types";

// マッピング画面。
// 1) 取り込みの現行方式（受信キーがTaxonomy KEYと一致したものだけを使う）
// 2) 送信側の設定サンプル（このとおり出せば正規化なしでそのまま画面に出る）
// 3) 正規化マッピング（検知ルール・相関分析が使う normalized_events 向け。イベント画面は使わない）
export function Mappings() {
  const [d, setD] = useState<MappingsResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [sel, setSel] = useState<string>("");
  const [copied, setCopied] = useState<string>("");

  useEffect(() => {
    api.mappings()
      .then((r) => { setD(r); setSel(r.samples[0]?.id ?? ""); })
      .catch((e) => setErr((e as Error).message));
  }, []);

  if (err) return <div className="alert alert-danger">取得失敗: {err}</div>;
  if (!d) return <div className="text-secondary">読み込み中…</div>;

  const sample: LogSample | undefined = d.samples.find((s) => s.id === sel);

  const copy = (s: LogSample) => {
    navigator.clipboard.writeText(s.body)
      .then(() => { setCopied(s.id); setTimeout(() => setCopied(""), 1500); })
      .catch(() => setErr("クリップボードにコピーできませんでした"));
  };

  return (
    <div className="row row-cards">
      {/* ---------------- 1) 取り込みの考え方 ---------------- */}
      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">取り込みの仕組み（受信JSONキー → 画面）</h3>
            <div className="card-actions d-flex gap-2 d-print-none">
              <button className="btn btn-sm btn-outline-primary"
                onClick={() => api.downloadMappingsCsv().catch((e) => setErr((e as Error).message))}>
                ⬇ CSVダウンロード
              </button>
              <button className="btn btn-sm btn-outline-secondary" onClick={() => window.print()}>
                🖨 印刷 / PDF保存
              </button>
            </div>
          </div>
          <div className="card-body">
            <p>{d.ingest_note}</p>
            <div className="alert alert-info mb-0">
              <strong>クラスについて：</strong>{d.class_note}
            </div>
          </div>
        </div>
      </div>

      {/* ---------------- 2) よく使うTaxonomy KEY ---------------- */}
      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">よく使うキー</h3>
            <span className="card-subtitle ms-2 text-secondary">
              全 {d.taxonomy_total.toLocaleString()} キーのうち代表的なもの
            </span>
          </div>
          <div className="card-body">
            <div className="row g-3">
              {d.key_groups.map((g) => (
                <div className="col-12 col-md-6 col-xl-4" key={g.title}>
                  <div className="fw-bold mb-1">{g.title}</div>
                  <div className="d-flex flex-wrap gap-1">
                    {g.keys.map((k) => (
                      <span key={k.key} className="badge bg-blue-lt" title={k.label}>
                        <code>{k.key}</code>
                        {k.label && <span className="ms-1 text-secondary">{k.label}</span>}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ---------------- 3) 送信設定サンプル ---------------- */}
      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">送信側の設定サンプル</h3>
            <span className="card-subtitle ms-2 text-secondary">
              このとおり出せば、受信側での読み替えなしにそのまま画面に出る
            </span>
          </div>
          <div className="card-body border-bottom py-2">
            <div className="btn-group flex-wrap" role="group">
              {d.samples.map((s) => (
                <button key={s.id}
                  className={`btn btn-sm ${sel === s.id ? "btn-primary" : "btn-outline-secondary"}`}
                  onClick={() => setSel(s.id)}>
                  {s.title}
                </button>
              ))}
            </div>
          </div>

          {sample && (
            <div className="card-body">
              <div className="d-flex flex-wrap align-items-center gap-2 mb-2">
                <span className="text-secondary">対象：</span><span>{sample.target}</span>
                <span className="text-secondary ms-3">設定ファイル：</span>
                <code>{sample.file}</code>
                <button className="btn btn-sm btn-outline-primary ms-auto d-print-none"
                  onClick={() => copy(sample)}>
                  {copied === sample.id ? "✓ コピーしました" : "⧉ コピー"}
                </button>
              </div>

              <div className="mb-2 d-flex flex-wrap gap-1">
                {sample.keys.map((k) => (
                  <span key={k} className="badge bg-green-lt"><code>{k}</code></span>
                ))}
              </div>

              {sample.note && (
                <div className="alert alert-warning py-2">
                  <strong>注意：</strong>{sample.note}
                </div>
              )}

              <pre className="mb-0 p-3 bg-dark text-white rounded"
                style={{ overflowX: "auto", fontSize: "0.8125rem", lineHeight: 1.5 }}>
                <code>{sample.body}</code>
              </pre>
              <div className="text-secondary small mt-2">
                ホスト名・IPはサンプル用の値です。自分の環境の送信先に置き換えてください。
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ---------------- 4) 正規化マッピング（他機能用） ---------------- */}
      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">正規化マッピング（検知ルール・相関分析用）</h3>
          </div>
          <div className="card-body py-2">
            <p className="text-secondary mb-1">{d.normalize_note}</p>
            <p className="text-secondary mb-0 small">{d.note}</p>
          </div>
        </div>
      </div>

      {d.groups.map((g) => (
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
