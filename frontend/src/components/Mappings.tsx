import { useEffect, useState } from "react";
import { api } from "../api";
import type { MappingsResponse, LogSample } from "../types";

// マッピング画面。取り込みの規則と、送信側の設定サンプルを示す。
// 旧「正規化マッピング」（source_typeごとにTaxonomy外の別名キーを並べた対応表）は廃止した。
// 表示・検索・集計・検知はすべて Taxonomy KEY だけを使う。
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
      {/* ---------------- 取り込みの考え方 ---------------- */}
      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">取り込みの仕組み（受信JSONキー → 画面）</h3>
            <div className="card-actions d-print-none">
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

      {/* ---------------- よく使うTaxonomy KEY ---------------- */}
      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">よく使うキー</h3>
            <span className="card-subtitle ms-2 text-secondary">
              全 {d.taxonomy_total.toLocaleString()} キーのうち代表的なもの
            </span>
          </div>
          <div className="card-body">
            {d.key_groups.map((g) => (
              <div className="mb-4" key={g.title}>
                <div className="d-flex align-items-center gap-2 mb-1">
                  <span className="fw-bold">{g.title}</span>
                  {g.ordered && (
                    <span className="badge bg-orange-lt">左から優先</span>
                  )}
                </div>
                <div className="text-secondary small mb-2">{g.note}</div>
                <div className="d-flex flex-wrap align-items-center gap-1">
                  {g.keys.map((k, i) => (
                    <span key={k.key} className="d-inline-flex align-items-center">
                      {/* 並び順に意味があるグループは、優先順であることが見て分かるよう
                          番号と矢印を出す。ただの候補の羅列と誤解されないようにする。 */}
                      {g.ordered && i > 0 && <span className="text-secondary mx-1">›</span>}
                      <span className="badge bg-blue-lt">
                        {g.ordered && <span className="text-secondary me-1">{i + 1}.</span>}
                        <code>{k.key}</code>
                        {k.label && <span className="ms-1 text-secondary">{k.label}</span>}
                      </span>
                    </span>
                  ))}
                </div>
              </div>
            ))}
            <div className="text-secondary small border-top pt-2">
              日本語名が付いているKEYは全{d.taxonomy_total.toLocaleString()}件のうち一部だけです。
              名前が無いKEYは、画面でもKEY名のまま表示されます。
            </div>
          </div>
        </div>
      </div>

      {/* ---------------- 送信設定サンプル ---------------- */}
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
    </div>
  );
}
