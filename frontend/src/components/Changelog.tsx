import { useEffect, useState } from "react";
import DOMPurify from "dompurify";
import { marked } from "marked";
import { api } from "../api";
import type { ReleaseItem } from "../types";

// お知らせ・更新履歴の一覧（常にアクセス可能。ダッシュボードの非表示設定の影響は受けない）。
// GitHub Releasesの本文(Markdown)をHTMLに変換して表示する。取得元はGitHub側のリリースノートなので
// 基本的には信頼できるが、リモートコンテンツである以上サニタイズ(DOMPurify)してから描画する。
function renderBody(md: string): { __html: string } {
  const html = marked.parse(md || "", { breaks: true }) as string;
  return { __html: DOMPurify.sanitize(html) };
}

export function Changelog() {
  const [releases, setReleases] = useState<ReleaseItem[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.changelog().then(setReleases).catch((e) => setErr((e as Error).message));
  }, []);

  const ts = (s: string | null) => (s ? s.slice(0, 10) : "-");

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="alert alert-info mb-0">
          <strong>お知らせ・更新履歴</strong>：GitHubのリリースノートをそのまま表示しています。
        </div>
      </div>

      {err && <div className="col-12"><div className="alert alert-danger">取得失敗: {err}</div></div>}
      {!releases && !err && <div className="col-12 text-secondary">読み込み中…</div>}
      {releases && releases.length === 0 && (
        <div className="col-12"><div className="card"><div className="empty">
          <p className="empty-title">お知らせはまだありません</p>
        </div></div></div>
      )}

      {releases?.map((r) => (
        <div className="col-12" key={r.tag_name}>
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">
                {r.name}
                {r.prerelease && <span className="badge bg-orange-lt ms-2">プレリリース</span>}
              </h3>
              <span className="card-subtitle ms-2 text-secondary">{ts(r.published_at)}</span>
              <div className="card-actions">
                <a className="btn btn-sm btn-outline-secondary" href={r.html_url} target="_blank" rel="noreferrer">
                  GitHubで見る ↗
                </a>
              </div>
            </div>
            <div className="card-body">
              <div className="markdown-body" dangerouslySetInnerHTML={renderBody(r.body)} />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
