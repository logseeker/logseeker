import { useEffect, useState } from "react";
import { api } from "../api";
import { stLabel } from "../labels";
import { adviseForEvent } from "../advice";
import type { Count, EventRow, EventsResponse, FilterState, Screen } from "../types";
import { EventDetail } from "./EventDetail";

function Badge({ r }: { r: string | null }) {
  const v = r ?? "unknown";
  const cls = v === "success" ? "bg-green-lt" : v === "failure" ? "bg-red-lt" : "bg-secondary-lt";
  return <span className={`badge ${cls}`}>{v}</span>;
}
function SevBadge({ s }: { s: string | null }) {
  if (!s) return <span className="text-secondary">-</span>;
  const v = s.toUpperCase();
  const cls = ["EMERG","ALERT","CRITICAL","CRIT"].includes(v) ? "bg-red text-white"
    : ["ERROR","ERR"].includes(v) ? "bg-red-lt"
    : v === "WARNING" || v === "WARN" ? "bg-yellow-lt"
    : v === "NOTICE" ? "bg-azure-lt"
    : "bg-secondary-lt";
  return <span className={`badge ${cls}`}>{s}</span>;
}
const dash = (v: string | null) => (v ? v : <span className="text-secondary">-</span>);

// ページ番号一覧を生成（多い場合は省略記号「…」を挟む）。例: 1 … 4 5 [6] 7 8 … 20
function pageNumbers(current: number, total: number): (number | "...")[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const keep = new Set([1, 2, total - 1, total, current - 1, current, current + 1]);
  const sorted = [...keep].filter((p) => p >= 1 && p <= total).sort((a, b) => a - b);
  const result: (number | "...")[] = [];
  let prev = 0;
  for (const p of sorted) {
    if (prev && p - prev > 1) result.push("...");
    result.push(p);
    prev = p;
  }
  return result;
}

// 横スクロール時も主要列（時刻・ログソース・種別・重大度）を常に見えるようにする sticky 設定。
const STICKY_W = [150, 130, 90, 90]; // px: 時刻, ログソース, 種別, 重大度
const STICKY_LEFT = STICKY_W.reduce<number[]>((acc, _w, i) => [...acc, i === 0 ? 0 : acc[i - 1] + STICKY_W[i - 1]], []);
function stickyStyle(i: number, isHeader = false): React.CSSProperties {
  return {
    position: "sticky",
    left: STICKY_LEFT[i],
    width: STICKY_W[i],
    minWidth: STICKY_W[i],
    maxWidth: STICKY_W[i],
    background: "var(--tblr-card-bg, #fff)",
    zIndex: isHeader ? 3 : 2,
    whiteSpace: "nowrap",
    overflow: "hidden",
    textOverflow: "ellipsis",
    boxShadow: i === STICKY_W.length - 1 ? "2px 0 4px -2px rgba(0,0,0,.15)" : undefined,
  };
}

// イベント1件の「対応策」セル。既定はルール名バッジ1つのみ表示し、
// 「詳細」クリックでアクションバッジ・調査ボタンを展開する（列が横に広がりすぎるのを防ぐ）。
function AdviceCell({ e, onPick }: { e: EventRow; onPick: (k: string, v: string) => void }) {
  const a = adviseForEvent(e);
  const [open, setOpen] = useState(false);
  if (!a) return <span className="text-secondary">-</span>;
  return (
    <div style={{ maxWidth: 240, whiteSpace: "normal" }}>
      <div className="d-flex align-items-center flex-wrap gap-1">
        <span className={`badge ${a.level === "danger" ? "bg-red-lt" : "bg-yellow-lt"}`}>{a.title}</span>
        <button type="button" className="btn btn-xs btn-link p-0"
          onClick={(ev) => { ev.stopPropagation(); setOpen((v) => !v); }}>
          {open ? "隠す" : "詳細"}
        </button>
      </div>
      {open && (
        <div className="mt-1">
          <div className="d-flex flex-wrap gap-1 mb-1">
            {a.actions.map((x) => <span key={x} className="badge bg-azure-lt">{x}</span>)}
          </div>
          {e.source_ip && (
            <button className="btn btn-xs btn-outline-danger py-0"
              onClick={(ev) => { ev.stopPropagation(); onPick("source_ip", e.source_ip!); }}>
              このIPを調査 ({e.source_ip})
            </button>
          )}
        </div>
      )}
    </div>
  );
}

// 脅威プルダウン選択時に出す「対応策」
const THREAT_INFO: Record<string, { label: string; cls: string; rec: string }> = {
  any: { label: "危ない系（攻撃の疑い）", cls: "danger",
    rec: "送信元IPの遮断、公開ポート/不要サービスの停止、WAF・レート制限を検討。" },
  ioc: { label: "IOC一致（既知の不正IP/ドメイン）", cls: "danger",
    rec: "即時に該当IP/ドメインを遮断（FW/WAF）。関連イベントを調査し被害有無を確認。" },
  sensitive_path: { label: "危険パスへのアクセス", cls: "danger",
    rec: "該当IPを遮断。.env/.git 等の公開停止、管理画面を認証保護、CMS/プラグインを最新化。" },
  web_scan: { label: "Webスキャン(4xx多発)", cls: "warning",
    rec: "該当IPをWAF/FWで遮断、レート制限。存在しないパスへの探索をブロック。" },
  auth_fail: { label: "認証失敗（総当たりの疑い）", cls: "warning",
    rec: "アカウントロック/MFA/強パスワード化。該当IPを遮断。SSH/RDP等のポート見直し・公開制限。" },
  root_ssh: { label: "root SSH試行", cls: "danger",
    rec: "【即対応推奨】sshd_config で PermitRootLogin no を設定。PasswordAuthentication no で公開鍵のみに。Fail2ban で自動遮断。不要なら SSH ポートを変更または IP 制限。" },
  ssh_invalid: { label: "SSH不正ユーザー試行", cls: "warning",
    rec: "Fail2ban で自動遮断。AllowUsers で許可ユーザーを限定。公開鍵のみ認証に変更（PasswordAuthentication no）。" },
};

export function Events({
  filter, setSearch, search, onTax, onDate, onAttention, onThreat, onEntity, onNav,
}: {
  filter: FilterState;
  search: string;
  setSearch: (s: string) => void;
  onTax: (k: string, v: string) => void;
  onDate: (which: "start" | "end", d: string) => void;
  onAttention: (b: boolean) => void;
  onThreat: (v: string) => void;
  onEntity: (type: string, value: string) => void;
  onNav: (s: Screen) => void;
}) {
  const [data, setData] = useState<EventsResponse>({ total: 0, limit: 100, offset: 0, items: [] });
  const [srcNames, setSrcNames] = useState<Count[]>([]);
  const [types, setTypes] = useState<{ source_type: string | null; count: number }[]>([]);
  const [statuses, setStatuses] = useState<Count[]>([]);
  const [severities, setSeverities] = useState<Count[]>([]);
  const [sel, setSel] = useState<number | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [pageSize, setPageSize] = useState(30);
  const [offset, setOffset] = useState(0);
  const [showAdvice, setShowAdvice] = useState(false);   // 「対応策」列の表示切替（既定オフ）

  // フィルタ変更で先頭ページに戻す
  useEffect(() => { setOffset(0); }, [filter]);

  useEffect(() => {
    setErr(null);
    api.events(filter, pageSize, offset).then(setData).catch((e) => setErr((e as Error).message));
  }, [filter, pageSize, offset]);

  // 選択肢リストは「その軸自身の絞り込みを除いた」フィルタで取得する。
  // （種別を選ぶと種別リストが1件に潰れて他を選べない、という自己崩壊を防ぐ）
  const without = (key: string): FilterState => ({
    ...filter,
    tax: Object.fromEntries(Object.entries(filter.tax).filter(([k]) => k !== key)),
  });
  useEffect(() => {
    api.groupby(without("source_name"), "source_name", 100).then(setSrcNames).catch(() => {});
    api.sourceTypes(without("source_type")).then(setTypes).catch(() => {});
    api.groupby(without("http_status_code"), "http_status_code", 100).then(setStatuses).catch(() => {});
    api.groupby(without("event_severity"), "event_severity", 100).then(setSeverities).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  const stop = (e: React.MouseEvent) => e.stopPropagation();
  const from = data.total === 0 ? 0 : offset + 1;
  const to = offset + data.items.length;
  const hasPrev = offset > 0;
  const hasNext = to < data.total;
  const totalPages = Math.max(1, Math.ceil(data.total / pageSize));
  const currentPage = Math.floor(offset / pageSize) + 1;
  const goToPage = (p: number) => setOffset((Math.min(Math.max(p, 1), totalPages) - 1) * pageSize);

  return (
    <div className="row row-cards">
      <div className="col-12">
        <div className="card"><div className="card-body">
          <div className="row g-2 align-items-end">
            <div className="col-md">
              <label className="form-label">全文検索（payload全体）</label>
              <input className="form-control" placeholder="Enterで検索" value={search}
                onChange={(e) => setSearch(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") onTax("__q__", search); }} />
            </div>
            <div className="col-md-auto">
              <label className="form-label">ログソース</label>
              <select className="form-select" value={filter.tax.source_name ?? ""} onChange={(e) => onTax("source_name", e.target.value)}>
                <option value="">すべて</option>
                {srcNames.map((s) => <option key={s.value ?? ""} value={s.value ?? ""}>{s.value} ({s.count})</option>)}
              </select>
            </div>
            <div className="col-md-auto">
              <label className="form-label">種別</label>
              <select className="form-select" value={filter.tax.source_type ?? ""} onChange={(e) => onTax("source_type", e.target.value)}>
                <option value="">すべて</option>
                {types.map((t) => <option key={t.source_type ?? ""} value={t.source_type ?? ""}>{stLabel(t.source_type)} ({t.count})</option>)}
              </select>
            </div>
            <div className="col-md-auto">
              <label className="form-label">ステータス</label>
              <select className="form-select" value={filter.tax.http_status_code ?? ""} onChange={(e) => onTax("http_status_code", e.target.value)}>
                <option value="">すべて</option>
                {statuses.map((s) => <option key={s.value ?? ""} value={s.value ?? ""}>{s.value} ({s.count})</option>)}
              </select>
            </div>
            <div className="col-md-auto">
              <label className="form-label">重大度</label>
              <select className="form-select" value={filter.tax.event_severity ?? ""} onChange={(e) => onTax("event_severity", e.target.value)}>
                <option value="">すべて</option>
                {severities.map((s) => <option key={s.value ?? ""} value={s.value ?? ""}>{s.value} ({s.count})</option>)}
              </select>
            </div>
            <div className="col-md-auto">
              <label className="form-label">脅威</label>
              <select className="form-select" value={filter.threat ?? ""} onChange={(e) => onThreat(e.target.value)}>
                <option value="">すべて</option>
                <option value="any">危ない系（総合）</option>
                <option value="ioc">IOC一致</option>
                <option value="sensitive_path">危険パス</option>
                <option value="web_scan">Webスキャン(4xx)</option>
                <option value="auth_fail">認証失敗</option>
                <option value="root_ssh">root SSH試行</option>
              </select>
            </div>
            <div className="col-md-auto">
              <label className="form-label">期間</label>
              <div className="input-group">
                <input type="date" className="form-control" value={filter.start?.slice(0, 10) ?? ""} onChange={(e) => onDate("start", e.target.value)} />
                <input type="date" className="form-control" value={filter.end?.slice(0, 10) ?? ""} onChange={(e) => onDate("end", e.target.value)} />
              </div>
            </div>
            <div className="col-md-auto">
              <label className="form-label d-block">表示</label>
              <div className="btn-group">
                <button className={`btn ${!filter.attention ? "btn-primary" : "btn-outline-primary"}`} onClick={() => onAttention(false)}>全件</button>
                <button className={`btn ${filter.attention ? "btn-primary" : "btn-outline-primary"}`} onClick={() => onAttention(true)}>注目のみ</button>
              </div>
            </div>
          </div>
        </div></div>
      </div>

      {err && <div className="col-12"><div className="alert alert-danger">取得失敗: {err}</div></div>}

      {filter.threat && THREAT_INFO[filter.threat] && (
        <div className="col-12">
          <div className={`alert alert-${THREAT_INFO[filter.threat].cls}`}>
            <div className="d-flex align-items-start">
              <div className="flex-fill">
                <strong>🛡 {THREAT_INFO[filter.threat].label}</strong> のイベントを表示中
                <div className="mt-1"><strong>対策：</strong>{THREAT_INFO[filter.threat].rec}</div>
              </div>
              <button className="btn btn-sm btn-outline-dark ms-2" onClick={() => onThreat("")}>解除</button>
            </div>
          </div>
        </div>
      )}

      <div className="col-12">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">イベント</h3>
            <span className="card-subtitle ms-2 text-secondary">該当 {data.total.toLocaleString()} 件</span>
            <div className="card-actions d-flex gap-2">
              <button className={`btn btn-sm ${showAdvice ? "btn-warning" : "btn-outline-warning"}`}
                onClick={() => setShowAdvice((v) => !v)}>
                🛠 対応策{showAdvice ? "を隠す" : "を表示"}
              </button>
              <div className="btn-group" title="現在の絞り込みで最大2万件までダウンロード">
                <button className="btn btn-sm btn-outline-secondary"
                  onClick={() => api.exportEvents(filter, "csv").catch((e) => setErr((e as Error).message))}>
                  ⬇ CSV
                </button>
                <button className="btn btn-sm btn-outline-secondary"
                  onClick={() => api.exportEvents(filter, "json").catch((e) => setErr((e as Error).message))}>
                  ⬇ JSON
                </button>
              </div>
              <button className="btn btn-sm btn-outline-danger" onClick={() => onNav("rules")}>
                🛡 攻撃・注意喚起を見る
              </button>
            </div>
          </div>
          <div className="table-responsive">
          <table className="table table-vcenter table-sm card-table table-hover">
            <thead><tr>
              <th style={stickyStyle(0, true)}>時刻</th>
              <th style={stickyStyle(1, true)}>ログソース</th>
              <th style={stickyStyle(2, true)}>種別</th>
              <th style={stickyStyle(3, true)}>重大度</th>
              <th>ホスト/デバイス</th><th>ドメイン</th>
              <th>送信元IP</th><th>ユーザー</th><th>イベント/サービス</th><th>対象</th><th>ステータス</th><th>メッセージ</th>
              {showAdvice && <th>対応策</th>}
            </tr></thead>
            <tbody>
              {data.items.map((e) => (
                <tr key={e.id} style={{ cursor: "pointer" }} onClick={() => setSel(e.id)}>
                  <td style={stickyStyle(0)} title={e.event_time ?? undefined}>{e.event_time ? e.event_time.replace("T", " ").slice(0, 19) : <span className="text-secondary">（時刻なし）</span>}</td>
                  <td style={stickyStyle(1)} title={e.source_name ?? undefined}><a role="button" className="text-primary" onClick={(ev) => { stop(ev); e.source_name && onTax("source_name", e.source_name); }}>{dash(e.source_name)}</a></td>
                  <td style={stickyStyle(2)}>{stLabel(e.source_type)}</td>
                  <td style={stickyStyle(3)}><SevBadge s={e.event_severity} /></td>
                  <td className="text-nowrap"><a role="button" className="text-reset" onClick={(ev) => { stop(ev); e.device_name && onTax("device_name", e.device_name); }}>{dash(e.device_name)}</a></td>
                  <td className="text-nowrap"><a role="button" className="text-reset" onClick={(ev) => { stop(ev); e.url_domain && onTax("url_domain", e.url_domain); }}>{dash(e.url_domain)}</a></td>
                  <td className="text-nowrap">
                    <a role="button" className="text-primary" onClick={(ev) => { stop(ev); e.source_ip && onTax("source_ip", e.source_ip); }}>{dash(e.source_ip)}</a>
                    {e.source_country && <span className="badge bg-secondary-lt ms-1">{e.source_country}</span>}
                  </td>
                  <td className="text-nowrap">{dash(e.actor_user)}</td>
                  <td className="text-nowrap">
                    {dash(e.event_action)}
                    {e.service_name && <><br /><small className="text-secondary">{e.service_name}</small></>}
                  </td>
                  <td className="text-truncate" style={{ maxWidth: 220 }}>{e.url_path || <span className="text-secondary">-</span>}</td>
                  <td>{e.http_status_code ? <span className="badge bg-azure-lt">{e.http_status_code}</span> : <Badge r={e.event_result} />}</td>
                  <td className="text-truncate" style={{ maxWidth: 320 }}>{dash(e.message)}</td>
                  {showAdvice && <td className="text-nowrap"><AdviceCell e={e} onPick={(k, v) => onTax(k, v)} /></td>}
                </tr>
              ))}
              {data.items.length === 0 && <tr><td colSpan={showAdvice ? 13 : 12} className="text-secondary text-center py-4">該当なし</td></tr>}
            </tbody>
          </table>
          </div>
          <div className="card-footer d-flex align-items-center flex-wrap gap-2">
            <span className="text-secondary">{from.toLocaleString()}–{to.toLocaleString()} / {data.total.toLocaleString()} 件（{currentPage} / {totalPages} ページ）</span>
            <div className="ms-auto d-flex align-items-center gap-2">
              <span className="text-secondary small">表示件数</span>
              <select className="form-select form-select-sm w-auto" value={pageSize}
                onChange={(e) => { setPageSize(Number(e.target.value)); setOffset(0); }}>
                <option value={30}>30</option><option value={50}>50</option>
                <option value={100}>100</option><option value={200}>200</option>
              </select>
              <ul className="pagination pagination-sm m-0">
                <li className={`page-item ${!hasPrev ? "disabled" : ""}`}>
                  <button type="button" className="page-link" disabled={!hasPrev} onClick={() => goToPage(1)}>«</button>
                </li>
                <li className={`page-item ${!hasPrev ? "disabled" : ""}`}>
                  <button type="button" className="page-link" disabled={!hasPrev} onClick={() => goToPage(currentPage - 1)}>前</button>
                </li>
                {pageNumbers(currentPage, totalPages).map((p, i) =>
                  p === "..." ? (
                    <li key={`ellipsis-${i}`} className="page-item disabled"><span className="page-link">…</span></li>
                  ) : (
                    <li key={p} className={`page-item ${p === currentPage ? "active" : ""}`}>
                      <button type="button" className="page-link" onClick={() => goToPage(p)}>{p}</button>
                    </li>
                  )
                )}
                <li className={`page-item ${!hasNext ? "disabled" : ""}`}>
                  <button type="button" className="page-link" disabled={!hasNext} onClick={() => goToPage(currentPage + 1)}>次</button>
                </li>
                <li className={`page-item ${!hasNext ? "disabled" : ""}`}>
                  <button type="button" className="page-link" disabled={!hasNext} onClick={() => goToPage(totalPages)}>»</button>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {sel != null && <EventDetail id={sel} onClose={() => setSel(null)} onPivot={onTax} onEntity={onEntity} />}
    </div>
  );
}
