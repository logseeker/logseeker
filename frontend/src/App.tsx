import { useEffect, useState } from "react";
import {
  IconAffiliate, IconAlertTriangle, IconArrowsExchange, IconBell, IconClipboardList, IconColumns,
  IconFileText, IconCloudDownload, IconInbox, IconLayoutDashboard, IconLicense, IconList, IconLogout,
  IconServer, IconSettings, IconShield, IconSitemap, IconSpeakerphone, IconUsers, IconWorld,
} from "@tabler/icons-react";
import { useChangelog } from "./changelog";
import { Changelog } from "./components/Changelog";
import { Dashboard } from "./components/Dashboard";
import { Events } from "./components/Events";
import { Sources } from "./components/Sources";
import { HostsDomains } from "./components/HostsDomains";
import { Fields } from "./components/Fields";
import { Entities } from "./components/Entities";
import { Ingest } from "./components/Ingest";
import { Incidents } from "./components/Incidents";
import { Rules } from "./components/Rules";
import { ThreatIntel } from "./components/ThreatIntel";
import { License } from "./components/License";
import { Notifications } from "./components/Notifications";
import { Correlations } from "./components/Correlations";
import { DeadLetters } from "./components/DeadLetters";
import { Mappings } from "./components/Mappings";
import { Admin } from "./components/Admin";
import { Users } from "./components/Users";
import { Audit } from "./components/Audit";
import { Login } from "./components/Login";
import { Placeholder } from "./components/Placeholder";
import { api, setUnauthorizedHandler, tokenStore } from "./api";
import type { AuthStatus, FilterState, Role, Screen } from "./types";
import "./styles.css";

const ROLE_RANK: Record<Role, number> = { viewer: 1, editor: 2, sysadmin: 3, admin: 4 };
// 画面ごとの最低ロール（未指定＝ログインすれば誰でも）。認証OFF時は全開放。
const MIN_ROLE: Partial<Record<Screen, Role>> = {
  notifications: "sysadmin", license: "sysadmin", threatintel: "sysadmin",
  users: "sysadmin", audit: "sysadmin",
};

const EMPTY: FilterState = { tax: {} };

// 絞り込み(filter)を実際に使う画面だけ。ここ以外（ダッシュボード/マッピング/管理/
// ライセンス等）へは絞り込みを持ち込まない＝URLにも載せず、チップも出さない。
const FILTER_SCREENS = new Set<Screen>(["events", "sources", "hosts", "fields", "rules"]);

// 画面＋絞り込みを URL に出し入れ（ブラウザの戻る/進むを効かせる）
// 絞り込みを使わない画面では filter を URL に載せない（無関係な画面に値を持ち回らない）。
function serializeUrl(screen: Screen, f: FilterState): string {
  const p = new URLSearchParams();
  p.set("screen", screen);
  if (FILTER_SCREENS.has(screen)) {
    if (f.q) p.set("q", f.q);
    if (f.start) p.set("start", f.start);
    if (f.end) p.set("end", f.end);
    if (f.attention) p.set("attention", "1");
    if (f.threat) p.set("threat", f.threat);
    Object.entries(f.tax).forEach(([k, v]) => p.set(`t.${k}`, v));
  }
  return p.toString();
}
function parseUrl(search: string): { screen: Screen; filter: FilterState } {
  const p = new URLSearchParams(search);
  const tax: Record<string, string> = {};
  p.forEach((v, k) => { if (k.startsWith("t.")) tax[k.slice(2)] = v; });
  return {
    screen: (p.get("screen") as Screen) || "dashboard",
    filter: {
      q: p.get("q") || undefined,
      start: p.get("start") || undefined,
      end: p.get("end") || undefined,
      attention: p.get("attention") === "1" || undefined,
      threat: p.get("threat") || undefined,
      tax,
    },
  };
}

const MENU: { key: Screen; label: string; Icon: typeof IconList; ready: boolean }[] = [
  { key: "dashboard", label: "ダッシュボード", Icon: IconLayoutDashboard, ready: true },
  { key: "changelog", label: "お知らせ", Icon: IconSpeakerphone, ready: true },
  { key: "events", label: "イベント", Icon: IconList, ready: true },
  { key: "sources", label: "ログソース", Icon: IconServer, ready: true },
  { key: "hosts", label: "ホスト / ドメイン", Icon: IconWorld, ready: true },
  { key: "fields", label: "フィールド", Icon: IconColumns, ready: true },
  { key: "entities", label: "エンティティ", Icon: IconAffiliate, ready: true },
  { key: "correlations", label: "相関分析", Icon: IconSitemap, ready: true },
  { key: "mappings", label: "マッピング", Icon: IconArrowsExchange, ready: true },
  { key: "ingest", label: "取り込み", Icon: IconInbox, ready: true },
  { key: "deadletters", label: "取り込み失敗", Icon: IconAlertTriangle, ready: true },
  { key: "incidents", label: "インシデント", Icon: IconFileText, ready: true },
  { key: "rules", label: "ルール / 注意喚起", Icon: IconShield, ready: true },
  { key: "threatintel", label: "脅威インテリ", Icon: IconCloudDownload, ready: true },
  { key: "notifications", label: "通知設定", Icon: IconBell, ready: true },
  { key: "license", label: "ライセンス", Icon: IconLicense, ready: true },
  { key: "users", label: "ユーザー管理", Icon: IconUsers, ready: true },
  { key: "audit", label: "監査ログ", Icon: IconClipboardList, ready: true },
  { key: "admin", label: "システム状態", Icon: IconSettings, ready: true },
];

const INIT = parseUrl(window.location.search);

export default function App() {
  const [screen, setScreen] = useState<Screen>(INIT.screen);
  const [filter, setFilter] = useState<FilterState>(INIT.filter);
  const [search, setSearch] = useState(INIT.filter.q ?? "");
  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const [authLoaded, setAuthLoaded] = useState(false);
  const changelog = useChangelog(auth);

  const loadAuth = () => api.authStatus().then(setAuth).catch(() => setAuth(null)).finally(() => setAuthLoaded(true));
  useEffect(() => {
    setUnauthorizedHandler(() => { tokenStore.clear(); loadAuth(); });
    loadAuth();
  }, []);

  // 認証ONで未ログインなら、どの画面でも使えない機能があるため最小権限で扱う。
  const effRole: Role = (!auth || !auth.auth_required) ? "admin" : (auth.user?.role ?? "viewer");
  const canSee = (s: Screen): boolean => {
    const need = MIN_ROLE[s];
    if (!need) return true;
    if (!auth?.auth_required) return true;      // OFF＝全開放（デモ）
    return ROLE_RANK[effRole] >= ROLE_RANK[need];
  };
  const logout = async () => { try { await api.logout(); } catch { /* noop */ } tokenStore.clear(); setScreen("dashboard"); loadAuth(); };

  // 権限のない画面（URL直打ち等）はダッシュボードへ退避
  useEffect(() => {
    if (authLoaded && !canSee(screen)) setScreen("dashboard");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [screen, auth, authLoaded]);

  // 状態 → URL（履歴に積む）。同じURLなら積まない＝戻る操作のループ防止。
  useEffect(() => {
    const qsStr = serializeUrl(screen, filter);
    if (qsStr !== window.location.search.replace(/^\?/, "")) {
      window.history.pushState(null, "", `?${qsStr}`);
    }
  }, [screen, filter]);

  // 戻る/進む → URL から状態を復元
  useEffect(() => {
    const onPop = () => {
      const parsed = parseUrl(window.location.search);
      setScreen(parsed.screen);
      setFilter(parsed.filter);
      setSearch(parsed.filter.q ?? "");
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const onTax = (k: string, v: string) => {
    if (k === "__q__") { setFilter((p) => ({ ...p, q: v || undefined })); return; }
    setFilter((p) => {
      const tax = { ...p.tax };
      if (!v || tax[k] === v) delete tax[k];
      else tax[k] = v;
      return { ...p, tax };
    });
  };
  const onDate = (which: "start" | "end", d: string) =>
    setFilter((p) => ({ ...p, [which]: d ? `${d}T${which === "start" ? "00:00:00" : "23:59:59"}+09:00` : undefined }));
  const onAttention = (b: boolean) => setFilter((p) => ({ ...p, attention: b }));
  const onThreat = (v: string) => setFilter((p) => ({ ...p, threat: v || undefined }));
  // ダッシュボード/ルール/エンティティ等から Events へ。現在の絞り込み文脈（logw等）は維持して追加。
  // ルール等は同じ絞り込みに追従して算出されるので、追加しても0件にならない。
  const drill = (k: string, v: string) => { onTax(k, v); setScreen("events"); };
  // イベント等から「エンティティ調査」画面へ（IP/ユーザーの攻撃像を時系列で見る）
  const [entityInit, setEntityInit] = useState<{ type: string; value: string; nonce: number } | undefined>();
  const navEntity = (type: string, value: string) => {
    setEntityInit({ type, value, nonce: Date.now() });
    setScreen("entities");
  };

  const cur = MENU.find((m) => m.key === screen)!;
  const onFilterScreen = FILTER_SCREENS.has(screen);

  // 絞り込みチップ（絞り込みを使う画面でのみ表示・解除できる）
  const chips: { label: string; clear: () => void }[] = [];
  Object.entries(filter.tax).forEach(([k, v]) => chips.push({ label: `${k} = ${v}`, clear: () => onTax(k, v) }));
  if (filter.q) chips.push({ label: `検索 "${filter.q}"`, clear: () => { setSearch(""); setFilter((p) => ({ ...p, q: undefined })); } });
  if (filter.start || filter.end)
    chips.push({ label: `期間 ${filter.start?.slice(0, 10) ?? "…"}〜${filter.end?.slice(0, 10) ?? "…"}`, clear: () => setFilter((p) => ({ ...p, start: undefined, end: undefined })) });
  if (filter.threat) chips.push({ label: `脅威: ${filter.threat}`, clear: () => onThreat("") });
  const clearAll = () => { setFilter(EMPTY); setSearch(""); };

  const body = () => {
    switch (screen) {
      case "dashboard": return <Dashboard onPick={drill} changelog={changelog} onNavChangelog={() => setScreen("changelog")} />;
      case "changelog": return <Changelog />;
      case "events": return <Events filter={filter} search={search} setSearch={setSearch}
        onTax={onTax} onDate={onDate} onAttention={onAttention} onThreat={onThreat} onEntity={navEntity} onNav={setScreen} />;
      case "sources": return <Sources filter={filter} onPick={drill} />;
      case "hosts": return <HostsDomains filter={filter} onPick={drill} />;
      case "fields": return <Fields filter={filter} />;
      case "entities": return <Entities onPick={drill} initial={entityInit} />;
      case "ingest": return <Ingest />;
      case "incidents": return <Incidents />;
      case "rules": return <Rules filter={filter} onPick={drill} auth={auth ?? undefined} />;
      case "threatintel": return <ThreatIntel />;
      case "notifications": return <Notifications />;
      case "correlations": return <Correlations onPick={drill} onEntity={navEntity} />;
      case "mappings": return <Mappings />;
      case "deadletters": return <DeadLetters />;
      case "admin": return auth ? <Admin onNav={setScreen} auth={auth} onAuthChanged={loadAuth} /> : null;
      case "users": return auth ? <Users auth={auth} onChanged={loadAuth} /> : null;
      case "audit": return <Audit />;
      case "license": return <License />;
      default: return <Placeholder title={cur.label} />;
    }
  };

  // 認証ロード中
  if (!authLoaded) return <div className="page page-center"><div className="text-secondary">読み込み中…</div></div>;
  // ログイン必須なのに未ログイン → ログイン画面
  if (auth?.auth_required && !auth.user) {
    return <Login sso={auth.sso} onLoggedIn={() => { loadAuth(); setScreen("dashboard"); }} />;
  }
  const visibleMenu = MENU.filter((m) => canSee(m.key));

  return (
    <div className="page">
      <aside className="navbar navbar-vertical navbar-expand-lg" data-bs-theme="dark">
        <div className="container-fluid">
          <h1 className="navbar-brand mb-1">LogSeeker</h1>
          <div className="text-secondary small mb-2">ログシーカー</div>
          <div className="navbar-nav flex-column flex-fill w-100">
            <ul className="navbar-nav">
              {visibleMenu.map((m) => (
                <li className={`nav-item ${screen === m.key ? "active" : ""}`} key={m.key}>
                  <a className="nav-link" role="button" onClick={() => setScreen(m.key)}>
                    <span className="nav-link-icon"><m.Icon size={18} /></span>
                    <span className="nav-link-title">{m.label}</span>
                    {m.key === "changelog" && changelog.unread && (
                      <span className="badge bg-red ms-auto" style={{ width: 8, height: 8, padding: 0, borderRadius: "50%" }}></span>
                    )}
                    {!m.ready && <span className="badge bg-secondary-lt ms-auto">未実装</span>}
                  </a>
                </li>
              ))}
            </ul>
            {chips.length > 0 && onFilterScreen && (
              <button className="btn btn-sm btn-outline-warning mt-3" onClick={clearAll}>
                フィルタ全クリア ({chips.length})
              </button>
            )}
          </div>
        </div>
      </aside>

      <div className="page-wrapper">
        <div className="page-header d-print-none">
          <div className="container-fluid d-flex align-items-center">
            <h2 className="page-title mb-0">{cur.label}</h2>
            <div className="ms-auto d-flex align-items-center gap-2">
              {auth?.user ? (
                <>
                  <span className="text-secondary small">
                    {auth.user.display_name || auth.user.username}
                    <span className="badge bg-blue-lt ms-1">{auth.user.role_label}</span>
                  </span>
                  <button className="btn btn-sm btn-outline-secondary" onClick={logout}>
                    <IconLogout size={16} className="me-1" />ログアウト
                  </button>
                </>
              ) : (
                <span className="badge bg-yellow-lt">ログインなし（認証OFF）</span>
              )}
            </div>
          </div>
        </div>
        <div className="page-body">
          <div className="container-fluid">
            {chips.length > 0 && onFilterScreen && (
              <div className="card mb-3">
                <div className="card-body py-2 d-flex flex-wrap gap-2 align-items-center">
                  <span className="text-secondary small">絞り込み中:</span>
                  {chips.map((c, i) => (
                    <span key={i} className="badge bg-blue" role="button" onClick={c.clear}>{c.label} ✕</span>
                  ))}
                  <button className="btn btn-sm btn-ghost-secondary ms-auto" onClick={clearAll}>全クリア</button>
                </div>
              </div>
            )}
            {body()}
          </div>
        </div>
      </div>
    </div>
  );
}
