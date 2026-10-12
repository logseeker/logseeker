import { useEffect, useMemo, useState } from "react";
import ReactECharts from "echarts-for-react";
import {
  IconAlertOctagon, IconBuildingCommunity, IconDeviceDesktop, IconServer, IconShieldCheck, IconShieldExclamation,
} from "@tabler/icons-react";
import { api } from "../api";
import { fmtTime, stLabel } from "../labels";
import type { CorrelationGraph as Graph, GraphAttacker, GraphEdge, GraphStatus, CorrelationTimeline } from "../types";

// 相関分析の関係図。左＝攻撃元（PC）、右＝自分のサーバー。線の色と盾マークで
// 「攻撃されている／遮断した」をひと目でわかるようにする。データは /api/correlations/graph。
// 攻撃＝失敗イベントのあるアクセスのみ（成功だけのアクセスは正規利用と区別できないので描かない）。

export const STATUS: Record<GraphStatus, { label: string; short: string; color: string }> = {
  breach: { label: "失敗のあとにログイン成功（侵入の可能性）", short: "侵入の可能性", color: "#ae3ec9" },
  active: { label: "遮断されず攻撃が続いている", short: "攻撃継続中", color: "#d63939" },
  leak: { label: "遮断したが、その後も失敗が記録されている", short: "遮断後も継続", color: "#f76707" },
  stopped: { label: "遮断していないが、現在は止まっている", short: "停止（未遮断）", color: "#f59f00" },
  blocked: { label: "遮断済み。遮断後の攻撃は記録されていない", short: "遮断済み", color: "#2fb344" },
};

const W = 1000;
const ROW = 58;
const PAD = 34;
const AX = 24;          // 攻撃元アイコンのx
const EDGE_X1 = 300;    // 線の始点（攻撃元の右端）
const EDGE_X2 = 772;    // 線の終点（サーバーアイコンの左端）
const SX = 780;         // サーバーアイコンのx

const hm = (iso: string | null) => (iso ? fmtTime(iso).slice(5, 16) : "-");

function bez(x1: number, y1: number, x2: number, y2: number, t: number) {
  const cx = (x1 + x2) / 2;
  const u = 1 - t;
  return {
    x: u * u * u * x1 + 3 * u * u * t * cx + 3 * u * t * t * cx + t * t * t * x2,
    y: u * u * u * y1 + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t * t * t * y2,
  };
}

const strokeW = (n: number) => 1.5 + Math.min(5, Math.log10(n + 1) * 2);

export function CorrelationGraph({ days, onPick, onEntity }: {
  days: number;
  onPick: (k: string, v: string) => void;
  onEntity: (type: string, value: string) => void;
}) {
  const graphDays = days === 0 || days > 30 ? 30 : days;
  const [data, setData] = useState<Graph | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  const [hover, setHover] = useState<string | null>(null);

  useEffect(() => {
    setErr(null);
    setData(null);
    api.correlationGraph(graphDays, 20).then((d) => {
      setData(d);
      setSel(d.attackers[0]?.ip ?? null);
    }).catch((e) => setErr((e as Error).message));
  }, [graphDays]);

  const layout = useMemo(() => {
    if (!data) return null;
    const n = data.attackers.length;
    const m = data.servers.length;
    const h = Math.max(n * ROW, m * 110, 160) + PAD * 2;
    const ay = new Map(data.attackers.map((a, i) => [a.ip, PAD + ROW / 2 + i * ROW]));
    const span = h - PAD * 2;
    const sy = new Map(data.servers.map((s, i) => [s.name, PAD + (span * (i + 0.5)) / m]));
    return { h, ay, sy };
  }, [data]);

  if (err) return <div className="alert alert-danger">関係図の取得に失敗しました: {err}</div>;
  if (!data || !layout) return <div className="card"><div className="card-body text-secondary">集計中…</div></div>;

  const s = data.summary;
  const focus = hover;   // マウスを乗せた攻撃元の線だけを強調（選択中でも他の線は薄くしない）
  const selA = data.attackers.find((a) => a.ip === sel) ?? null;

  return (
    <>
      {s.breach > 0 && (
        <div className="col-12">
          <div className="alert alert-danger d-flex align-items-start gap-3 mb-0" style={{ borderLeftColor: STATUS.breach.color }}>
            <IconAlertOctagon size={28} style={{ color: STATUS.breach.color }} className="flex-shrink-0" />
            <div>
              <div className="fw-bold">失敗のあとにログインに成功した送信元が {s.breach} 件あります（侵入の可能性）</div>
              <div className="small">
                {data.edges.filter((e) => e.status === "breach").map((e) => (
                  <a key={`${e.ip}|${e.server}`} role="button" className="me-3" onClick={() => setSel(e.ip)}>
                    {e.ip} → {e.server}（失敗 {e.breach!.fail_count}件のあと {hm(e.breach!.last_success)} に
                    {e.breach!.success_users.join("、") || "不明なユーザー"} で成功）
                  </a>
                ))}
              </div>
              <div className="small text-secondary">
                自分・社内からの打ち間違いでなければ、成功したユーザーの操作履歴を直ちに確認してください。
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="col-12">
        <div className="row row-cards">
          <SummaryCard title="攻撃元（失敗のあったIP）" value={s.attackers} color="secondary"
            note={s.truncated ? "件数が多いため一部のみ集計" : undefined} />
          <SummaryCard title="遮断済み" value={s.blocked} color="green" icon={<IconShieldCheck size={22} />} />
          <SummaryCard title="遮断されず攻撃が続いている" value={s.active} color="red"
            icon={<IconShieldExclamation size={22} />} note={s.stopped ? `ほかに停止中（未遮断） ${s.stopped}` : undefined} />
          <SummaryCard title="複数のサーバーを攻撃" value={s.multi_server} color="orange" />
        </div>
      </div>

      <div className="col-lg-8">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">攻撃の関係図</h3>
            <span className="card-subtitle ms-2 text-secondary small">
              {days === 0 || days > 30 ? "過去30日" : days === 1 ? "過去24時間" : `過去${days}日`}・
              上位{data.attackers.length}件{s.attackers > data.attackers.length ? `（全${s.attackers}件）` : ""}・
              アイコンをクリックで詳細
            </span>
          </div>
          <div className="card-body p-2" style={{ overflowX: "auto" }}>
            {data.attackers.length === 0 ? (
              <div className="text-center text-secondary py-5">
                <IconShieldCheck size={40} className="text-green mb-2" /><br />
                この期間に失敗のあったアクセス（攻撃の疑い）はありません
              </div>
            ) : (
              <svg viewBox={`0 0 ${W} ${layout.h}`} style={{ width: "100%", minWidth: 640, display: "block" }}
                role="img" aria-label="攻撃元とサーバーの関係図">
                <style>{`
                  @keyframes ls-flow { to { stroke-dashoffset: -32; } }
                  .ls-flow { stroke-dasharray: 10 6; animation: ls-flow 1.2s linear infinite; }
                  .ls-node { cursor: pointer; }
                `}</style>
                <text x={AX} y={18} fontSize={13} fill="#667382" fontWeight={600}>攻撃元</text>
                <text x={SX} y={18} fontSize={13} fill="#667382" fontWeight={600}>自分のサーバー</text>

                {data.edges.map((e) => (
                  <EdgeLine key={`${e.ip}|${e.server}`} e={e}
                    y1={layout.ay.get(e.ip)!} y2={layout.sy.get(e.server)!}
                    dim={focus !== null && focus !== e.ip} />
                ))}

                {data.attackers.map((a) => (
                  <AttackerNode key={a.ip} a={a} y={layout.ay.get(a.ip)!} selected={sel === a.ip}
                    onClick={() => setSel(a.ip)} onHover={(on) => setHover(on ? a.ip : null)} />
                ))}

                {data.servers.map((sv) => {
                  const y = layout.sy.get(sv.name)!;
                  return (
                    <g key={sv.name}>
                      <rect x={SX - 8} y={y - 34} width={212} height={68} rx={8} fill="#f6f8fb" stroke="#dce1e7" />
                      <IconServer x={SX} y={y - 20} width={40} height={40} color="#206bc4" stroke={1.6} />
                      <text x={SX + 48} y={y - 6} fontSize={15} fontWeight={700} fill="#182433">{sv.name}</text>
                      <text x={SX + 48} y={y + 14} fontSize={11.5} fill="#667382">
                        攻撃元 {sv.attacker_count}・遮断 {sv.blocked_count}
                      </text>
                    </g>
                  );
                })}
              </svg>
            )}
          </div>
          <div className="card-footer d-flex flex-wrap gap-3 small text-secondary">
            <Legend color={STATUS.breach.color} flow label="失敗後にログイン成功（侵入の可能性）" />
            <Legend color={STATUS.active.color} flow label="攻撃継続中（未遮断）" />
            <Legend color={STATUS.leak.color} flow label="遮断後も継続" />
            <Legend color={STATUS.stopped.color} label="停止（未遮断）" />
            <Legend color={STATUS.active.color} shield label="遮断済み（盾で止まる）" />
            <span>線の太さ＝失敗件数</span>
          </div>
        </div>
      </div>

      <div className="col-lg-4">
        {selA
          ? <AttackerDetail a={selA} edges={data.edges.filter((e) => e.ip === selA.ip)} days={graphDays}
              onPick={onPick} onEntity={onEntity} />
          : <div className="card"><div className="card-body text-secondary">攻撃元を選ぶと詳細を表示します</div></div>}
      </div>
    </>
  );
}

function SummaryCard({ title, value, color, icon, note }: {
  title: string; value: number; color: string; icon?: React.ReactNode; note?: string;
}) {
  return (
    <div className="col-sm-6 col-lg-3">
      <div className="card card-sm">
        <div className="card-body d-flex align-items-center gap-3">
          <span className={`avatar bg-${color}-lt text-${color}`}>{icon ?? <IconDeviceDesktop size={22} />}</span>
          <div>
            <div className="text-secondary small">{title}</div>
            <div className={`h2 mb-0 ${value > 0 && color !== "secondary" ? `text-${color}` : ""}`}>{value.toLocaleString()}</div>
            {note && <div className="text-secondary small">{note}</div>}
          </div>
        </div>
      </div>
    </div>
  );
}

function Legend({ color, label, flow, dashed, shield }: {
  color: string; label: string; flow?: boolean; dashed?: boolean; shield?: boolean;
}) {
  return (
    <span className="d-inline-flex align-items-center gap-1">
      <svg width={38} height={14}>
        <line x1={2} y1={7} x2={shield ? 22 : 36} y2={7} stroke={color} strokeWidth={3}
          strokeOpacity={shield ? 0.55 : 1}
          strokeDasharray={dashed ? "5 4" : flow ? "10 6" : undefined} className={flow ? "ls-flow" : undefined} />
        {shield && <IconShieldCheck x={22} y={-1} width={16} height={16} color={STATUS.blocked.color} />}
      </svg>
      {label}
    </span>
  );
}

function EdgeLine({ e, y1, y2, dim }: { e: GraphEdge; y1: number; y2: number; dim: boolean }) {
  const cx = (EDGE_X1 + EDGE_X2) / 2;
  const d = `M${EDGE_X1},${y1} C${cx},${y1} ${cx},${y2} ${EDGE_X2},${y2}`;
  const w = strokeW(e.failure_count);
  const opacity = dim ? 0.15 : 1;
  const blocked = e.status === "blocked" || e.status === "leak";
  // 盾は攻撃元寄りに置く（サーバー側に置くと同じサーバーへの線の盾が1点に重なるため）
  const SHIELD_T = 0.3;
  const sp = bez(EDGE_X1, y1, EDGE_X2, y2, SHIELD_T);
  const tip = `${e.ip} → ${e.server}\n${STATUS[e.status].label}\n失敗 ${e.failure_count}件` +
    (e.banned_since ? `\n遮断: ${hm(e.banned_since)}（${e.jails.join(", ")}）` : "") +
    (e.breach ? `\nログイン成功: ${hm(e.breach.last_success)}（${e.breach.success_users.join(", ") || "ユーザー不明"}）` : "");
  return (
    <g opacity={opacity}>
      <title>{tip}</title>
      {e.status === "blocked" ? (
        <>
          <path d={d} fill="none" stroke="#ced4da" strokeWidth={1.5} strokeDasharray="5 5" />
          <path d={d} fill="none" stroke={STATUS.active.color} strokeOpacity={0.55} strokeWidth={w}
            pathLength={100} strokeDasharray={`${SHIELD_T * 100} 100`} />
        </>
      ) : (
        <path d={d} fill="none" stroke={STATUS[e.status].color} strokeWidth={w}
          className={e.status === "stopped" ? undefined : "ls-flow"} />
      )}
      {e.status === "breach" && (
        <g>
          <circle cx={EDGE_X2 - 16} cy={y2} r={13} fill="#fff" stroke={STATUS.breach.color} strokeWidth={2} />
          <IconAlertOctagon x={EDGE_X2 - 26} y={y2 - 10} width={20} height={20} color={STATUS.breach.color} />
        </g>
      )}
      {blocked && (
        <g>
          <circle cx={sp.x} cy={sp.y} r={15} fill="#fff" stroke={STATUS[e.status].color} strokeWidth={2} />
          {e.status === "blocked"
            ? <IconShieldCheck x={sp.x - 11} y={sp.y - 11} width={22} height={22} color={STATUS.blocked.color} />
            : <IconShieldExclamation x={sp.x - 11} y={sp.y - 11} width={22} height={22} color={STATUS.leak.color} />}
        </g>
      )}
    </g>
  );
}

function AttackerNode({ a, y, selected, onClick, onHover }: {
  a: GraphAttacker; y: number; selected: boolean; onClick: () => void; onHover: (on: boolean) => void;
}) {
  const c = STATUS[a.status].color;
  const Icon = a.status === "breach" ? IconAlertOctagon : a.is_private ? IconBuildingCommunity : IconDeviceDesktop;
  return (
    <g className="ls-node" onClick={onClick} onMouseEnter={() => onHover(true)} onMouseLeave={() => onHover(false)}>
      <rect x={AX - 8} y={y - 25} width={EDGE_X1 - AX + 4} height={50} rx={8}
        fill={selected ? "#eef3fb" : "#fff"} stroke={selected ? "#206bc4" : "#e6e9ee"} />
      <rect x={AX - 8} y={y - 25} width={4} height={50} rx={2} fill={c} />
      <Icon x={AX} y={y - 16} width={32} height={32} color={a.status === "blocked" ? "#868e96" : c} stroke={1.6} />
      {a.status === "blocked" && <IconShieldCheck x={AX + 18} y={y + 2} width={18} height={18} color={STATUS.blocked.color} fill="#fff" />}
      <text x={AX + 42} y={y - 4} fontSize={14} fontWeight={700} fill="#182433">
        {a.ip}
        {a.country && <tspan fontSize={11} fontWeight={400} fill="#667382"> {a.country}</tspan>}
        {a.is_private && <tspan fontSize={11} fontWeight={400} fill="#667382"> 社内</tspan>}
        {a.is_ioc && <tspan fontSize={11} fontWeight={700} fill="#d63939"> IOC</tspan>}
      </text>
      <text x={AX + 42} y={y + 14} fontSize={11.5} fill={c}>
        {STATUS[a.status].short}
        <tspan fill="#667382">・失敗 {a.failure_count.toLocaleString()}件</tspan>
      </text>
    </g>
  );
}

function AttackerDetail({ a, edges, days, onPick, onEntity }: {
  a: GraphAttacker; edges: GraphEdge[]; days: number;
  onPick: (k: string, v: string) => void; onEntity: (type: string, value: string) => void;
}) {
  const [tl, setTl] = useState<CorrelationTimeline | null>(null);
  useEffect(() => {
    setTl(null);
    api.correlationTimeline(a.ip, days).then(setTl).catch(() => setTl(null));
  }, [a.ip, days]);

  const option = useMemo(() => {
    if (!tl) return null;
    const servers = [...new Set(tl.series.map((r) => r.server))];
    const palette = ["#d63939", "#f76707", "#ae3ec9", "#4263eb"];
    const series: object[] = servers.map((sv, i) => ({
      name: sv, type: "bar", barWidth: tl.unit === "hour" ? (days <= 1 ? 8 : 5) : 7,
      itemStyle: { color: palette[i % palette.length] },
      data: tl.series.filter((r) => r.server === sv).map((r) => [r.bucket, r.count]),
    }));
    const bans = tl.ban_events.filter((b) => b.action === "Ban");
    if (tl.success_events.length) {
      series.push({
        name: "ログイン成功", type: "line", data: [], markLine: {
          symbol: "none", lineStyle: { color: STATUS.breach.color, width: 2, type: "solid" },
          label: { formatter: "成功", color: STATUS.breach.color, fontWeight: "bold", position: "end" },
          data: tl.success_events.map((x) => ({ xAxis: x.time })),
        },
      });
    }
    series.push({
      name: "遮断", type: "line", data: [], markLine: {
        symbol: "none", lineStyle: { color: STATUS.blocked.color, width: 2 },
        label: { formatter: "遮断", color: STATUS.blocked.color, fontWeight: "bold", position: "end" },
        data: bans.map((b) => ({ xAxis: b.time })),
      },
    });
    return {
      animation: false,
      grid: { left: 8, right: 16, top: 32, bottom: 8, containLabel: true },
      legend: { top: 0, data: servers, textStyle: { fontSize: 11 } },
      tooltip: { trigger: "axis" },
      // 横軸は期間全体に固定する（データの範囲だけだと、遮断時刻や「遮断後に何も来ていない」ことが見えない）
      xAxis: { type: "time", min: Date.now() - days * 86400000, max: Date.now(),
        axisLabel: { fontSize: 10, hideOverlap: true } },
      yAxis: { type: "value", minInterval: 1, axisLabel: { fontSize: 10 } },
      series,
    };
  }, [tl, days]);

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <h3 className="card-title d-flex align-items-center gap-2">
            {a.is_private ? <IconBuildingCommunity size={20} /> : <IconDeviceDesktop size={20} />}
            {a.ip}
            {a.is_ioc && <span className="badge bg-red">IOC</span>}
          </h3>
          <div className="text-secondary small">
            {a.country ?? (a.is_private ? "社内" : "国不明")}・{a.source_types.map(stLabel).join(" / ") || "-"}
          </div>
        </div>
      </div>
      <div className="card-body">
        <div className="mb-3 fw-bold" style={{ color: STATUS[a.status].color }}>{STATUS[a.status].label}</div>
        <ul className="list-unstyled mb-3">
          {edges.map((e) => (
            <li key={e.server} className="mb-2 d-flex gap-2">
              <IconServer size={18} className="text-blue flex-shrink-0 mt-1" />
              <div className="small">
                <strong>{e.server}</strong>：
                {e.failure_count > 0
                  ? <>失敗 {e.failure_count.toLocaleString()}件（{hm(e.first_seen)}〜{hm(e.last_seen)}）</>
                  : <>この期間の失敗記録なし</>}
                <br />
                {e.breach && (
                  <div className="fw-bold" style={{ color: STATUS.breach.color }}>
                    → 認証失敗 {e.breach.fail_count}件のあと、{hm(e.breach.last_success)} に
                    {e.breach.success_users.length ? ` ${e.breach.success_users.join("、")} ` : " 不明なユーザー"}でログイン成功
                    （成功 {e.breach.success_count}件）。
                    {e.breach.failed_users.length > 0 && <span className="fw-normal">失敗したユーザー: {e.breach.failed_users.join("、")}</span>}
                  </div>
                )}
                {e.banned_since
                  ? <span style={{ color: STATUS[e.status].color }}>
                      → {hm(e.banned_since)} に fail2ban（{e.jails.join(", ")}）で遮断。
                      {e.status === "leak" ? "遮断後も失敗が記録されています" : "遮断後の攻撃は記録されていません"}
                    </span>
                  : <span style={{ color: STATUS[e.status].color }}>
                      → 遮断されていません{e.status === "active" ? "（直近1時間以内も攻撃あり）" : ""}
                    </span>}
              </div>
            </li>
          ))}
        </ul>
        <div className="text-secondary small mb-1">失敗件数の推移（緑の縦線＝遮断、紫の縦線＝ログイン成功）</div>
        {option
          ? <ReactECharts option={option} style={{ height: 200 }} notMerge />
          : <div className="text-secondary small py-4 text-center">読み込み中…</div>}
        <div className="d-flex gap-2 mt-3">
          <button className="btn btn-sm btn-outline-primary" onClick={() => onPick("source_ip", a.ip)}>Eventsで見る</button>
          <button className="btn btn-sm btn-outline-secondary" onClick={() => onEntity("ip", a.ip)}>このIPの詳細</button>
        </div>
      </div>
    </div>
  );
}
