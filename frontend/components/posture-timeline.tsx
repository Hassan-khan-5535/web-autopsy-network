"use client";

import type { PostureTimelineResponse, PostureTimelineSnapshot } from "@/lib/api";

const bandClass: Record<string, string> = {
  critical: "border-red-300/35 bg-red-400/10 text-red-100",
  high: "border-orange-300/35 bg-orange-400/10 text-orange-100",
  medium: "border-amber-300/35 bg-amber-400/10 text-amber-100",
  low: "border-cyan-300/35 bg-cyan-400/10 text-cyan-100",
  info: "border-slate-300/35 bg-slate-400/10 text-slate-100",
};

function formatDate(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function ChangeSummary({ snapshot }: { snapshot: PostureTimelineSnapshot }) {
  const entries = Object.entries(snapshot.comparison_summary.change_counts || {});
  if (snapshot.comparison_summary.baseline) {
    return <p className="text-xs leading-relaxed text-cyan-100/55">Baseline snapshot. Later scans will describe differences against this recorded posture.</p>;
  }
  if (entries.length === 0) {
    return <p className="text-xs leading-relaxed text-cyan-100/55">No material persisted posture changes were recorded for this comparison.</p>;
  }
  return <div className="flex flex-wrap gap-1.5">{entries.map(([change, count]) => <span key={change} className="rounded-full border border-cyan-300/20 bg-cyan-300/[0.04] px-2 py-1 font-mono text-[10px] text-cyan-100/75">{change.replaceAll("_", " ")}: {count}</span>)}</div>;
}

export function PostureTimeline({ timeline }: { timeline: PostureTimelineResponse }) {
  const latest = timeline.snapshots.at(-1);
  return <section id="posture-timeline" className="space-y-5 rounded-2xl border border-cyan-300/25 bg-[#071418] p-6 shadow-[0_0_45px_rgba(34,211,238,0.05)]">
    <div className="flex flex-col gap-4 border-b border-cyan-300/15 pb-5 lg:flex-row lg:items-start lg:justify-between">
      <div><p className="font-mono text-[11px] uppercase tracking-[0.22em] text-cyan-300/75">Extension 12 · Differential Assessment</p><h2 className="mt-1 text-xl font-semibold text-cyan-50">Historical Security Posture</h2><p className="mt-2 max-w-3xl text-sm text-cyan-50/55">A same-target record of persisted posture snapshots, risk movement, and evidence-backed changes across completed scans.</p></div>
      <div className="rounded-xl border border-cyan-300/20 bg-cyan-300/[0.04] px-3 py-2 text-xs leading-relaxed text-cyan-50/75"><p className="font-mono text-[10px] uppercase tracking-wider text-cyan-300">Posture version</p><p className="mt-1">{timeline.posture_version} · {timeline.snapshots.length} stored snapshot{timeline.snapshots.length === 1 ? "" : "s"}</p></div>
    </div>

    {latest && <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4"><Metric label="Latest risk" value={`${latest.overall_risk_score.toFixed(1)}/100`} accent="text-cyan-100" /><Metric label="Risk band" value={latest.risk_band.toUpperCase()} accent="text-cyan-300" /><Metric label="Assets / endpoints" value={`${latest.posture_summary.asset_count} / ${latest.posture_summary.endpoint_count}`} accent="text-emerald-200" /><Metric label="Security findings" value={latest.posture_summary.security_finding_count} accent="text-amber-200" /></div>}

    {timeline.snapshots.length > 0 ? <div className="space-y-3">{timeline.snapshots.slice().reverse().map((snapshot) => <article key={snapshot.scan_id} className="rounded-xl border border-cyan-300/15 bg-[#061015] p-4"><div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between"><div><div className="flex flex-wrap items-center gap-2"><h3 className="font-mono text-sm text-cyan-50">{formatDate(snapshot.created_at)}</h3><span className={`rounded border px-2 py-0.5 font-mono text-[10px] ${bandClass[snapshot.risk_band.toLowerCase()] || bandClass.info}`}>{snapshot.risk_band} · {snapshot.overall_risk_score.toFixed(1)}</span></div><p className="mt-1 font-mono text-[10px] text-cyan-100/35">scan {snapshot.scan_id}</p></div><div className="grid grid-cols-3 gap-2 text-right text-xs"><Stat label="Vulns" value={snapshot.posture_summary.vulnerability_count} /><Stat label="Config" value={snapshot.posture_summary.configuration_finding_count} /><Stat label="Secrets" value={snapshot.posture_summary.secret_finding_count} /></div></div><div className="mt-4 grid gap-3 border-t border-cyan-300/10 pt-4 lg:grid-cols-[0.75fr_1.25fr]"><div><p className="font-mono text-[10px] uppercase tracking-wider text-cyan-300/75">Observed posture</p><p className="mt-2 text-xs leading-relaxed text-cyan-100/60">{snapshot.posture_summary.technology_count} technologies · {snapshot.posture_summary.header_observation_count} header observations · severity mix: {Object.entries(snapshot.posture_summary.severity_counts).map(([severity, count]) => `${severity} ${count}`).join(", ") || "none"}</p></div><div><p className="font-mono text-[10px] uppercase tracking-wider text-cyan-300/75">Comparison record</p><div className="mt-2"><ChangeSummary snapshot={snapshot} /></div>{snapshot.comparison_summary.limitation && <p className="mt-2 text-xs text-amber-100/60">Limitation: {snapshot.comparison_summary.limitation}</p>}</div></div></article>)}</div> : <div className="rounded-xl border border-cyan-300/15 bg-[#061015] p-5 text-sm text-cyan-100/60">No completed-scan posture snapshot is available yet. This record is populated after the scan’s persisted analysis finishes.</div>}
    <p className="text-xs leading-relaxed text-cyan-100/40">{timeline.limitation}</p>
  </section>;
}

function Metric({ label, value, accent }: { label: string; value: string | number; accent: string }) { return <div className="rounded-xl border border-cyan-300/15 bg-[#061015] p-4"><p className="font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-100/40">{label}</p><p className={`mt-2 font-mono text-xl ${accent}`}>{value}</p></div>; }
function Stat({ label, value }: { label: string; value: number }) { return <div><p className="font-mono text-[9px] uppercase tracking-wider text-cyan-100/35">{label}</p><p className="mt-1 font-mono text-cyan-100">{value}</p></div>; }
