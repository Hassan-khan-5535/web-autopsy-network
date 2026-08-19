"use client";

import { getSecurityReportExportUrl, type SecurityReportResponse } from "@/lib/api";

const severityStyle: Record<string, string> = {
  critical: "border-red-400/40 bg-red-500/10 text-red-200",
  high: "border-orange-400/40 bg-orange-500/10 text-orange-200",
  medium: "border-amber-400/40 bg-amber-500/10 text-amber-100",
  low: "border-emerald-400/30 bg-emerald-500/10 text-emerald-200",
  info: "border-cyan-400/30 bg-cyan-500/10 text-cyan-200",
};

export function SecurityReport({ report }: { report: SecurityReportResponse }) {
  const exportLink = (format: "pdf" | "json" | "sarif") => getSecurityReportExportUrl(report.scan.id, format);
  return (
    <section id="security-posture-report" className="space-y-6 rounded-2xl border border-indigo-500/25 bg-[#0b1714] p-6">
      <header className="flex flex-col gap-4 border-b border-indigo-500/15 pb-5 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <p className="text-xs font-mono uppercase tracking-[0.2em] text-indigo-300/75">Evidence-backed security posture</p>
          <h2 className="mt-2 text-2xl font-semibold text-indigo-100">Executive Security Report</h2>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-emerald-100/60">{report.executive_summary.summary}</p>
        </div>
        <div className="flex flex-wrap gap-2 text-xs font-semibold">
          {(["pdf", "json", "sarif"] as const).map((format) => <a key={format} href={exportLink(format)} className="rounded-lg border border-indigo-400/30 bg-indigo-500/10 px-3 py-2 uppercase tracking-wide text-indigo-100 hover:bg-indigo-500/20">Export {format}</a>)}
        </div>
      </header>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric label="Overall risk" value={`${report.executive_summary.overall_risk_score}`} detail={report.executive_summary.risk_band} />
        <Metric label="Evidence-backed findings" value={`${report.executive_summary.finding_count}`} detail={`${report.executive_summary.prioritized_finding_count} prioritized`} />
        <Metric label="Attack-surface assets" value={`${report.attack_surface_summary.asset_count}`} detail={`${report.attack_surface_summary.endpoint_count} endpoints`} />
        <Metric label="Graph coverage" value={`${report.attack_surface_summary.graph_node_count}`} detail={`${report.attack_surface_summary.graph_edge_count} relationships`} />
      </div>

      <div className="grid gap-5 lg:grid-cols-[1.2fr,0.8fr]">
        <div className="rounded-xl border border-indigo-500/15 bg-black/20 p-5">
          <h3 className="text-sm font-semibold text-indigo-100">Exploitation Breakpoints</h3>
          <p className="mt-1 text-xs leading-5 text-emerald-100/50">High-level triage only. The report intentionally omits payloads, commands, and exploitation steps.</p>
          {report.exploitation_breakpoints.length ? <div className="mt-4 space-y-3">{report.exploitation_breakpoints.map((item) => <article key={`${item.rule_id}-${item.entry_point}`} className="rounded-lg border border-indigo-500/15 bg-[#08110f] p-4"><div className="flex flex-wrap items-center justify-between gap-2"><p className="max-w-xl truncate text-sm font-medium text-indigo-100" title={item.entry_point}>{item.entry_point}</p><span className={`rounded-full border px-2 py-0.5 text-[10px] font-mono ${severityStyle[item.severity] ?? severityStyle.info}`}>{item.severity} · {item.risk_score}</span></div><p className="mt-2 text-xs leading-5 text-emerald-100/65">{item.why_it_matters}</p><p className="mt-2 text-[11px] text-emerald-100/40">Evidence state: {item.evidence_state} · {item.safety_note}</p></article>)}</div> : <p className="mt-4 text-sm text-emerald-100/50">No validated prioritized entry points are available for this report.</p>}
        </div>
        <div className="space-y-4">
          <div className="rounded-xl border border-indigo-500/15 bg-black/20 p-5"><h3 className="text-sm font-semibold text-indigo-100">Trend comparison</h3><pre className="mt-3 max-h-40 overflow-auto whitespace-pre-wrap text-[11px] leading-5 text-emerald-100/55">{JSON.stringify(report.trend_comparison, null, 2)}</pre></div>
          <div className="rounded-xl border border-indigo-500/15 bg-black/20 p-5"><h3 className="text-sm font-semibold text-indigo-100">Safe screenshots</h3><p className="mt-2 text-xs text-emerald-100/60">{report.safe_screenshot_summary.note}</p></div>
        </div>
      </div>

      <div className="rounded-xl border border-indigo-500/15 bg-black/20 p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-3"><div><h3 className="text-sm font-semibold text-indigo-100">Technical Findings</h3><p className="mt-1 text-xs text-emerald-100/50">Severity, confidence, affected location, evidence state, deterministic risk, remediation, and mapped references.</p></div><span className="text-xs font-mono text-indigo-200">{report.technical_findings.length} findings</span></div>
        <div className="mt-4 space-y-3">{report.technical_findings.map((finding) => <details key={finding.id} className="rounded-lg border border-indigo-500/15 bg-[#08110f] p-4"><summary className="cursor-pointer list-none"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-sm font-semibold text-indigo-100">{finding.statement}</p><p className="mt-1 max-w-3xl truncate text-xs font-mono text-emerald-100/50" title={finding.subject}>{finding.rule_id} · {finding.subject}</p></div><span className={`rounded-full border px-2.5 py-1 text-xs font-mono ${severityStyle[finding.severity] ?? severityStyle.info}`}>{finding.severity} · {finding.confidence}%</span></div></summary><div className="mt-4 grid gap-4 border-t border-indigo-500/10 pt-4 text-xs leading-5 text-emerald-100/65 md:grid-cols-2"><div><p className="font-mono uppercase tracking-wider text-emerald-100/40">Affected location</p><p className="mt-1 break-all">{finding.affected_url ?? finding.subject}{finding.affected_parameter ? ` · parameter: ${finding.affected_parameter}` : ""}</p><p className="mt-3 font-mono uppercase tracking-wider text-emerald-100/40">Evidence</p><p className="mt-1">State: {finding.evidence_state} · quality: {finding.evidence_quality} · classification: {finding.classification}</p><pre className="mt-2 max-h-28 overflow-auto whitespace-pre-wrap rounded bg-black/30 p-2 text-[10px] text-emerald-100/50">{JSON.stringify(finding.evidence, null, 2)}</pre></div><div><p className="font-mono uppercase tracking-wider text-emerald-100/40">Remediation</p><p className="mt-1">{finding.remediation}</p><p className="mt-3 font-mono uppercase tracking-wider text-emerald-100/40">References</p><p className="mt-1 flex flex-wrap gap-2">{finding.references.length ? finding.references.map((reference) => <a key={reference.label} href={reference.url} target="_blank" rel="noreferrer" className="text-indigo-300 underline decoration-indigo-400/40 underline-offset-2">{reference.label}</a>) : "No reference mapping available"}</p><p className="mt-3 text-emerald-100/45">Risk: {finding.risk_score} ({finding.risk_band}) · {finding.limitations || "No additional limitation recorded."}</p></div></div></details>)}</div>
      </div>
      <p className="text-xs text-emerald-100/40">{report.executive_summary.limitations.join(" ")}</p>
    </section>
  );
}

function Metric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <div className="rounded-xl border border-indigo-500/15 bg-black/20 p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">{label}</p><p className="mt-1 text-2xl font-semibold text-indigo-100">{value}</p><p className="mt-1 text-xs text-emerald-100/50">{detail}</p></div>;
}
