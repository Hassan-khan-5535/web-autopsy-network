"use client";

import type { CauseOfDeathDiagnosis, DiagnosisIssue } from "@/lib/api";

function IssueRow({ issue, tone }: { issue: DiagnosisIssue; tone: "primary" | "secondary" | "contributing" }) {
  const toneClasses = tone === "primary"
    ? "border-red-500/30 bg-red-500/10"
    : tone === "secondary"
    ? "border-amber-500/20 bg-amber-500/5"
    : "border-cyan-500/20 bg-cyan-500/5";
  return (
    <article className={`rounded-xl border p-4 ${toneClasses}`}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[10px] font-mono uppercase tracking-[0.22em] text-emerald-100/45">{tone}</p>
          <h3 className="mt-1 text-base font-semibold text-emerald-50">{issue.subject}</h3>
          <p className="mt-1 text-xs uppercase tracking-wider text-emerald-100/45">{issue.category} · {issue.classification}</p>
        </div>
        <div className="text-right">
          <p className="text-lg font-semibold text-emerald-200">{issue.score.toFixed(2)}</p>
          <p className="text-[10px] font-mono text-emerald-100/40">priority score</p>
        </div>
      </div>
      <p className="mt-3 text-sm leading-6 text-emerald-50/80">{issue.statement}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        {issue.evidence.map((item) => (
          <a key={item.id} href={`#evidence-${item.id}`} className="rounded border border-emerald-500/20 px-2 py-1 text-[10px] font-mono text-emerald-300 hover:bg-emerald-500/10">
            evidence {item.id.slice(0, 8)}
          </a>
        ))}
      </div>
    </article>
  );
}

export function CauseOfDeath({ diagnosis }: { diagnosis: CauseOfDeathDiagnosis }) {
  return (
    <section id="cause-of-death" className="overflow-hidden rounded-2xl border border-red-500/25 bg-gradient-to-br from-[#1a1011] via-[#0b1714] to-[#091313] shadow-2xl shadow-red-950/20">
      <div className="border-b border-red-500/15 bg-red-500/5 px-6 py-5">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div>
            <p className="text-xs font-mono uppercase tracking-[0.28em] text-red-300/75">Forensic synthesis · Phase 12</p>
            <h2 className="mt-2 text-3xl font-semibold tracking-tight text-red-100">Cause of Death</h2>
            <p className="mt-2 max-w-2xl text-sm text-emerald-100/55">A deterministic prioritization of the most consequential persisted findings in this scan.</p>
          </div>
          <div className="grid grid-cols-2 gap-2 text-center sm:grid-cols-3">
            <div className="rounded-lg border border-red-500/20 bg-black/20 px-4 py-3"><p className="text-2xl font-semibold text-red-200">{Math.round(diagnosis.confidence * 100)}%</p><p className="text-[10px] font-mono text-red-200/50">confidence</p></div>
            <div className="rounded-lg border border-white/5 bg-black/20 px-4 py-3"><p className="text-2xl font-semibold text-emerald-200">{diagnosis.evidence_count}</p><p className="text-[10px] font-mono text-emerald-100/50">evidence items</p></div>
            <div className="col-span-2 rounded-lg border border-white/5 bg-black/20 px-4 py-3 sm:col-span-1"><p className="text-2xl font-semibold text-amber-200">{diagnosis.secondary_issues.length + diagnosis.contributing_factors.length + 1}</p><p className="text-[10px] font-mono text-amber-100/50">selected issues</p></div>
          </div>
        </div>
      </div>
      <div className="space-y-4 p-6">
        <IssueRow issue={diagnosis.primary_issue} tone="primary" />
        {diagnosis.secondary_issues.length > 0 && <div className="grid gap-3 md:grid-cols-2">{diagnosis.secondary_issues.map((issue) => <IssueRow key={issue.finding_id ?? issue.subject} issue={issue} tone="secondary" />)}</div>}
        {diagnosis.contributing_factors.length > 0 && <div><p className="mb-3 text-xs font-mono uppercase tracking-[0.2em] text-cyan-300/60">Contributing factors · relation-traceable</p><div className="grid gap-3 md:grid-cols-2">{diagnosis.contributing_factors.map((issue) => <IssueRow key={issue.finding_id ?? issue.subject} issue={issue} tone="contributing" />)}</div></div>}
        {diagnosis.ai_narrative && <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4"><div className="flex flex-wrap items-center justify-between gap-2"><p className="text-sm font-semibold text-blue-200">AI-narrated diagnosis</p><span className="rounded-full border border-blue-500/20 px-2 py-1 text-[10px] font-mono text-blue-300">AI INTERPRETATION</span></div><p className="mt-2 text-sm leading-6 text-emerald-50/80">{diagnosis.ai_narrative}</p></div>}
        <div className="rounded-lg border border-red-500/15 bg-red-500/5 p-4 text-xs leading-5 text-red-100/70"><strong className="text-red-200">Required disclaimer:</strong> {diagnosis.disclaimer}</div>
      </div>
    </section>
  );
}
