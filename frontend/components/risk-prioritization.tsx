"use client";

import { useState } from "react";
import type { RiskAssessmentResponse, RiskPrioritizationResponse } from "@/lib/api";

const bandStyle: Record<string, string> = { critical: "border-red-400/35 bg-red-400/10 text-red-200", high: "border-orange-400/35 bg-orange-400/10 text-orange-200", medium: "border-amber-400/35 bg-amber-400/10 text-amber-200", low: "border-cyan-400/35 bg-cyan-400/10 text-cyan-200", info: "border-slate-400/35 bg-slate-400/10 text-slate-200" };

export function RiskPrioritization({ report }: { report: RiskPrioritizationResponse }) {
  const [selectedId, setSelectedId] = useState(report.assessments[0]?.id ?? null);
  const selected = report.assessments.find((item) => item.id === selectedId) ?? null;
  const movementClass = report.trend.movement === "increased" ? "text-red-300" : report.trend.movement === "decreased" ? "text-emerald-300" : "text-cyan-300";

  return <section id="risk-prioritization" className="space-y-5 rounded-2xl border border-orange-400/25 bg-[#171008] p-6 shadow-[0_0_45px_rgba(251,146,60,0.06)]">
    <div className="flex flex-col gap-4 border-b border-orange-300/15 pb-5 lg:flex-row lg:items-start lg:justify-between">
      <div><p className="font-mono text-[11px] uppercase tracking-[0.22em] text-orange-300/75">Extension 11 · Risk Agent</p><h2 className="mt-1 text-xl font-semibold text-orange-100">Risk &amp; Heuristic Prioritization</h2><p className="mt-2 max-w-3xl text-sm text-orange-100/55">Transparent scoring for engineering review, calculated from persisted evidence and visible deterministic components.</p></div>
      <div className="max-w-sm rounded-xl border border-cyan-300/20 bg-cyan-400/5 px-3 py-2 text-xs leading-relaxed text-cyan-50/80"><span className="font-mono text-[10px] uppercase tracking-wider text-cyan-300">Model boundary</span><p className="mt-1">No opaque model is active. ML cannot override validated evidence, and no exploitation or new network request is performed.</p></div>
    </div>

    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <Metric label="Overall risk" value={`${report.summary.overall_score.toFixed(1)}/100`} accent="text-orange-200" />
      <Metric label="Risk band" value={report.summary.risk_band.toUpperCase()} accent="text-orange-300" />
      <Metric label="Eligible findings" value={report.summary.eligible_assessment_count} accent="text-amber-300" />
      <Metric label="Priority model" value="DETERMINISTIC" accent="text-cyan-300" compact />
    </div>

    <div className="rounded-xl border border-orange-300/15 bg-[#120d08] p-4 text-sm text-orange-50/65"><span className={`font-mono text-xs uppercase tracking-wider ${movementClass}`}>Trend · {report.trend.movement}</span>{report.trend.score_delta !== null && <span className="ml-2">{report.trend.score_delta > 0 ? "+" : ""}{report.trend.score_delta.toFixed(1)} points versus the latest same-target completed scan.</span>}<p className="mt-2 text-xs text-orange-100/45">{report.trend.limitation}</p></div>

    <div className="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
      <div className="rounded-xl border border-orange-300/15 bg-[#120d08] p-2"><div className="flex items-center justify-between px-2 py-2"><h3 className="font-mono text-xs uppercase tracking-[0.18em] text-orange-300">Priority queue</h3><span className="text-xs text-orange-100/45">{report.assessments.length} findings</span></div><div className="space-y-1">{report.assessments.map((item) => <AssessmentRow key={item.id} item={item} selected={selectedId === item.id} onSelect={() => setSelectedId(item.id)} />)}{report.assessments.length === 0 && <p className="p-4 text-sm text-orange-100/45">No persisted risk assessments are available yet.</p>}</div></div>
      <div className="rounded-xl border border-amber-300/15 bg-[#100e08] p-4"><h3 className="font-mono text-xs uppercase tracking-[0.18em] text-amber-300">Transparent score breakdown</h3>{selected ? <Breakdown item={selected} /> : <p className="mt-3 text-sm text-amber-100/50">Select a finding to inspect every score component and decision note.</p>}</div>
    </div>
  </section>;
}

function AssessmentRow({ item, selected, onSelect }: { item: RiskAssessmentResponse; selected: boolean; onSelect: () => void }) {
  return <button type="button" onClick={onSelect} className={`flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left transition ${selected ? "bg-orange-300/10 ring-1 ring-orange-300/35" : "hover:bg-orange-300/5"}`}><span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${bandStyle[item.risk_band] || bandStyle.info}`}>{item.risk_band}</span><span className="min-w-0 flex-1 truncate text-sm text-orange-50" title={item.subject}>{item.subject}</span><span className="font-mono text-sm text-orange-200">{item.risk_score.toFixed(1)}</span></button>;
}

function Breakdown({ item }: { item: RiskAssessmentResponse }) {
  return <div className="mt-3 space-y-4"><div className="flex flex-wrap items-center gap-2"><h4 className="text-base text-amber-50">{item.subject}</h4><span className={`rounded border px-2 py-0.5 font-mono text-[10px] ${bandStyle[item.risk_band] || bandStyle.info}`}>{item.risk_band} · {item.risk_score.toFixed(1)}</span><span className="font-mono text-[10px] text-amber-100/50">evidence: {item.evidence_state}</span></div><div className="grid gap-2 sm:grid-cols-2">{Object.entries(item.score_components).map(([name, component]) => <div key={name} className="rounded-lg border border-amber-300/10 bg-amber-300/[0.03] p-3"><div className="flex items-center justify-between gap-2"><p className="font-mono text-[10px] uppercase tracking-wider text-amber-300">{name.replaceAll("_", " ")}</p><p className="font-mono text-sm text-amber-100">{component.score.toFixed(0)} <span className="text-amber-100/40">× {component.weight}%</span></p></div><p className="mt-2 text-xs leading-relaxed text-amber-100/55">{component.explanation}</p><p className="mt-2 font-mono text-[10px] text-amber-200/60">contribution: {component.weighted_contribution.toFixed(2)}</p></div>)}</div><div className="rounded-lg border border-cyan-300/15 bg-cyan-400/[0.03] p-3"><p className="font-mono text-[10px] uppercase tracking-wider text-cyan-300">Decision notes</p><ul className="mt-2 space-y-1 text-xs leading-relaxed text-cyan-50/65">{item.decision_notes.map((note) => <li key={note}>— {note}</li>)}</ul></div></div>;
}

function Metric({ label, value, accent, compact = false }: { label: string; value: string | number; accent: string; compact?: boolean }) { return <div className="rounded-xl border border-orange-300/15 bg-[#120d08] p-4"><p className="font-mono text-[10px] uppercase tracking-[0.18em] text-orange-100/40">{label}</p><p className={`mt-2 font-mono ${compact ? "text-sm" : "text-2xl"} ${accent}`}>{value}</p></div>; }
