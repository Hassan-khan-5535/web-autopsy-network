"use client";

import { useState } from "react";
import { createWeeklySchedule, updateRecurringSchedule, type RecurringScheduleResponse } from "@/lib/api";

function formatDate(value: string | null): string {
  if (!value) return "Not yet";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

export function RecurringSchedule({ scanId, schedule, onChange }: { scanId: string; schedule: RecurringScheduleResponse | null; onChange: (schedule: RecurringScheduleResponse) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function create() {
    setBusy(true); setError(null);
    try { onChange(await createWeeklySchedule(scanId)); } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to create the recurring schedule."); } finally { setBusy(false); }
  }
  async function toggle() {
    if (!schedule) return;
    setBusy(true); setError(null);
    try { onChange(await updateRecurringSchedule(schedule.id, !schedule.enabled)); } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to update the recurring schedule."); } finally { setBusy(false); }
  }

  return <section id="recurring-schedule" className="space-y-5 rounded-2xl border border-emerald-300/25 bg-[#07150f] p-6 shadow-[0_0_45px_rgba(52,211,153,0.05)]">
    <div className="flex flex-col gap-4 border-b border-emerald-300/15 pb-5 lg:flex-row lg:items-start lg:justify-between"><div><p className="font-mono text-[11px] uppercase tracking-[0.22em] text-emerald-300/75">Extension 12 · Continuous Assessment</p><h2 className="mt-1 text-xl font-semibold text-emerald-50">Weekly Recurring Assessment</h2><p className="mt-2 max-w-3xl text-sm text-emerald-50/55">Schedules create ordinary bounded scans only after the checker revalidates the persisted authorization, scope, profile, and current policy.</p></div>{schedule ? <span className={`w-fit rounded-full border px-3 py-1 font-mono text-xs ${schedule.enabled ? "border-emerald-300/30 bg-emerald-300/10 text-emerald-100" : "border-amber-300/30 bg-amber-300/10 text-amber-100"}`}>{schedule.enabled ? "enabled" : "disabled"}</span> : <span className="w-fit rounded-full border border-slate-300/25 bg-slate-300/10 px-3 py-1 font-mono text-xs text-slate-100">not scheduled</span>}</div>
    {schedule ? <div className="space-y-4"><div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4"><Metric label="Cadence" value={schedule.cadence} /><Metric label="Next eligibility" value={formatDate(schedule.next_run_at)} small /><Metric label="Last run" value={formatDate(schedule.last_run_at)} small /><Metric label="Target" value={schedule.target_url} small /></div>{schedule.last_block_reason && <div className="rounded-xl border border-amber-300/25 bg-amber-300/[0.06] p-3 text-sm text-amber-50/80"><span className="font-mono text-[10px] uppercase tracking-wider text-amber-300">Schedule blocked</span><p className="mt-1">{schedule.last_block_reason}</p></div>}<div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-emerald-300/15 bg-[#06100b] p-4"><p className="max-w-2xl text-xs leading-relaxed text-emerald-100/55">Disabling pauses future checks. Re-enabling does not bypass authorization: every due run still fails closed if the stored authorization has expired or scope/policy changes.</p><button type="button" disabled={busy} onClick={toggle} className="rounded-lg border border-emerald-300/30 bg-emerald-300/[0.08] px-4 py-2 text-sm font-medium text-emerald-100 transition hover:bg-emerald-300/[0.14] disabled:cursor-not-allowed disabled:opacity-50">{busy ? "Updating…" : schedule.enabled ? "Disable schedule" : "Enable schedule"}</button></div></div> : <div className="flex flex-col gap-4 rounded-xl border border-emerald-300/15 bg-[#06100b] p-5 sm:flex-row sm:items-center sm:justify-between"><p className="max-w-2xl text-sm leading-relaxed text-emerald-100/60">Create a weekly schedule from this scan’s stored authorization. Only the safe assessment profile is eligible, and all authorization and scope gates are checked again before dispatch.</p><button type="button" disabled={busy} onClick={create} className="w-fit rounded-lg border border-emerald-300/30 bg-emerald-300/[0.1] px-4 py-2 text-sm font-medium text-emerald-100 transition hover:bg-emerald-300/[0.16] disabled:cursor-not-allowed disabled:opacity-50">{busy ? "Creating…" : "Create weekly schedule"}</button></div>}
    {error && <p role="alert" className="rounded-lg border border-red-300/30 bg-red-300/[0.08] px-3 py-2 text-sm text-red-100">{error}</p>}
  </section>;
}

function Metric({ label, value, small = false }: { label: string; value: string; small?: boolean }) { return <div className="min-w-0 rounded-xl border border-emerald-300/15 bg-[#06100b] p-4"><p className="font-mono text-[10px] uppercase tracking-[0.18em] text-emerald-100/40">{label}</p><p className={`mt-2 truncate ${small ? "text-sm" : "font-mono text-xl"} text-emerald-100`} title={value}>{value}</p></div>; }
