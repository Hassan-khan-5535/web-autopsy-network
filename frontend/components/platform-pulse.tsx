"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { getPlatformDashboard, getUpdateStatus, type PlatformDashboardResponse, type UpdateStatusResponse } from "@/lib/api";

const stateStyle: Record<string, string> = {
  COMPLETED: "border-emerald-400/30 bg-emerald-500/10 text-emerald-200",
  PARTIAL_FAILED: "border-amber-400/30 bg-amber-500/10 text-amber-100",
  FAILED: "border-red-400/30 bg-red-500/10 text-red-200",
  CANCELLED: "border-slate-400/30 bg-slate-500/10 text-slate-200",
};

export function PlatformPulse() {
  const [data, setData] = useState<PlatformDashboardResponse | null>(null);
  const [updates, setUpdates] = useState<UpdateStatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshedAt, setRefreshedAt] = useState<Date | null>(null);

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const [next, updateStatus] = await Promise.all([getPlatformDashboard(), getUpdateStatus().catch(() => null)]);
        if (!active) return;
        setData(next);
        setUpdates(updateStatus);
        setRefreshedAt(new Date());
        setError(null);
      } catch (err: unknown) {
        if (active) setError(err instanceof Error ? err.message : "Platform pulse unavailable");
      }
    };
    void load();
    const timer = window.setInterval(() => { void load(); }, 10000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  const scans = data?.scans ?? [];
  return (
    <section className="border-y border-emerald-100/10 py-8" aria-label="Continuous security command center">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div><p className="text-xs font-mono uppercase tracking-[0.22em] text-cyan-300/75">Continuous security command center</p><h2 className="mt-2 text-2xl font-semibold text-emerald-50">Portfolio pulse</h2><p className="mt-2 text-sm text-emerald-100/55">Persisted scan posture, active investigations, and direct report access. No target requests are issued from this view.</p></div>
        <div className="text-xs font-mono text-emerald-100/40">{refreshedAt ? `Updated ${refreshedAt.toLocaleTimeString()}` : "Connecting to persisted scan state…"}</div>
      </div>
      {error && <p className="mt-4 rounded-lg border border-amber-400/20 bg-amber-500/5 p-3 text-xs text-amber-100">{error}</p>}
      <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><Metric label="Recent scans" value={data?.summary.scan_count ?? "—"} detail="Persisted work queue" /><Metric label="Targets observed" value={data?.summary.target_count ?? "—"} detail="Distinct target origins" /><Metric label="Active investigations" value={data?.summary.active_scan_count ?? "—"} detail="Queued or in progress" /><Metric label="Completed reports" value={data?.summary.state_counts.COMPLETED ?? "—"} detail="Ready for review" /></div>
      <div className="mt-5 overflow-hidden rounded-2xl border border-emerald-500/15 bg-[#07110e]/80">
        <div className="grid grid-cols-[minmax(0,1fr)_auto] gap-3 border-b border-emerald-500/10 px-4 py-3 text-[10px] font-mono uppercase tracking-wider text-emerald-100/40"><span>Recent investigations</span><span>Posture / report</span></div>
        {scans.length ? scans.slice(0, 6).map((scan) => <Link key={scan.id} href={`/scans/${scan.id}`} className="grid grid-cols-[minmax(0,1fr)_auto] gap-3 border-b border-emerald-500/10 px-4 py-4 transition-colors hover:bg-emerald-500/[0.05]"><div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><p className="truncate text-sm font-medium text-emerald-100" title={scan.target_url}>{scan.target_url}</p><span className={`rounded-full border px-2 py-0.5 text-[10px] font-mono ${stateStyle[scan.state] ?? "border-cyan-400/30 bg-cyan-500/10 text-cyan-100"}`}>{scan.state}</span></div><p className="mt-1 text-xs text-emerald-100/45">{scan.assessment_profile ?? "legacy"} profile · {scan.page_count} persisted pages · started {new Date(scan.created_at).toLocaleString()}</p></div><div className="text-right"><p className="text-sm font-mono text-cyan-100">{scan.risk_score ?? "—"}</p><p className="mt-1 text-[10px] uppercase tracking-wider text-emerald-100/45">{scan.risk_band ?? "risk pending"}{scan.posture_available ? " · posture" : ""}</p></div></Link>) : <div className="px-4 py-8 text-sm text-emerald-100/50">No persisted scans are available yet. Create an authorized assessment to start the portfolio timeline.</div>}
      </div>
      <UpdateLifecycle updates={updates} />
    </section>
  );
}

function UpdateLifecycle({ updates }: { updates: UpdateStatusResponse | null }) {
  const active = updates?.packages.find((item) => item.status === "active");
  const disabledCount = active?.validation_report?.regression?.disabled_rule_ids?.length ?? 0;
  return <div className="mt-5 rounded-2xl border border-cyan-500/15 bg-cyan-500/[0.035] p-4"><div className="flex flex-wrap items-start justify-between gap-3"><div><p className="text-[10px] font-mono uppercase tracking-[0.18em] text-cyan-300/70">Signature intelligence lifecycle</p><p className="mt-1 text-sm font-semibold text-cyan-100">{active ? `${active.name} · ${active.version}` : "Built-in rule fallback active"}</p><p className="mt-1 text-xs text-emerald-100/55">{active ? `Verified ${active.activated_at ? new Date(active.activated_at).toLocaleString() : "locally"} · ${active.components.length} component sets · ${disabledCount} disabled rules` : updates?.fallback ?? "Local signatures remain available if update metadata is unavailable."}</p></div><span className={`rounded-full border px-3 py-1 text-[10px] font-mono ${active?.signature_verified ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-100" : "border-slate-400/30 bg-slate-500/10 text-slate-200"}`}>{active?.signature_verified ? "VERIFIED PACKAGE" : "OFFLINE FALLBACK"}</span></div></div>;
}

function Metric({ label, value, detail }: { label: string; value: string | number; detail: string }) {
  return <div className="rounded-xl border border-cyan-500/15 bg-cyan-500/[0.04] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">{label}</p><p className="mt-1 text-2xl font-semibold text-cyan-100">{value}</p><p className="mt-1 text-xs text-emerald-100/50">{detail}</p></div>;
}
