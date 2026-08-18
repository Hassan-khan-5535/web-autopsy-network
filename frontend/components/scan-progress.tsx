"use client";

import { useEffect, useMemo, useState } from "react";
import { cancelScan, getScanProgress, type ScanProgressResponse } from "@/lib/api";

const LABELS: Record<string, string> = {
  admission: "Admission & SSRF validation",
  collection: "HTTP collection & bounded crawl",
  browser_analysis: "Isolated browser analysis",
  technology: "Technology DNA",
  structure: "Structure intelligence",
  api_intelligence: "API intelligence",
  network_intelligence: "Dependency intelligence",
  security: "Security analysis",
  performance: "Performance analysis",
  accessibility: "Accessibility analysis",
  content: "Content & SEO analysis",
  diagnosis: "Cause of Death diagnosis",
  synthesis: "AI synthesis",
};

function statusStyle(status: string) {
  if (status === "SUCCEEDED") return "text-emerald-300 border-emerald-500/20 bg-emerald-500/10";
  if (status === "RUNNING" || status === "DISPATCHED") return "text-cyan-300 border-cyan-500/20 bg-cyan-500/10";
  if (status === "RETRYING") return "text-amber-300 border-amber-500/20 bg-amber-500/10";
  if (status === "FAILED" || status === "CANCELLED") return "text-red-300 border-red-500/20 bg-red-500/10";
  return "text-emerald-100/45 border-white/10 bg-white/[0.03]";
}

export function ScanProgress({ scanId, state }: { scanId: string; state: string }) {
  const [progress, setProgress] = useState<ScanProgressResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);

  useEffect(() => {
    let active = true;
    let polling = false;
    let source: EventSource | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    const terminalStates = ["COMPLETED", "FAILED", "PARTIAL_FAILED", "CANCELLED"];

    const stop = () => {
      source?.close();
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = null;
    };

    const applyProgress = (next: ScanProgressResponse) => {
      if (!active) return;
      setProgress(next);
      setError(null);
      if (terminalStates.includes(next.state)) stop();
    };

    const poll = async () => {
      try {
        applyProgress(await getScanProgress(scanId));
      } catch (err: unknown) {
        if (active) setError(err instanceof Error ? err.message : "Progress unavailable");
      }
    };

    const startPolling = () => {
      if (!active || polling) return;
      polling = true;
      source?.close();
      setError("Live progress stream unavailable; checking progress automatically.");
      void poll();
      pollTimer = setInterval(() => { void poll(); }, 3000);
    };

    void poll();
    source = new EventSource(`${process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"}/v1/scans/${scanId}/progress/stream`);
    source.addEventListener("progress", (event) => {
      if (!active) return;
      try {
        applyProgress(JSON.parse((event as MessageEvent).data) as ScanProgressResponse);
      } catch {
        startPolling();
      }
    });
    source.onerror = startPolling;
    return () => { active = false; stop(); };
  }, [scanId]);

  const taskCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const task of progress?.tasks ?? []) counts.set(task.task_type, (counts.get(task.task_type) ?? 0) + 1);
    return counts;
  }, [progress]);

  async function handleCancel() {
    setCancelling(true);
    try { setProgress(await cancelScan(scanId)); } catch (err: unknown) { setError(err instanceof Error ? err.message : "Cancellation failed"); } finally { setCancelling(false); }
  }

  return (
    <section className="rounded-2xl border border-cyan-900/40 bg-[#0b1714] p-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div>
          <p className="text-xs font-mono uppercase tracking-[0.25em] text-cyan-400/70">Distributed scan execution</p>
          <h2 className="mt-2 text-xl font-semibold text-cyan-200">Live Scan Progress</h2>
          <p className="mt-1 text-sm text-emerald-100/50">Task state is persisted and streamed from the worker graph; downstream tasks wait for their declared dependencies.</p>
        </div>
        {progress && !["COMPLETED", "FAILED", "PARTIAL_FAILED", "CANCELLED"].includes(progress.state) && <button type="button" onClick={handleCancel} disabled={cancelling || progress.cancel_requested} className="rounded-lg border border-red-500/25 bg-red-500/10 px-4 py-2 text-xs font-semibold text-red-200 hover:bg-red-500/20 disabled:opacity-40">{cancelling ? "Cancelling…" : progress.cancel_requested ? "Cancellation requested" : "Cancel scan"}</button>}
      </div>
      {error && <p className="mt-4 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs text-amber-200/80">{error}</p>}
      <div className="mt-5 flex items-center gap-3"><div className="h-2 flex-1 overflow-hidden rounded-full bg-white/5"><div className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-emerald-400 transition-all" style={{ width: `${progress?.percent ?? (state === "QUEUED" ? 0 : 5)}%` }} /></div><span className="w-12 text-right text-sm font-mono text-cyan-200">{progress?.percent ?? 0}%</span></div>
      {progress?.queue_position && progress.queue_position > 1 && <p className="mt-3 text-xs text-amber-200/70">Queue position {progress.queue_position} · estimated wait {progress.estimated_wait_seconds}s</p>}
      <div className="mt-5 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {(progress?.tasks ?? []).map((task) => <div key={task.id} className={`rounded-lg border p-3 ${statusStyle(task.status)}`}><div className="flex items-center justify-between gap-2"><p className="text-xs font-semibold">{LABELS[task.task_type] ?? task.task_type}</p><span className="rounded-full border px-2 py-0.5 text-[10px] font-mono">{task.status}</span></div><div className="mt-2 flex items-center justify-between text-[10px] font-mono opacity-70"><span>{task.queue} pool</span><span>attempt {task.attempt}/{task.max_retries + 1}</span></div>{task.error_reason && <p className="mt-2 text-[10px] leading-4 opacity-80">{task.error_reason}</p>}</div>)}
      </div>
      {progress && <p className="mt-4 text-xs font-mono text-emerald-100/40">{progress.completed_tasks}/{progress.total_tasks} terminal tasks · {taskCounts.size} task types · state {progress.state}</p>}
    </section>
  );
}
