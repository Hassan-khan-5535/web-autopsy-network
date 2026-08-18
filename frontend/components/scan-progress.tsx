"use client";

import Link from "next/link";
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

const TERMINAL_STATES = ["COMPLETED", "FAILED", "PARTIAL_FAILED", "CANCELLED"];

function statusStyle(status: string) {
  if (status === "SUCCEEDED") return "text-emerald-300 border-emerald-500/20 bg-emerald-500/10";
  if (status === "RUNNING" || status === "DISPATCHED") return "text-cyan-300 border-cyan-500/20 bg-cyan-500/10";
  if (status === "RETRYING") return "text-amber-300 border-amber-500/20 bg-amber-500/10";
  if (status === "FAILED" || status === "CANCELLED") return "text-red-300 border-red-500/20 bg-red-500/10";
  return "text-emerald-100/45 border-white/10 bg-white/[0.03]";
}

function formatDuration(milliseconds: number | null) {
  if (milliseconds === null) return "Estimating…";
  const totalSeconds = Math.max(0, Math.round(milliseconds / 1000));
  if (totalSeconds < 1) return "<1s";
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes < 60) return seconds ? `${minutes}m ${seconds}s` : `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return remainingMinutes ? `${hours}h ${remainingMinutes}m` : `${hours}h`;
}

function formatClock(timestamp: number | null) {
  if (timestamp === null) return "—";
  return new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit", second: "2-digit" }).format(timestamp);
}

export function ScanProgress({ scanId, state }: { scanId: string; state: string }) {
  const [progress, setProgress] = useState<ScanProgressResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    let active = true;
    let polling = false;
    let source: EventSource | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const stop = () => {
      source?.close();
      if (pollTimer) clearInterval(pollTimer);
      pollTimer = null;
    };

    const applyProgress = (next: ScanProgressResponse) => {
      if (!active) return;
      setProgress(next);
      setError(null);
      if (TERMINAL_STATES.includes(next.state)) stop();
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
    const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL || "/api";
    source = new EventSource(`${apiBaseUrl}/v1/scans/${scanId}/progress/stream`);
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

  const progressState = progress?.state;

  useEffect(() => {
    if (!progressState || TERMINAL_STATES.includes(progressState)) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [progressState]);

  const timing = useMemo(() => {
    const taskStarts = (progress?.tasks ?? [])
      .map((task) => task.started_at ? Date.parse(task.started_at) : null)
      .filter((value): value is number => value !== null && Number.isFinite(value));
    const taskFinishes = (progress?.tasks ?? [])
      .map((task) => task.finished_at ? Date.parse(task.finished_at) : null)
      .filter((value): value is number => value !== null && Number.isFinite(value));
    const startedAt = taskStarts.length ? Math.min(...taskStarts) : null;
    const finishedAt = taskFinishes.length && progress && TERMINAL_STATES.includes(progress.state) ? Math.max(...taskFinishes) : null;
    const elapsedMs = startedAt === null ? 0 : Math.max(0, (finishedAt ?? now) - startedAt);
    const isTerminal = Boolean(progress && TERMINAL_STATES.includes(progress.state));
    const remainingMs = !progress || isTerminal || progress.percent <= 0
      ? (isTerminal ? 0 : null)
      : Math.max(0, elapsedMs * ((100 - progress.percent) / progress.percent));
    const expectedAt = remainingMs === null ? null : now + remainingMs;
    return { elapsedMs, remainingMs, expectedAt, startedAt, finishedAt, isTerminal };
  }, [now, progress]);

  const taskCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const task of progress?.tasks ?? []) counts.set(task.task_type, (counts.get(task.task_type) ?? 0) + 1);
    return counts;
  }, [progress]);

  async function handleCancel() {
    setCancelling(true);
    try { setProgress(await cancelScan(scanId)); } catch (err: unknown) { setError(err instanceof Error ? err.message : "Cancellation failed"); } finally { setCancelling(false); }
  }

  const isTerminal = timing.isTerminal;
  const percent = progress?.percent ?? (state === "QUEUED" ? 0 : 5);

  return (
    <section className="rounded-2xl border border-cyan-900/40 bg-[#0b1714] p-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div>
          <p className="text-xs font-mono uppercase tracking-[0.25em] text-cyan-400/70">Distributed scan execution</p>
          <h2 className="mt-2 text-xl font-semibold text-cyan-200">{isTerminal ? "Scan Summary" : "Live Scan Progress"}</h2>
          <p className="mt-1 text-sm text-emerald-100/50">Task state is persisted and streamed from the worker graph; downstream tasks wait for their declared dependencies.</p>
        </div>
        {progress && !isTerminal && <button type="button" onClick={handleCancel} disabled={cancelling || progress.cancel_requested} className="rounded-lg border border-red-500/25 bg-red-500/10 px-4 py-2 text-xs font-semibold text-red-200 hover:bg-red-500/20 disabled:opacity-40">{cancelling ? "Cancelling…" : progress.cancel_requested ? "Cancellation requested" : "Cancel scan"}</button>}
      </div>
      {error && <p className="mt-4 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs text-amber-200/80">{error}</p>}
      <div className="mt-5 flex items-center gap-3"><div className="h-2 flex-1 overflow-hidden rounded-full bg-white/5"><div className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-emerald-400 transition-all" style={{ width: `${percent}%` }} /></div><span className="w-12 text-right text-sm font-mono text-cyan-200">{percent}%</span></div>
      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <div className="rounded-lg border border-white/5 bg-black/20 p-3"><p className="text-[10px] uppercase tracking-wider text-emerald-100/40">Elapsed</p><p className="mt-1 text-lg font-mono text-emerald-100">{formatDuration(timing.elapsedMs)}</p></div>
        <div className="rounded-lg border border-white/5 bg-black/20 p-3"><p className="text-[10px] uppercase tracking-wider text-emerald-100/40">{isTerminal ? "Total duration" : "Estimated remaining"}</p><p className="mt-1 text-lg font-mono text-cyan-200">{formatDuration(isTerminal ? timing.elapsedMs : timing.remainingMs)}</p></div>
        <div className="rounded-lg border border-white/5 bg-black/20 p-3"><p className="text-[10px] uppercase tracking-wider text-emerald-100/40">{isTerminal ? "Finished" : "Expected completion"}</p><p className="mt-1 text-lg font-mono text-emerald-100">{isTerminal ? formatClock(timing.finishedAt) : formatClock(timing.expectedAt)}</p></div>
      </div>
      {!isTerminal && <p className="mt-3 text-xs text-emerald-100/45">The remaining-time estimate recalculates every second from completed progress and the current task graph. It is an estimate, not a hard deadline.</p>}
      {progress?.queue_position && progress.queue_position > 1 && <p className="mt-3 text-xs text-amber-200/70">Queue position {progress.queue_position} · estimated wait {progress.estimated_wait_seconds}s</p>}
      <div className="mt-5 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {(progress?.tasks ?? []).map((task) => <div key={task.id} className={`rounded-lg border p-3 ${statusStyle(task.status)}`}><div className="flex items-center justify-between gap-2"><p className="text-xs font-semibold">{LABELS[task.task_type] ?? task.task_type}</p><span className="rounded-full border px-2 py-0.5 text-[10px] font-mono">{task.status}</span></div><div className="mt-2 flex items-center justify-between text-[10px] font-mono opacity-70"><span>{task.queue} pool</span><span>attempt {task.attempt}/{task.max_retries + 1}</span></div>{task.error_reason && <p className="mt-2 text-[10px] leading-4 opacity-80">{task.error_reason}</p>}</div>)}
      </div>
      {progress && <p className="mt-4 text-xs font-mono text-emerald-100/40">{progress.completed_tasks}/{progress.total_tasks} terminal tasks · {taskCounts.size} task types · state {progress.state}</p>}
      {isTerminal && (
        <div className="mt-6 flex flex-col gap-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-sm font-semibold text-emerald-200">{progress?.state === "COMPLETED" ? "Scan complete — your report is ready." : `Scan finished with state ${progress?.state ?? state}.`}</p>
            <p className="mt-1 text-xs text-emerald-100/50">Choose what you want to do next.</p>
          </div>
          <div className="flex flex-wrap gap-2 text-xs font-semibold">
            <a href="#cause-of-death" className="rounded-lg bg-emerald-400 px-3 py-2 text-emerald-950 hover:bg-emerald-300">View report ↓</a>
            <Link href="/scans" className="rounded-lg border border-emerald-500/30 px-3 py-2 text-emerald-200 hover:bg-emerald-500/10">New scan</Link>
            <Link href="/" className="rounded-lg border border-white/10 px-3 py-2 text-emerald-100/70 hover:bg-white/5">Home</Link>
          </div>
        </div>
      )}
    </section>
  );
}
