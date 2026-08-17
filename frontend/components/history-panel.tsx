"use client";

import { useEffect, useMemo, useState } from "react";
import {
  compareScans,
  getWebsiteScans,
  type DiffItem,
  type ScanDifferenceResponse,
  type WebsiteScanHistoryItem,
} from "@/lib/api";

const CATEGORY_LABELS: Record<string, string> = {
  structure: "Structure",
  technology: "Technology DNA",
  dependencies: "Dependencies",
  security: "Security",
  performance: "Performance",
  content: "Content & SEO",
};

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function ClassificationBadge({ value }: { value: DiffItem["classification"] }) {
  const styles = value === "OBSERVED"
    ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/20"
    : value === "INFERRED"
    ? "bg-amber-500/15 text-amber-300 border-amber-500/20"
    : "bg-blue-500/15 text-blue-300 border-blue-500/20";
  return <span className={`rounded-full border px-2 py-1 text-[10px] font-mono ${styles}`}>{value}</span>;
}

export function HistoryPanel({ websiteId, currentScanId }: { websiteId: string; currentScanId: string }) {
  const [history, setHistory] = useState<WebsiteScanHistoryItem[]>([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [difference, setDifference] = useState<ScanDifferenceResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [comparing, setComparing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    getWebsiteScans(websiteId)
      .then((response) => {
        if (!active) return;
        const prior = response.scans.filter((scan) => scan.id !== currentScanId && scan.state === "COMPLETED");
        setHistory(prior);
        if (prior[0]) setSelectedScanId(prior[0].id);
      })
      .catch((err: unknown) => active && setError(err instanceof Error ? err.message : "History unavailable"))
      .finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [websiteId, currentScanId]);

  async function handleCompare() {
    if (!selectedScanId) return;
    setComparing(true);
    setError(null);
    try {
      setDifference(await compareScans(selectedScanId, currentScanId));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Comparison failed");
    } finally {
      setComparing(false);
    }
  }

  const grouped = useMemo(() => {
    const map = new Map<string, DiffItem[]>();
    for (const item of difference?.items ?? []) map.set(item.category, [...(map.get(item.category) ?? []), item]);
    return map;
  }, [difference]);

  return (
    <section className="space-y-5 rounded-2xl border border-cyan-900/40 bg-[#0b1714] p-6" id="history">
      <div className="flex flex-col gap-4 border-b border-cyan-900/25 pb-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="mb-1 text-xs font-mono uppercase tracking-[0.25em] text-cyan-400/70">Phase 11 · Time Machine</p>
          <h2 className="text-xl font-semibold text-cyan-200">History & Difference Engine</h2>
          <p className="mt-1 max-w-2xl text-sm text-emerald-100/50">Compare stored scans only. No new requests are issued to the target website.</p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <label className="text-xs font-mono text-emerald-100/50" htmlFor="prior-scan">COMPARE CURRENT AGAINST</label>
          <select id="prior-scan" value={selectedScanId} onChange={(event) => setSelectedScanId(event.target.value)} disabled={loading || history.length === 0} className="rounded-lg border border-cyan-900/50 bg-[#050b09] px-3 py-2 text-xs text-emerald-100 outline-none focus:border-cyan-400">
            <option value="">Select a prior completed scan</option>
            {history.map((scan) => <option key={scan.id} value={scan.id}>{new Date(scan.created_at).toLocaleString()} · {scan.page_count} pages</option>)}
          </select>
          <button type="button" onClick={handleCompare} disabled={!selectedScanId || comparing} className="rounded-lg bg-cyan-500/15 px-4 py-2 text-xs font-semibold text-cyan-200 transition hover:bg-cyan-500/25 disabled:cursor-not-allowed disabled:opacity-40">{comparing ? "Comparing…" : "Compare scans"}</button>
        </div>
      </div>

      {error && <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-200">{error}</div>}
      {!loading && history.length === 0 && <div className="rounded-xl border border-white/5 bg-black/20 px-5 py-8 text-center text-sm text-emerald-100/45">No earlier completed scan is available for this website yet. Run a re-scan to activate the Time Machine.</div>}
      {difference && (
        <>
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-xl border border-white/5 bg-black/20 p-4"><p className="text-xs uppercase tracking-wider text-emerald-100/40">Before</p><p className="mt-2 font-mono text-xs text-emerald-100/75">{difference.scan_a.created_at ? new Date(difference.scan_a.created_at).toLocaleString() : "—"}</p></div>
            <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 p-4"><p className="text-xs uppercase tracking-wider text-cyan-300/60">Observed diff items</p><p className="mt-2 text-2xl font-semibold text-cyan-200">{difference.item_count}</p></div>
            <div className="rounded-xl border border-white/5 bg-black/20 p-4"><p className="text-xs uppercase tracking-wider text-emerald-100/40">After</p><p className="mt-2 font-mono text-xs text-emerald-100/75">{difference.scan_b.created_at ? new Date(difference.scan_b.created_at).toLocaleString() : "—"}</p></div>
          </div>
          <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-5">
            <div className="flex items-center justify-between gap-3"><h3 className="font-semibold text-blue-200">AI-explained changes</h3><span className="rounded-full border border-blue-500/20 px-2 py-1 text-[10px] font-mono text-blue-300">AI INTERPRETATION</span></div>
            <p className="mt-3 text-sm leading-6 text-emerald-50/80">{difference.ai_summary.summary}</p>
            <div className="mt-3 flex flex-wrap gap-2">{difference.ai_summary.evidence.map((id) => <a key={id} href={`#diff-${id}`} className="rounded border border-blue-500/20 px-2 py-1 text-[10px] font-mono text-blue-300 hover:bg-blue-500/10">citation {id.slice(0, 8)}</a>)}</div>
          </div>
          <div className="space-y-4">
            {Object.entries(CATEGORY_LABELS).map(([category, label]) => {
              const items = grouped.get(category) ?? [];
              return <div key={category} className="rounded-xl border border-white/5 bg-black/20 p-4"><div className="mb-3 flex items-center justify-between"><h3 className="font-semibold text-emerald-100">{label}</h3><span className="text-xs font-mono text-emerald-100/40">{items.length} change(s)</span></div>{items.length === 0 ? <p className="text-sm text-emerald-100/40">No changes observed.</p> : <div className="space-y-3">{items.map((item) => <article key={item.id} id={`diff-${item.id}`} className="rounded-lg border border-white/5 bg-[#050b09] p-4 target:ring-2 target:ring-cyan-400"><div className="flex flex-wrap items-center justify-between gap-2"><p className="text-sm font-semibold text-emerald-50">{item.change.replaceAll("_", " ")}</p><ClassificationBadge value={item.classification} /></div><div className="mt-3 grid gap-3 md:grid-cols-2"><div><p className="text-[10px] uppercase tracking-wider text-emerald-100/40">Before</p><p className="mt-1 break-words text-xs text-emerald-100/70">{formatValue(item.before)}</p></div><div><p className="text-[10px] uppercase tracking-wider text-emerald-100/40">After</p><p className="mt-1 break-words text-xs text-emerald-100/70">{formatValue(item.after)}</p></div></div>{item.note && <p className="mt-3 text-xs text-amber-200/70">{item.note}</p>}<p className="mt-3 text-[10px] font-mono text-emerald-100/35">DIFF ID {item.id} · evidence {item.evidence.length}</p></article>)}</div>}</div>;
            })}
          </div>
        </>
      )}
    </section>
  );
}
