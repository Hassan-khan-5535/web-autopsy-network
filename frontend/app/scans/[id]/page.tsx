"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { getScan, getScanEvidence, type ScanResponse, type ObservationResponse } from "@/lib/api";

export default function ScanResultPage() {
  const params = useParams();
  const id = params.id as string;

  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [evidence, setEvidence] = useState<ObservationResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    async function loadData() {
      try {
        const scanData = await getScan(id);
        if (!mounted) return;
        setScan(scanData);

        if (scanData.state === "COMPLETED") {
          const evidenceData = await getScanEvidence(id);
          if (mounted) setEvidence(evidenceData);
        }
      } catch (err: any) {
        if (mounted) setError(err.message || "Failed to load scan data");
      } finally {
        if (mounted) setLoading(false);
      }
    }

    loadData();
    return () => { mounted = false; };
  }, [id]);

  if (loading) {
    return (
      <main className="min-h-screen flex items-center justify-center bg-[#08110f] text-[#ecf4ee]">
        <div className="animate-pulse flex items-center gap-3">
          <div className="h-3 w-3 bg-emerald-400 rounded-full" />
          <p className="text-emerald-400/80 font-mono text-sm tracking-widest">LOADING EVIDENCE...</p>
        </div>
      </main>
    );
  }

  if (error || !scan) {
    return (
      <main className="min-h-screen flex flex-col items-center justify-center bg-[#08110f] text-[#ecf4ee] p-6">
        <div className="bg-red-500/10 border border-red-500/20 p-6 rounded-2xl max-w-lg text-center">
          <h2 className="text-red-400 font-semibold mb-2">Error Loading Scan</h2>
          <p className="text-red-200/80 text-sm mb-6">{error || "Scan not found"}</p>
          <a href="/scans" className="text-emerald-500 hover:text-emerald-400 text-sm font-medium">
            &larr; Return to Scanner
          </a>
        </div>
      </main>
    );
  }

  const isFailed = scan.state === "FAILED";
  const isCompleted = scan.state === "COMPLETED";

  return (
    <main className="min-h-screen bg-[#08110f] text-[#ecf4ee] px-6 py-12 sm:px-10">
      <div className="max-w-4xl mx-auto space-y-8">
        
        <header className="flex items-start justify-between border-b border-emerald-100/10 pb-8">
          <div>
            <div className="flex items-center gap-3 mb-3">
              <span className={`px-2.5 py-1 text-xs font-mono font-medium rounded border ${
                isCompleted ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : 
                isFailed ? "bg-red-500/10 text-red-400 border-red-500/20" : 
                "bg-amber-500/10 text-amber-400 border-amber-500/20"
              }`}>
                {scan.state}
              </span>
              <p className="text-xs text-emerald-100/40 font-mono">{scan.id}</p>
            </div>
            <h1 className="text-3xl font-semibold tracking-tight truncate max-w-2xl" title={scan.requested_url}>
              {scan.requested_url}
            </h1>
          </div>
          <a href="/scans" className="text-emerald-500 hover:text-emerald-400 text-sm font-medium">
            New Scan &rarr;
          </a>
        </header>

        {isFailed && (
          <section className="bg-red-500/5 border border-red-500/10 rounded-2xl p-6">
            <h3 className="text-red-400 font-semibold mb-2">Collection Failed</h3>
            <p className="text-red-200/70 text-sm font-mono whitespace-pre-wrap">{scan.error_reason}</p>
          </section>
        )}

        {isCompleted && (
          <section className="space-y-4">
            <h2 className="text-xl font-semibold mb-6 flex items-center gap-2">
              <span className="text-emerald-400">Raw Evidence</span>
              <span className="text-xs font-mono bg-white/5 px-2 py-0.5 rounded text-emerald-100/50">{evidence.length} OBSERVATIONS</span>
            </h2>

            <div className="overflow-hidden rounded-xl border border-white/5 bg-black/20">
              <table className="w-full text-left text-sm">
                <thead className="bg-white/5 font-mono text-xs text-emerald-100/40">
                  <tr>
                    <th className="px-4 py-3 font-medium">CATEGORY</th>
                    <th className="px-4 py-3 font-medium">SUBJECT</th>
                    <th className="px-4 py-3 font-medium">OBSERVATION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {evidence.map((obs) => (
                    <tr key={obs.id} className="hover:bg-white/[0.02] transition-colors">
                      <td className="px-4 py-3 whitespace-nowrap text-emerald-200/70">{obs.category}</td>
                      <td className="px-4 py-3 text-emerald-100/50 truncate max-w-[200px]" title={obs.subject}>{obs.subject}</td>
                      <td className="px-4 py-3 text-emerald-50">{obs.observation}</td>
                    </tr>
                  ))}
                  {evidence.length === 0 && (
                    <tr>
                      <td colSpan={3} className="px-4 py-8 text-center text-emerald-100/40">
                        No evidence recorded for this scan.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}
