"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { HealthIndicator } from "@/components/health-indicator";
import { PlatformPulse } from "@/components/platform-pulse";

export default function Home() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLaunchScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    router.push(`/scans?url=${encodeURIComponent(url.trim())}`);
  };

  return (
    <main className="min-h-screen overflow-hidden bg-[#08110f] text-[#ecf4ee] relative selection:bg-emerald-500/30">
      {/* Dynamic Background Glows */}
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_22%_18%,rgba(91,176,121,0.18),transparent_35%),radial-gradient(circle_at_82%_82%,rgba(30,93,150,0.17),transparent_40%)]" />

      <section className="relative mx-auto flex min-h-screen w-full max-w-6xl flex-col justify-between px-6 py-8 sm:px-10 lg:px-14">
        {/* Navigation Header */}
        <header className="flex items-center justify-between border-b border-emerald-100/10 pb-6">
          <div className="flex items-center gap-3">
            <span className="grid h-10 w-10 place-items-center rounded-xl border border-emerald-300/30 bg-emerald-300/10 font-mono text-sm text-emerald-200 shadow-inner">
              WAN
            </span>
            <div>
              <p className="text-sm font-semibold tracking-wide">Web Autopsy Network</p>
              <p className="text-xs text-emerald-100/55 font-mono">Forensic Web Intelligence Workstation</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            <Link
              href="/architecture/system"
              className="text-xs font-mono text-emerald-300/80 hover:text-emerald-200 transition-colors"
            >
              System Architecture &rarr;
            </Link>
            <span className="rounded-full border border-emerald-300/20 bg-emerald-300/10 px-3 py-1 text-xs font-medium text-emerald-100">
              Extension 15 · Continuous Security
            </span>
          </div>
        </header>

        {/* Hero Section */}
        <div className="max-w-4xl py-16">
          <div className="inline-flex items-center gap-2 mb-6 px-3 py-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 font-mono text-xs tracking-wider">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
            DISTRIBUTED DIGITAL FORENSICS PLATFORM
          </div>

          <h1 className="text-5xl font-semibold tracking-[-0.05em] text-balance sm:text-7xl leading-tight">
            Dissect any website.<br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-300 via-teal-200 to-cyan-400">
              Understand how it works.
            </span>
          </h1>

          <p className="mt-6 max-w-2xl text-lg leading-8 text-emerald-50/70">
            Collect observable HTTP evidence, execute sandboxed browser telemetry, analyze security/performance bottlenecks, and produce evidence-backed forensic autopsy reports.
          </p>

          {/* Interactive URL Admission Launcher */}
          <form onSubmit={handleLaunchScan} className="mt-8 flex flex-col sm:flex-row items-center gap-3 max-w-2xl">
            <div className="relative w-full">
              <input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://target-website.com"
                required
                className="w-full h-13 px-4 rounded-xl bg-[#0d1c19] border border-emerald-500/30 text-emerald-100 placeholder:text-emerald-100/30 focus:outline-none focus:ring-2 focus:ring-emerald-400 text-sm font-mono"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full sm:w-auto h-13 px-8 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-emerald-950 font-medium text-sm transition-all shadow-lg shadow-emerald-500/20 whitespace-nowrap"
            >
              {loading ? "Initializing..." : "Dissect Target"}
            </button>
          </form>

          <p className="mt-4 text-xs font-mono text-emerald-100/60">
            Submit only a website you are authorized to assess. Every report is generated from a persisted real scan ID.
          </p>
        </div>

        <PlatformPulse />

        {/* 10-Second Concept Legend: 🟢 🟡 🔵 ⚫ */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 py-8 border-t border-emerald-100/10">
          <div className="p-4 rounded-2xl bg-[#0c1815] border border-emerald-500/20 hover:border-emerald-500/40 transition-colors">
            <div className="flex items-center gap-2 mb-2">
              <span className="h-3 w-3 rounded-full bg-emerald-400 shadow-sm shadow-emerald-400" />
              <h3 className="font-mono text-xs font-bold tracking-wider text-emerald-300">OBSERVED</h3>
            </div>
            <p className="text-xs text-emerald-100/60 leading-relaxed">
              Directly measured HTTP headers, DOM structure, DNS records, and network requests.
            </p>
          </div>

          <div className="p-4 rounded-2xl bg-[#0c1815] border border-amber-500/20 hover:border-amber-500/40 transition-colors">
            <div className="flex items-center gap-2 mb-2">
              <span className="h-3 w-3 rounded-full bg-amber-400 shadow-sm shadow-amber-400" />
              <h3 className="font-mono text-xs font-bold tracking-wider text-amber-300">INFERRED</h3>
            </div>
            <p className="text-xs text-amber-100/60 leading-relaxed">
              Technically derived conclusions derived deterministically from multiple observations.
            </p>
          </div>

          <div className="p-4 rounded-2xl bg-[#0c1815] border border-cyan-500/20 hover:border-cyan-500/40 transition-colors">
            <div className="flex items-center gap-2 mb-2">
              <span className="h-3 w-3 rounded-full bg-cyan-400 shadow-sm shadow-cyan-400" />
              <h3 className="font-mono text-xs font-bold tracking-wider text-cyan-300">AI INTERPRETATION</h3>
            </div>
            <p className="text-xs text-cyan-100/60 leading-relaxed">
              LLM diagnostic reasoning strictly citation-grounded to validated evidence IDs.
            </p>
          </div>

          <div className="p-4 rounded-2xl bg-[#0c1815] border border-slate-500/20 hover:border-slate-500/40 transition-colors">
            <div className="flex items-center gap-2 mb-2">
              <span className="h-3 w-3 rounded-full bg-slate-500" />
              <h3 className="font-mono text-xs font-bold tracking-wider text-slate-400">UNKNOWN</h3>
            </div>
            <p className="text-xs text-slate-100/60 leading-relaxed">
              Unobservable or restricted parameters that cannot be determined externally.
            </p>
          </div>
        </div>

        <HealthIndicator />
      </section>
    </main>
  );
}
