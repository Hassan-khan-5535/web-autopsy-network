"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowUpRight, Command, FileSearch, Network, ShieldCheck, Sparkles } from "lucide-react";
import { HealthIndicator } from "@/components/health-indicator";
import { PlatformPulse } from "@/components/platform-pulse";

const principles = [
  { label: "Observed", icon: FileSearch, color: "text-emerald-300", dot: "bg-emerald-300", copy: "Directly measured HTTP, DOM, DNS, browser, and network evidence." },
  { label: "Inferred", icon: Network, color: "text-amber-200", dot: "bg-amber-300", copy: "Deterministic conclusions built from multiple persisted observations." },
  { label: "AI interpreted", icon: Sparkles, color: "text-cyan-200", dot: "bg-cyan-300", copy: "Citation-grounded reasoning that never replaces evidence quality." },
  { label: "Unknown", icon: ShieldCheck, color: "text-slate-300", dot: "bg-slate-300", copy: "Explicitly marked when a behavior cannot be observed externally." },
];

export default function Home() {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLaunchScan = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const target = url.trim();
    if (!target) return;
    setLoading(true);
    router.push(`/scans?url=${encodeURIComponent(target)}`);
  };

  return (
    <main className="min-h-screen overflow-hidden px-4 py-4 text-[var(--text)] sm:px-6 lg:px-8">
      <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden" aria-hidden="true">
        <div className="absolute -left-32 top-24 h-80 w-80 rounded-full bg-emerald-400/10 blur-3xl" />
        <div className="absolute right-0 top-0 h-[28rem] w-[28rem] rounded-full bg-cyan-400/10 blur-3xl" />
      </div>

      <div className="relative z-10 mx-auto max-w-[1380px]">
        <header className="glass-panel flex flex-col gap-4 rounded-2xl px-5 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <Link href="/" className="group flex items-center gap-3" aria-label="Web Autopsy Network home">
            <span className="grid h-11 w-11 place-items-center rounded-xl border border-emerald-200/25 bg-emerald-200/10 font-mono text-xs font-medium text-emerald-200 transition group-hover:border-emerald-200/60">WAN</span>
            <span><strong className="block text-sm tracking-wide text-emerald-50">Web Autopsy Network</strong><span className="mono block text-[10px] uppercase tracking-[0.16em] text-emerald-100/45">Forensic web intelligence</span></span>
          </Link>
          <nav className="flex flex-wrap items-center gap-2 text-xs" aria-label="Primary navigation">
            <Link href="/scans" className="rounded-lg px-3 py-2 text-emerald-100/65 transition hover:bg-white/5 hover:text-emerald-50">Scan history</Link>
            <Link href="/architecture/system" className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-300/20 bg-cyan-300/5 px-3 py-2 text-cyan-100/80 transition hover:border-cyan-300/45 hover:bg-cyan-300/10">System architecture <ArrowUpRight className="h-3.5 w-3.5" /></Link>
          </nav>
        </header>

        <section className="grid gap-8 pb-10 pt-14 lg:grid-cols-[minmax(0,1.15fr)_minmax(350px,0.85fr)] lg:items-end lg:pt-20">
          <div>
            <div className="eyebrow inline-flex items-center gap-2 rounded-full border border-emerald-200/20 bg-emerald-200/5 px-3 py-2"><span className="h-1.5 w-1.5 rounded-full bg-emerald-300 shadow-[0_0_12px_rgba(114,240,197,0.9)]" /> Evidence-first assessment platform</div>
            <h1 className="mt-7 max-w-4xl text-5xl font-semibold leading-[0.98] tracking-[-0.06em] text-balance sm:text-7xl lg:text-[clamp(4.5rem,7.5vw,7.5rem)]">See the web<br /><span className="bg-gradient-to-r from-emerald-200 via-teal-200 to-cyan-300 bg-clip-text text-transparent">under the surface.</span></h1>
            <p className="mt-7 max-w-2xl text-base leading-7 text-emerald-50/65 sm:text-lg">Collect real, bounded evidence. Trace how a target behaves. Turn observations into an explainable security, performance, and architecture report.</p>

            <form onSubmit={handleLaunchScan} className="glass-panel mt-9 flex max-w-3xl flex-col gap-2 rounded-2xl p-2 sm:flex-row" aria-label="Start an authorized assessment">
              <label htmlFor="hero-target" className="sr-only">Target website URL</label>
              <input id="hero-target" type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://target-website.com" required className="glass-input min-h-12 min-w-0 flex-1 rounded-xl px-4 font-mono text-sm placeholder:text-emerald-100/30" />
              <button type="submit" disabled={loading} className="glass-button inline-flex min-h-12 items-center justify-center gap-2 rounded-xl px-5 text-sm font-semibold">
                <Command className="h-4 w-4" /> {loading ? "Opening workspace…" : "Start assessment"}
              </button>
            </form>
            <p className="mt-3 flex items-start gap-2 text-xs leading-5 text-emerald-100/45"><ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-300/70" /> Authorization, scope, rate limits, and non-destructive policy are recorded before collection begins.</p>
          </div>

          <aside className="glass-panel-subtle relative overflow-hidden rounded-3xl p-6 sm:p-7">
            <div className="absolute right-5 top-5 h-20 w-20 rounded-full bg-cyan-300/10 blur-2xl" aria-hidden="true" />
            <p className="eyebrow">Assessment loop</p>
            <h2 className="mt-3 text-2xl font-semibold tracking-tight text-emerald-50">From URL to evidence graph.</h2>
            <div className="mt-7 space-y-4">
              {[["01", "Admit", "Validate authorization and egress scope."], ["02", "Collect", "Persist bounded HTTP and browser observations."], ["03", "Analyze", "Run deterministic agents with evidence gates."], ["04", "Explain", "Synthesize risk, diagnosis, and remediation."]].map(([number, title, copy]) => <div key={number} className="flex gap-4"><span className="mono grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-cyan-200/20 bg-cyan-200/5 text-[10px] text-cyan-200/80">{number}</span><div><p className="text-sm font-semibold text-emerald-100">{title}</p><p className="mt-0.5 text-xs leading-5 text-emerald-100/50">{copy}</p></div></div>)}
            </div>
            <Link href="/architecture/system" className="mt-7 inline-flex items-center gap-1 text-xs font-semibold text-cyan-200 transition hover:text-cyan-100">Explore the control plane <ArrowUpRight className="h-3.5 w-3.5" /></Link>
          </aside>
        </section>

        <PlatformPulse />

        <section className="grid gap-3 py-10 sm:grid-cols-2 lg:grid-cols-4" aria-label="Evidence principles">
          {principles.map(({ label, icon: Icon, color, dot, copy }) => <article key={label} className="glass-panel-subtle rounded-2xl p-5 transition duration-200 hover:-translate-y-0.5 hover:border-emerald-200/25"><div className="flex items-center gap-2"><span className={`h-2 w-2 rounded-full ${dot}`} /><Icon className={`h-4 w-4 ${color}`} /><h3 className={`mono text-[11px] font-medium uppercase tracking-[0.16em] ${color}`}>{label}</h3></div><p className="mt-3 text-sm leading-6 text-emerald-100/55">{copy}</p></article>)}
        </section>

        <HealthIndicator />
        <footer className="flex flex-col gap-2 border-t border-white/10 py-6 text-xs text-emerald-100/35 sm:flex-row sm:items-center sm:justify-between"><span>Web Autopsy Network · authorized research only</span><span className="mono">deterministic core · AI optional · no exploit automation</span></footer>
      </div>
    </main>
  );
}
