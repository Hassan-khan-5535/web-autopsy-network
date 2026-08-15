import { HealthIndicator } from "@/components/health-indicator";

export default function Home() {
  return (
    <main className="min-h-screen overflow-hidden bg-[#08110f] text-[#ecf4ee]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_22%_18%,rgba(91,176,121,0.18),transparent_28%),radial-gradient(circle_at_82%_82%,rgba(30,93,150,0.17),transparent_30%)]" />
      <section className="relative mx-auto flex min-h-screen w-full max-w-6xl flex-col justify-between px-6 py-8 sm:px-10 lg:px-14">
        <header className="flex items-center justify-between border-b border-emerald-100/10 pb-6">
          <div className="flex items-center gap-3">
            <span className="grid h-10 w-10 place-items-center rounded-xl border border-emerald-300/30 bg-emerald-300/10 font-mono text-sm text-emerald-200">WAN</span>
            <div>
              <p className="text-sm font-semibold tracking-wide">Web Autopsy Network</p>
              <p className="text-xs text-emerald-100/55">Phase 1 · Foundation</p>
            </div>
          </div>
          <span className="rounded-full border border-emerald-300/20 bg-emerald-300/10 px-3 py-1 text-xs font-medium text-emerald-100">Evidence-first</span>
        </header>

        <div className="max-w-3xl py-20">
          <p className="mb-5 font-mono text-sm tracking-[0.2em] text-emerald-300/80">SYSTEM FOUNDATION ONLINE</p>
          <h1 className="max-w-3xl text-5xl font-semibold tracking-[-0.05em] text-balance sm:text-7xl">Dissect any website.<br /><span className="text-emerald-300">Understand how it works.</span></h1>
          <p className="mt-7 max-w-2xl text-lg leading-8 text-emerald-50/65">The Phase 1 foundation connects the interface to a typed FastAPI control plane, with database-aware health checks, structured logs, migration tooling, and future-ready boundaries.</p>
        </div>

        <HealthIndicator />
      </section>
    </main>
  );
}
