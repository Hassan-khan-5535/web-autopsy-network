"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import {
  getScan,
  getScanEvidence,
  getScanPages,
  getScanTechnologies,
  getScanArchitecture,
  getScanDependencies,
  getScanApiEndpoints,
  getScanPageRendered,
  type CrawledPage,
  type TechnologyDetection,
  type ObservationResponse,
  type ScanResponse,
  type SiteArchitecture,
  type DependencyItem,
  type ApiEndpointItem,
  type PageRenderedResponse,
} from "@/lib/api";
import DependencyGraph from "@/components/DependencyGraph";

export default function ScanResultPage() {
  const params = useParams();
  const id = params.id as string;

  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [pages, setPages] = useState<CrawledPage[]>([]);
  const [technologies, setTechnologies] = useState<TechnologyDetection[]>([]);
  const [evidence, setEvidence] = useState<ObservationResponse[]>([]);
  const [architecture, setArchitecture] = useState<SiteArchitecture | null>(null);
  const [dependencies, setDependencies] = useState<DependencyItem[]>([]);
  const [apiEndpoints, setApiEndpoints] = useState<ApiEndpointItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [selectedPageId, setSelectedPageId] = useState<string | null>(null);
  const [pageRenderedData, setPageRenderedData] = useState<PageRenderedResponse | null>(null);
  const [modalLoading, setModalLoading] = useState(false);
  const [activeDomTab, setActiveDomTab] = useState<"rendered" | "raw" | "network" | "console">("rendered");


  useEffect(() => {
    let mounted = true;

    async function loadData() {
      try {
        const scanData = await getScan(id);
        if (!mounted) return;
        setScan(scanData);

        if (scanData.state === "COMPLETED" || scanData.state === "FAILED") {
          const [pagesData, technologiesData, evidenceData, archData, depsData, apiData] = await Promise.all([
            getScanPages(id).catch(() => []),
            getScanTechnologies(id).catch(() => []),
            getScanEvidence(id).catch(() => []),
            getScanArchitecture(id).catch(() => null),
            getScanDependencies(id).catch(() => []),
            getScanApiEndpoints(id).catch(() => []),
          ]);

          if (mounted) {
            setPages(pagesData);
            setTechnologies(technologiesData);
            setEvidence(evidenceData);
            setArchitecture(archData);
            setDependencies(depsData);
            setApiEndpoints(apiData);
          }
        }
      } catch (err: unknown) {
        if (mounted) setError(err instanceof Error ? err.message : "Failed to load scan data");
      } finally {
        if (mounted) setLoading(false);
      }
    }

    loadData();
    return () => {
      mounted = false;
    };
  }, [id]);

  if (loading) {
    return (
      <main className="min-h-screen flex items-center justify-center bg-[#08110f] text-[#ecf4ee]">
        <div className="animate-pulse flex items-center gap-3">
          <div className="h-3 w-3 bg-emerald-400 rounded-full" />
          <p className="text-emerald-400/80 font-mono text-sm tracking-widest">LOADING AUTOPSY EVIDENCE...</p>
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
          <Link href="/scans" className="text-emerald-500 hover:text-emerald-400 text-sm font-medium">
            &larr; Return to Scanner
          </Link>
        </div>
      </main>
    );
  }

  const isFailed = scan.state === "FAILED";
  const isCompleted = scan.state === "COMPLETED";

  return (
    <main className="min-h-screen bg-[#08110f] text-[#ecf4ee] px-6 py-12 sm:px-10">
      <div className="max-w-6xl mx-auto space-y-10">
        {/* Header */}
        <header className="flex items-start justify-between border-b border-emerald-100/10 pb-8">
          <div>
            <div className="flex items-center gap-3 mb-3">
              <span
                className={`px-2.5 py-1 text-xs font-mono font-medium rounded border ${
                  isCompleted
                    ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                    : isFailed
                    ? "bg-red-500/10 text-red-400 border-red-500/20"
                    : "bg-amber-500/10 text-amber-400 border-amber-500/20"
                }`}
              >
                {scan.state}
              </span>
              <p className="text-xs text-emerald-100/40 font-mono">{scan.id}</p>
            </div>
            <h1 className="text-3xl font-semibold tracking-tight truncate max-w-2xl" title={scan.requested_url}>
              {scan.requested_url}
            </h1>
            <p className="mt-2 text-sm text-emerald-100/50">
              Bounded crawl: depth {scan.max_depth}, up to {scan.max_pages} pages.
            </p>
          </div>
          <Link href="/scans" className="text-emerald-500 hover:text-emerald-400 text-sm font-medium">
            New Scan &rarr;
          </Link>
        </header>

        {isFailed && (
          <section className="bg-red-500/5 border border-red-500/10 rounded-2xl p-6">
            <h3 className="text-red-400 font-semibold mb-2">Collection Failed</h3>
            <p className="text-red-200/70 text-sm font-mono whitespace-pre-wrap">{scan.error_reason}</p>
          </section>
        )}

        {/* Phase 5 Interactive Dependency Graph */}
        {(isCompleted || isFailed) && dependencies.length > 0 && (
          <section>
            <DependencyGraph dependencies={dependencies} targetUrl={scan.requested_url} evidence={evidence} />
          </section>
        )}

        {/* Phase 5 Site Architecture Section */}
        {(isCompleted || isFailed) && architecture && (
          <section className="space-y-6 bg-[#0b1714] border border-emerald-900/30 rounded-2xl p-6">
            <div className="flex items-end justify-between border-b border-emerald-900/20 pb-4">
              <div>
                <h2 className="text-xl font-semibold text-emerald-400 flex items-center gap-2">
                  <span>🏛️</span> Site Architecture & Structure
                </h2>
                <p className="mt-1 text-sm text-emerald-100/50">
                  Page hierarchy, navigational link counts, and observational form inventory.
                </p>
              </div>
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="bg-emerald-950 px-2.5 py-1 rounded text-emerald-400 border border-emerald-800/40">
                  {architecture.link_summary.total_internal_links} Internal Links
                </span>
                <span className="bg-emerald-950 px-2.5 py-1 rounded text-emerald-400 border border-emerald-800/40">
                  {architecture.link_summary.total_external_links} External Links
                </span>
              </div>
            </div>

            {/* Inferred Page Types */}
            {architecture.page_types && architecture.page_types.length > 0 && (
              <div className="space-y-3">
                <h3 className="text-sm font-semibold text-emerald-300">Page Type Heuristics (🟡 INFERRED)</h3>
                <div className="grid gap-3 md:grid-cols-2">
                  {architecture.page_types.map((item) => (
                    <div key={item.page_id} className="bg-[#050b09] border border-emerald-900/30 rounded-xl p-4 text-xs space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-emerald-300 truncate max-w-[220px]" title={item.url}>{item.url}</span>
                        <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono text-[10px] font-semibold">
                          {item.inferred_type}
                        </span>
                      </div>
                      <p className="text-emerald-100/60">{item.reason}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Form Inventory */}
            {architecture.form_inventory && architecture.form_inventory.length > 0 && (
              <div className="space-y-3 pt-4 border-t border-emerald-900/20">
                <h3 className="text-sm font-semibold text-emerald-300 flex items-center justify-between">
                  <span>Discovered HTML Forms Inventory</span>
                  <span className="text-xs font-mono text-emerald-500/70">{architecture.form_inventory.length} FORMS</span>
                </h3>
                <div className="overflow-hidden rounded-xl border border-emerald-900/30 bg-[#050b09]">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-emerald-950/60 font-mono text-emerald-400/60">
                      <tr>
                        <th className="px-4 py-2.5 font-medium">METHOD</th>
                        <th className="px-4 py-2.5 font-medium">ACTION TARGET</th>
                        <th className="px-4 py-2.5 font-medium">PAGE URL</th>
                        <th className="px-4 py-2.5 font-medium">OBSERVED FIELDS</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-emerald-900/20 font-mono">
                      {architecture.form_inventory.map((form, idx) => (
                        <tr key={idx} className="hover:bg-emerald-900/10">
                          <td className="px-4 py-2.5 whitespace-nowrap text-emerald-400 font-bold">{form.method}</td>
                          <td className="px-4 py-2.5 text-emerald-200 max-w-[240px] truncate" title={form.action}>{form.action}</td>
                          <td className="px-4 py-2.5 text-emerald-100/50 max-w-[200px] truncate" title={form.page_url}>{form.page_url}</td>
                          <td className="px-4 py-2.5 text-emerald-300">
                            {form.fields.map((f) => f.name || f.type).join(", ") || "No named fields"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </section>
        )}

        {/* Phase 5 API Endpoints Catalog */}
        {(isCompleted || isFailed) && apiEndpoints.length > 0 && (
          <section className="space-y-4 bg-[#0b1714] border border-emerald-900/30 rounded-2xl p-6">
            <div className="flex items-end justify-between border-b border-emerald-900/20 pb-4">
              <div>
                <h2 className="text-xl font-semibold text-emerald-400 flex items-center gap-2">
                  <span>🔌</span> API Intelligence Catalog (🟡 INFERRED)
                </h2>
                <p className="mt-1 text-sm text-emerald-100/50">
                  Statically identified API routes and methods from stored page text, scripts, and forms (0 network calls made).
                </p>
              </div>
              <span className="text-xs font-mono bg-emerald-950 px-2.5 py-1 rounded text-emerald-400 border border-emerald-800/40">
                {apiEndpoints.length} ENDPOINTS
              </span>
            </div>

            <div className="overflow-hidden rounded-xl border border-emerald-900/30 bg-[#050b09]">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-emerald-950/60 text-emerald-400/60">
                  <tr>
                    <th className="px-4 py-3 font-medium">METHOD</th>
                    <th className="px-4 py-3 font-medium">URL / PATH</th>
                    <th className="px-4 py-3 font-medium">CONTENT TYPE</th>
                    <th className="px-4 py-3 font-medium">DISCOVERY SOURCE</th>
                    <th className="px-4 py-3 font-medium">CONFIDENCE</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-emerald-900/20">
                  {apiEndpoints.map((ep) => (
                    <tr key={ep.id} className="hover:bg-emerald-900/10 transition-colors">
                      <td className="px-4 py-3 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                          ep.http_method === "POST" ? "bg-amber-500/10 text-amber-400 border border-amber-500/20" :
                          ep.http_method === "GET" ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" :
                          "bg-purple-500/10 text-purple-400 border border-purple-500/20"
                        }`}>
                          {ep.http_method}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-emerald-200 truncate max-w-[280px]" title={ep.url_or_path}>
                        {ep.url_or_path}
                      </td>
                      <td className="px-4 py-3 text-emerald-100/50">{ep.content_type || "—"}</td>
                      <td className="px-4 py-3 text-emerald-100/60 truncate max-w-[220px]" title={ep.discovered_from_source}>
                        {ep.discovered_from_source}
                      </td>
                      <td className="px-4 py-3 text-emerald-400 font-semibold">{Math.round(ep.confidence * 100)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* Existing Technology DNA Section */}
        {(isCompleted || isFailed) && (
          <section className="space-y-4">
            <div className="flex items-end justify-between">
              <div>
                <h2 className="text-xl font-semibold">Technology DNA</h2>
                <p className="mt-1 text-sm text-emerald-100/50">
                  Deterministic, evidence-backed fingerprints from stored static HTML, headers, and resources.
                </p>
              </div>
              <span className="text-xs font-mono bg-white/5 px-2 py-0.5 rounded text-emerald-100/50">
                {technologies.length} DETECTIONS
              </span>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              {technologies.map((technology) => (
                <details key={technology.id} className="rounded-xl border border-white/5 bg-black/20 p-5 group">
                  <summary className="cursor-pointer list-none">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <p className="text-lg font-semibold text-emerald-50">{technology.name}</p>
                        <p className="mt-1 text-xs uppercase tracking-wider text-emerald-100/45">
                          {technology.category.replaceAll("_", " ")} · {technology.classification}
                        </p>
                      </div>
                      <span
                        className={`shrink-0 rounded-full px-2.5 py-1 text-xs font-mono ${
                          technology.confidence_band === "high"
                            ? "bg-emerald-500/15 text-emerald-300"
                            : technology.confidence_band === "medium"
                            ? "bg-amber-500/15 text-amber-300"
                            : "bg-slate-500/15 text-slate-300"
                        }`}
                      >
                        {Math.round(technology.confidence)}% {technology.confidence_band}
                      </span>
                    </div>
                  </summary>
                  <div className="mt-4 space-y-3 border-t border-white/5 pt-4">
                    <p className="text-xs text-emerald-100/45">
                      Ruleset {technology.rule_version}. Confidence combines unique matched rule weights plus a small corroboration bonus for independent signals.
                    </p>
                    {technology.evidence.map((item) => (
                      <div key={item.id} className="rounded-lg bg-white/[0.03] p-3 text-sm">
                        <div className="flex items-center justify-between gap-3 text-xs text-emerald-100/45">
                          <span>
                            {item.type} · {item.match_rule}
                          </span>
                          <span>+{item.weight}</span>
                        </div>
                        <p className="mt-1 break-words text-emerald-50/85">{item.observation}</p>
                        <p className="mt-1 break-all text-xs text-emerald-100/40">Source: {item.source}</p>
                      </div>
                    ))}
                  </div>
                </details>
              ))}
              {technologies.length === 0 && (
                <div className="md:col-span-2 rounded-xl border border-white/5 bg-black/20 px-5 py-8 text-center text-emerald-100/45">
                  No technology signals were detected from the stored static evidence.
                </div>
              )}
            </div>
          </section>
        )}

        {/* Existing Crawled Pages Table */}
        {(isCompleted || isFailed) && (
          <section className="space-y-4">
            <div className="flex items-end justify-between">
              <div>
                <h2 className="text-xl font-semibold">Crawled Pages</h2>
                <p className="mt-1 text-sm text-emerald-100/50">
                  Static HTML pages fetched after same-domain, robots, and SSRF checks.
                </p>
              </div>
              <span className="text-xs font-mono bg-white/5 px-2 py-0.5 rounded text-emerald-100/50">
                {pages.length} PAGES
              </span>
            </div>
            <div className="overflow-hidden rounded-xl border border-white/5 bg-black/20">
              <table className="w-full text-left text-sm">
                <thead className="bg-white/5 font-mono text-xs text-emerald-100/40">
                  <tr>
                    <th className="px-4 py-3 font-medium">DEPTH</th>
                    <th className="px-4 py-3 font-medium">STATUS</th>
                    <th className="px-4 py-3 font-medium">PAGE</th>
                    <th className="px-4 py-3 font-medium">DISCOVERED FROM</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {pages.map((page) => (
                    <tr key={page.id} className="hover:bg-white/[0.02] transition-colors">
                      <td className="px-4 py-3 whitespace-nowrap text-emerald-200/70">{page.depth}</td>
                      <td className="px-4 py-3 whitespace-nowrap text-emerald-200/70">{page.status_code ?? "—"}</td>
                      <td className="px-4 py-3 text-emerald-50 max-w-[360px] truncate" title={page.url}>
                        <div className="flex items-center gap-2">
                          <span>{page.title || page.url}</span>
                          <button
                            onClick={async () => {
                              setSelectedPageId(page.id);
                              setModalLoading(true);
                              try {
                                const data = await getScanPageRendered(id, page.id);
                                setPageRenderedData(data);
                              } catch (e) {
                                console.error(e);
                              } finally {
                                setModalLoading(false);
                              }
                            }}
                            className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/30 transition-colors cursor-pointer"
                          >
                            Inspect DOM
                          </button>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-emerald-100/50 max-w-[300px] truncate" title={page.discovered_from || undefined}>
                        {page.discovered_from || "Seed URL"}
                      </td>
                    </tr>
                  ))}
                  {pages.length === 0 && (
                    <tr>
                      <td colSpan={4} className="px-4 py-8 text-center text-emerald-100/40">
                        No pages were persisted.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* Browser Analysis DOM Inspector Modal */}
        {selectedPageId && (
          <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-emerald-500/30 rounded-xl w-full max-w-4xl max-h-[85vh] overflow-hidden flex flex-col shadow-2xl">
              <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 bg-white/5">
                <div className="flex items-center gap-3">
                  <h3 className="font-semibold text-lg text-emerald-400">Browser Analysis & Rendered DOM</h3>
                  <span className="text-xs font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2 py-0.5 rounded">🟢 OBSERVED</span>
                </div>
                <button
                  onClick={() => {
                    setSelectedPageId(null);
                    setPageRenderedData(null);
                  }}
                  className="text-emerald-100/50 hover:text-white font-mono text-sm"
                >
                  [CLOSE ✕]
                </button>
              </div>

              <div className="p-6 overflow-y-auto space-y-6 flex-1 text-sm">
                {modalLoading ? (
                  <div className="py-12 text-center text-emerald-100/50 animate-pulse font-mono">
                    Loading Rendered DOM & Browser Events...
                  </div>
                ) : pageRenderedData ? (
                  <div className="space-y-6">
                    <div>
                      <div className="text-xs font-mono text-emerald-100/40 uppercase mb-1">Target Page URL</div>
                      <div className="font-mono text-emerald-300 break-all bg-black/40 p-2.5 rounded border border-white/5">{pageRenderedData.url}</div>
                    </div>

                    {/* Navigation Timing */}
                    {Boolean(pageRenderedData.timing_data?.navigation) && (
                      <div>
                        <div className="text-xs font-mono text-emerald-100/40 uppercase mb-2">Browser Performance Navigation Timing</div>
                        <div className="grid grid-cols-3 gap-3">
                          <div className="bg-black/30 p-3 rounded border border-white/5">
                            <div className="text-xs text-emerald-100/50">DOM Interactive</div>
                            <div className="text-lg font-mono text-emerald-400">
                              {(pageRenderedData.timing_data?.navigation as Record<string, number>)?.domInteractive ?? 0} ms
                            </div>
                          </div>
                          <div className="bg-black/30 p-3 rounded border border-white/5">
                            <div className="text-xs text-emerald-100/50">DOM Complete</div>
                            <div className="text-lg font-mono text-emerald-400">
                              {(pageRenderedData.timing_data?.navigation as Record<string, number>)?.domComplete ?? 0} ms
                            </div>
                          </div>
                          <div className="bg-black/30 p-3 rounded border border-white/5">
                            <div className="text-xs text-emerald-100/50">Load Event End</div>
                            <div className="text-lg font-mono text-emerald-400">
                              {(pageRenderedData.timing_data?.navigation as Record<string, number>)?.loadEventEnd ?? 0} ms
                            </div>
                          </div>
                        </div>
                      </div>
                    )}


                    {/* DOM HTML Tabs */}
                    <div>
                      <div className="flex border-b border-white/10 gap-4 font-mono text-xs mb-3">
                        <button
                          onClick={() => setActiveDomTab("rendered")}
                          className={`pb-2 border-b-2 transition-colors ${activeDomTab === "rendered" ? "border-emerald-400 text-emerald-400" : "border-transparent text-emerald-100/50 hover:text-emerald-100"}`}
                        >
                          Post-JS Rendered DOM ({pageRenderedData.rendered_body ? `${pageRenderedData.rendered_body.length} bytes` : "None"})
                        </button>
                        <button
                          onClick={() => setActiveDomTab("raw")}
                          className={`pb-2 border-b-2 transition-colors ${activeDomTab === "raw" ? "border-emerald-400 text-emerald-400" : "border-transparent text-emerald-100/50 hover:text-emerald-100"}`}
                        >
                          Static Raw HTML ({pageRenderedData.raw_body ? `${pageRenderedData.raw_body.length} bytes` : "None"})
                        </button>
                        <button
                          onClick={() => setActiveDomTab("network")}
                          className={`pb-2 border-b-2 transition-colors ${activeDomTab === "network" ? "border-emerald-400 text-emerald-400" : "border-transparent text-emerald-100/50 hover:text-emerald-100"}`}
                        >
                          Captured Resources ({pageRenderedData.resources.length})
                        </button>
                        <button
                          onClick={() => setActiveDomTab("console")}
                          className={`pb-2 border-b-2 transition-colors ${activeDomTab === "console" ? "border-emerald-400 text-emerald-400" : "border-transparent text-emerald-100/50 hover:text-emerald-100"}`}
                        >
                          Console Logs ({pageRenderedData.console_logs.length})
                        </button>
                      </div>

                      {activeDomTab === "rendered" && (
                        <textarea
                          readOnly
                          value={pageRenderedData.rendered_body || "No rendered DOM captured."}
                          className="w-full h-64 bg-black/60 font-mono text-xs text-emerald-200/80 p-4 rounded border border-white/5 focus:outline-none resize-none"
                        />
                      )}

                      {activeDomTab === "raw" && (
                        <textarea
                          readOnly
                          value={pageRenderedData.raw_body || "No raw static HTML captured."}
                          className="w-full h-64 bg-black/60 font-mono text-xs text-emerald-200/80 p-4 rounded border border-white/5 focus:outline-none resize-none"
                        />
                      )}

                      {activeDomTab === "network" && (
                        <div className="max-h-64 overflow-y-auto border border-white/5 rounded bg-black/40">
                          <table className="w-full text-xs text-left">
                            <thead className="bg-white/5 font-mono text-emerald-100/50">
                              <tr>
                                <th className="p-2 font-medium">SOURCE</th>
                                <th className="p-2 font-medium">TYPE</th>
                                <th className="p-2 font-medium">RESOURCE URL</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-white/5 font-mono">
                              {pageRenderedData.resources.map((res) => (
                                <tr key={res.id}>
                                  <td className="p-2">
                                    <span className={`px-1.5 py-0.5 text-[10px] rounded ${res.capture_source === "browser_runtime" ? "bg-purple-500/20 text-purple-300 border border-purple-500/30" : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"}`}>
                                      {res.capture_source}
                                    </span>
                                  </td>
                                  <td className="p-2 text-emerald-200">{res.type}</td>
                                  <td className="p-2 text-emerald-100/60 truncate max-w-md" title={res.url}>{res.url}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}

                      {activeDomTab === "console" && (
                        <div className="max-h-64 overflow-y-auto border border-white/5 rounded bg-black/40 p-3 font-mono text-xs space-y-2">
                          {pageRenderedData.console_logs.map((log) => (
                            <div key={log.id} className="flex gap-2">
                              <span className="text-amber-400 font-semibold">[{log.type.toUpperCase()}]</span>
                              <span className="text-emerald-100/80">{log.text}</span>
                            </div>
                          ))}
                          {pageRenderedData.console_logs.length === 0 && (
                            <div className="text-emerald-100/40 text-center py-4">No browser console warnings or errors logged.</div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="py-8 text-center text-rose-400 font-mono">Failed to load page render data.</div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Existing Raw Evidence Section */}
        {isCompleted && (
          <section className="space-y-4">
            <h2 className="text-xl font-semibold flex items-center gap-2">
              <span className="text-emerald-400">Raw Evidence</span>
              <span className="text-xs font-mono bg-white/5 px-2 py-0.5 rounded text-emerald-100/50">
                {evidence.length} OBSERVATIONS
              </span>
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
                      <td className="px-4 py-3 text-emerald-100/50 truncate max-w-[200px]" title={obs.subject}>
                        {obs.subject}
                      </td>
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

