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
  getScanRecon,
  getScanHTTPObservations,
  getScanSecurity,
  getScanConfiguration,
  getScanAPIAgent,
  getScanVulnerabilityAgent,
  getScanSecrets,
  getScanCVEIntelligence,
  getScanPerformance,
  getScanPageRendered,
  getScanAccessibility,
  getScanContent,
  getScanDiagnosis,
  getAssessmentAuthorization,
  type AssessmentAuthorization,
  type CrawledPage,
  type TechnologyDetection,
  type ObservationResponse,
  type ScanResponse,
  type SiteArchitecture,
  type DependencyItem,
  type ApiEndpointItem,
  type ReconResponse,
  type HTTPObservationResponse,
  type PageRenderedResponse,
  type SecurityFinding,
  type ConfigurationResponse,
  type APIAgentResponse,
  type VulnerabilityResponse,
  type SecretsResponse,
  type CVEIntelligenceResponse,
  type PerformanceResponse,
  type AccessibilityFinding,
  type ContentFinding,
  type CauseOfDeathDiagnosis,
} from "@/lib/api";
import DependencyGraph from "@/components/DependencyGraph";
import { AIDoctor } from "@/components/ai-doctor";
import { HistoryPanel } from "@/components/history-panel";
import { CauseOfDeath } from "@/components/cause-of-death";
import { ScanProgress } from "@/components/scan-progress";

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
  const [recon, setRecon] = useState<ReconResponse | null>(null);
  const [httpObservations, setHttpObservations] = useState<HTTPObservationResponse | null>(null);
  const [securityFindings, setSecurityFindings] = useState<SecurityFinding[]>([]);
  const [configuration, setConfiguration] = useState<ConfigurationResponse | null>(null);
  const [apiAgent, setApiAgent] = useState<APIAgentResponse | null>(null);
  const [vulnerability, setVulnerability] = useState<VulnerabilityResponse | null>(null);
  const [secrets, setSecrets] = useState<SecretsResponse | null>(null);
  const [cveIntelligence, setCveIntelligence] = useState<CVEIntelligenceResponse | null>(null);
  const [performance, setPerformance] = useState<PerformanceResponse | null>(null);
  const [accessibilityFindings, setAccessibilityFindings] = useState<AccessibilityFinding[]>([]);
  const [contentFindings, setContentFindings] = useState<ContentFinding[]>([]);
  const [diagnosis, setDiagnosis] = useState<CauseOfDeathDiagnosis | null>(null);
  const [assessmentAuthorization, setAssessmentAuthorization] = useState<AssessmentAuthorization | null>(null);
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
        if (!id.startsWith("demo")) {
          const authorizationData = await getAssessmentAuthorization(id).catch(() => null);
          if (mounted) setAssessmentAuthorization(authorizationData);
        }

        if (scanData.state === "COMPLETED" || scanData.state === "PARTIAL_FAILED") {
          const diagnosisData = scanData.diagnosis ?? await getScanDiagnosis(id).catch(() => null);
          if (mounted) setDiagnosis(diagnosisData);
        }

        if (["COMPLETED", "FAILED", "PARTIAL_FAILED", "CANCELLED"].includes(scanData.state)) {
          const [pagesData, technologiesData, evidenceData, archData, depsData, apiData, reconData, httpData, securityData, configurationData, apiAgentData, vulnerabilityData, secretsData, cveIntelligenceData, performanceData, accessData, contentData] = await Promise.all([
            getScanPages(id).catch(() => []),
            getScanTechnologies(id).catch(() => []),
            getScanEvidence(id).catch(() => []),
            getScanArchitecture(id).catch(() => null),
            getScanDependencies(id).catch(() => []),
            getScanApiEndpoints(id).catch(() => []),
            getScanRecon(id).catch(() => null),
            getScanHTTPObservations(id).catch(() => null),
            getScanSecurity(id).catch(() => []),
            getScanConfiguration(id).catch(() => null),
            getScanAPIAgent(id).catch(() => null),
            getScanVulnerabilityAgent(id).catch(() => null),
            getScanSecrets(id).catch(() => null),
            getScanCVEIntelligence(id).catch(() => null),
            getScanPerformance(id).catch(() => null),
            getScanAccessibility(id).catch(() => []),
            getScanContent(id).catch(() => []),
          ]);

          if (mounted) {
            setPages(pagesData);
            setTechnologies(technologiesData);
            setEvidence(evidenceData);
            setArchitecture(archData);
            setDependencies(depsData);
            setApiEndpoints(apiData);
            setRecon(reconData);
            setHttpObservations(httpData);
            setSecurityFindings(securityData);
            setConfiguration(configurationData);
            setApiAgent(apiAgentData);
            setVulnerability(vulnerabilityData);
            setSecrets(secretsData);
            setCveIntelligence(cveIntelligenceData);
            setPerformance(performanceData);
            setAccessibilityFindings(accessData);
            setContentFindings(contentData);
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

  const isFailed = scan.state === "FAILED" || scan.state === "PARTIAL_FAILED";
  const isCompleted = scan.state === "COMPLETED";

  const isDemo = id === "demo-scan-autopsy" || id.startsWith("demo");

  return (
    <main className="min-h-screen bg-[#08110f] text-[#ecf4ee] px-6 py-12 sm:px-10">
      <div className="max-w-6xl mx-auto space-y-10">
        {isDemo && (
          <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4 flex items-center justify-between text-amber-300">
            <div className="flex items-center gap-3">
              <span className="font-mono text-xs px-2 py-0.5 rounded bg-amber-500/20 text-amber-200 border border-amber-500/40">
                SAMPLE DEMO DATA
              </span>
              <p className="text-sm font-medium">
                You are viewing a pre-analyzed demo autopsy report. No live infrastructure was contacted.
              </p>
            </div>
            <Link href="/" className="text-xs underline hover:text-amber-100 font-mono">
              Return Home
            </Link>
          </div>
        )}

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

        {assessmentAuthorization && (
          <section className="rounded-2xl border border-emerald-500/20 bg-[#0b1714] p-6" aria-label="Assessment authorization">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="text-xs font-mono uppercase tracking-wider text-emerald-100/45">Scope &amp; consent record</p>
                <h2 className="mt-1 text-xl font-semibold text-emerald-100">{assessmentAuthorization.assessment_profile}</h2>
                <p className="mt-1 text-sm text-emerald-100/55">Authorized by {assessmentAuthorization.actor_id} on {assessmentAuthorization.authorized_at ? new Date(assessmentAuthorization.authorized_at).toLocaleString() : "—"}</p>
              </div>
              <div className="rounded-lg border border-emerald-500/20 px-3 py-2 text-right"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Consent hash</p><p className="mt-1 font-mono text-sm text-emerald-300">{assessmentAuthorization.consent_hash ? assessmentAuthorization.consent_hash.slice(0, 8) : "legacy"}</p></div>
            </div>
            <div className="mt-5 grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
              <div><p className="text-xs text-emerald-100/40">Allowed domains</p><p className="mt-1 text-emerald-100/75">{assessmentAuthorization.allowed_domains.join(", ") || "Target hostname"}</p></div>
              <div><p className="text-xs text-emerald-100/40">Allowed paths</p><p className="mt-1 text-emerald-100/75">{assessmentAuthorization.allowed_paths.join(", ") || "All paths"}</p></div>
              <div><p className="text-xs text-emerald-100/40">Excluded paths</p><p className="mt-1 text-emerald-100/75">{assessmentAuthorization.excluded_paths.join(", ") || "None"}</p></div>
              <div><p className="text-xs text-emerald-100/40">Limits</p><p className="mt-1 text-emerald-100/75">{assessmentAuthorization.max_requests} requests · {assessmentAuthorization.max_concurrency} workers · {assessmentAuthorization.rate_limit_per_host_ms}ms/host</p></div>
            </div>
            <div className="mt-4 flex flex-wrap gap-2 text-xs text-emerald-100/55"><span className="rounded-full border border-emerald-500/20 px-3 py-1">robots: {assessmentAuthorization.robots_override ? "override authorized" : "respected"}</span><span className="rounded-full border border-emerald-500/20 px-3 py-1">authentication: {assessmentAuthorization.authentication_configured ? `${assessmentAuthorization.authentication_type} configured` : "not configured"}</span><span className="rounded-full border border-emerald-500/20 px-3 py-1">policy {assessmentAuthorization.policy_version}</span></div>
          </section>
        )}

        {!isDemo && <ScanProgress scanId={scan.id} state={scan.state} />}

        {isCompleted && (
          <nav aria-label="Report sections" className="rounded-2xl border border-emerald-900/30 bg-[#0b1714] p-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="mr-2 text-xs font-mono uppercase tracking-wider text-emerald-100/45">Report sections</span>
              {[
                ["cause-of-death", "Cause of Death"], ["ai-doctor", "AI Doctor"], ["history", "History"], ["dependencies", "Dependencies"],
                ["architecture", "Architecture"], ["http-agent", "HTTP Agent"], ["recon", "Recon Agent"], ["api-intelligence", "API Intelligence"], ["api-agent", "API Agent"], ["vulnerability-agent", "Vulnerability Agent"], ["secrets", "Secrets & Sensitive Data"], ["cve-intelligence", "CVE Intelligence"], ["technology-dna", "Technology DNA"], ["performance", "Performance"],
                ["configuration", "Configuration"], ["security", "Security"], ["accessibility", "Accessibility"], ["content-seo", "Content & SEO"], ["raw-evidence", "Raw Evidence"],
              ].map(([anchor, label]) => <a key={anchor} href={`#${anchor}`} className="rounded-full border border-emerald-500/20 px-3 py-1.5 text-xs text-emerald-300 hover:border-emerald-400/50 hover:bg-emerald-500/10">{label}</a>)}
            </div>
          </nav>
        )}

        {isFailed && (
          <section className="bg-red-500/5 border border-red-500/10 rounded-2xl p-6">
            <h3 className="text-red-400 font-semibold mb-2">Collection Failed</h3>
            <p className="text-red-200/70 text-sm font-mono whitespace-pre-wrap">{scan.error_reason}</p>
          </section>
        )}

        {/* Phase 12 Cause of Death */}
        {isCompleted && diagnosis && <CauseOfDeath diagnosis={diagnosis} />}

        {/* AI Doctor Section */}
        {isCompleted && (
          <section id="ai-doctor" className="mb-10">
            <AIDoctor scanId={scan.id} />
          </section>
        )}

        {/* Phase 11 History / Time Machine */}
        {isCompleted && <section id="history"><HistoryPanel websiteId={scan.website_id} currentScanId={scan.id} /></section>}

        {/* Phase 5 Interactive Dependency Graph */}
        {(isCompleted || isFailed) && dependencies.length > 0 && (
          <section id="dependencies">
            <DependencyGraph dependencies={dependencies} targetUrl={scan.requested_url} evidence={evidence} />
          </section>
        )}

        {/* Phase 5 Site Architecture Section */}
        {(isCompleted || isFailed) && architecture && (
          <section id="architecture" className="space-y-6 bg-[#0b1714] border border-emerald-900/30 rounded-2xl p-6">
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

        {/* Extension 3 normalized HTTP Agent catalog */}
        {(isCompleted || isFailed) && httpObservations && (
          <section id="http-agent" className="space-y-5 bg-[#0b1714] border border-blue-900/30 rounded-2xl p-6">
            <div className="flex flex-wrap items-end justify-between gap-4 border-b border-blue-900/20 pb-4">
              <div>
                <h2 className="text-xl font-semibold text-blue-300">HTTP Agent</h2>
                <p className="mt-1 text-sm text-emerald-100/50">Central redacted observations from persisted HTTP behavior; no additional target requests were issued.</p>
              </div>
              <div className="flex gap-2 text-xs font-mono"><span className="rounded border border-blue-500/30 bg-blue-500/10 px-2.5 py-1 text-blue-300">{httpObservations.rule_version}</span><span className="rounded border border-emerald-500/20 px-2.5 py-1 text-emerald-300">{httpObservations.summary.observation_count} observations</span></div>
            </div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><div className="rounded-xl border border-blue-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Types</p><p className="mt-1 text-2xl font-semibold text-blue-200">{Object.keys(httpObservations.summary.types).length}</p></div><div className="rounded-xl border border-blue-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Redacted</p><p className="mt-1 text-2xl font-semibold text-blue-200">{httpObservations.summary.redacted_count}</p></div><div className="rounded-xl border border-blue-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Truncated</p><p className="mt-1 text-2xl font-semibold text-blue-200">{httpObservations.summary.truncated_count}</p></div><div className="rounded-xl border border-blue-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">TLS detail</p><p className="mt-1 text-sm font-semibold text-blue-200">Transport scheme only</p></div></div>
            <div className="flex flex-wrap gap-2 text-xs font-mono">{Object.entries(httpObservations.summary.types).map(([type, count]) => <span key={type} className="rounded-full border border-blue-500/20 px-3 py-1 text-blue-200/80">{type}: {count}</span>)}</div>
            {httpObservations.observations.length > 0 && <div className="overflow-x-auto rounded-xl border border-blue-900/30 bg-[#050b09]"><table className="w-full text-left text-xs font-mono"><thead className="bg-blue-950/40 text-blue-300/70"><tr><th className="px-4 py-3">TYPE</th><th className="px-4 py-3">SUBJECT</th><th className="px-4 py-3">VALUE</th><th className="px-4 py-3">FLAGS</th></tr></thead><tbody className="divide-y divide-blue-900/20">{httpObservations.observations.slice(0, 60).map((item) => <tr key={item.id} className="hover:bg-blue-900/10"><td className="px-4 py-3 text-blue-300">{item.observation_type}</td><td className="max-w-[300px] truncate px-4 py-3 text-emerald-100/70" title={item.subject}>{item.subject}</td><td className="max-w-[520px] truncate px-4 py-3 text-emerald-100/55" title={JSON.stringify(item.value)}>{JSON.stringify(item.value)}</td><td className="px-4 py-3 text-amber-200/80">{item.redacted ? "redacted" : "observed"}{item.truncated ? " · bounded" : ""}</td></tr>)}</tbody></table></div>}
            <p className="text-xs text-emerald-100/45">Header, cookie, URL-query, and redirect values are redacted or normalized before persistence. CORS is response-header observation only; TLS records HTTPS transport but does not perform a second certificate or cipher handshake.</p>
          </section>
        )}

        {/* Extension 2 normalized Recon Agent catalog */}
        {(isCompleted || isFailed) && recon && scan.recon_mode !== "disabled" && (
          <section id="recon" className="space-y-5 bg-[#0b1714] border border-cyan-900/30 rounded-2xl p-6">
            <div className="flex flex-wrap items-end justify-between gap-4 border-b border-cyan-900/20 pb-4">
              <div>
                <h2 className="text-xl font-semibold text-cyan-300">Recon Agent</h2>
                <p className="mt-1 text-sm text-emerald-100/50">Normalized assets, endpoints, and parameters collected from stored evidence and bounded public sources.</p>
              </div>
              <div className="flex gap-2 text-xs font-mono"><span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-1 text-cyan-300">{recon.mode}</span><span className="rounded border border-emerald-500/20 px-2.5 py-1 text-emerald-300">{recon.requests_used}/{recon.max_requests} requests</span></div>
            </div>
            <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
              {[["Assets", recon.summary.asset_count], ["Endpoints", recon.summary.endpoint_count], ["Parameters", recon.summary.parameter_count], ["Subdomains", recon.summary.subdomain_count], ["Cloud candidates", recon.summary.cloud_asset_candidates], ["Classified paths", recon.summary.login_admin_sensitive_count]].map(([label, value]) => <div key={String(label)} className="rounded-xl border border-cyan-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">{label}</p><p className="mt-1 text-2xl font-semibold text-cyan-200">{value}</p></div>)}
            </div>
            {recon.assets.length > 0 && <div className="overflow-x-auto rounded-xl border border-cyan-900/30 bg-[#050b09]"><table className="w-full text-left text-xs font-mono"><thead className="bg-cyan-950/40 text-cyan-300/70"><tr><th className="px-4 py-3">TYPE</th><th className="px-4 py-3">VALUE</th><th className="px-4 py-3">CLASSIFICATION</th><th className="px-4 py-3">SOURCE</th><th className="px-4 py-3">SCOPE</th></tr></thead><tbody className="divide-y divide-cyan-900/20">{recon.assets.slice(0, 40).map((asset) => <tr key={asset.id} className="hover:bg-cyan-900/10"><td className="px-4 py-3 text-cyan-300">{asset.asset_type}</td><td className="max-w-[360px] truncate px-4 py-3 text-emerald-100/80" title={asset.value}>{asset.value}</td><td className="px-4 py-3 text-amber-200/80">{asset.classification}</td><td className="px-4 py-3 text-emerald-100/55">{asset.source}</td><td className="px-4 py-3 text-emerald-100/55">{asset.scope_status}</td></tr>)}</tbody></table></div>}
            {recon.endpoints.length > 0 && <div className="overflow-x-auto rounded-xl border border-cyan-900/30 bg-[#050b09]"><table className="w-full text-left text-xs font-mono"><thead className="bg-cyan-950/40 text-cyan-300/70"><tr><th className="px-4 py-3">KIND</th><th className="px-4 py-3">METHOD</th><th className="px-4 py-3">URL / PATH</th><th className="px-4 py-3">CLASSIFICATION</th><th className="px-4 py-3">STATUS</th></tr></thead><tbody className="divide-y divide-cyan-900/20">{recon.endpoints.slice(0, 40).map((endpoint) => <tr key={endpoint.id} className="hover:bg-cyan-900/10"><td className="px-4 py-3 text-cyan-300">{endpoint.endpoint_kind}</td><td className="px-4 py-3 text-emerald-300">{endpoint.http_method}</td><td className="max-w-[400px] truncate px-4 py-3 text-emerald-100/80" title={endpoint.url_or_path}>{endpoint.url_or_path}</td><td className="px-4 py-3 text-amber-200/80">{endpoint.classification}</td><td className="px-4 py-3 text-emerald-100/55">{endpoint.status_code ?? "—"}</td></tr>)}</tbody></table></div>}
            {recon.parameters.length > 0 && <p className="text-xs text-emerald-100/55">Parameters: {recon.parameters.slice(0, 24).map((parameter) => `${parameter.name} (${parameter.location})`).join(", ")}{recon.parameters.length > 24 ? " …" : ""}</p>}
            <p className="text-xs text-emerald-100/45">Cloud asset candidates are pattern-based observations only; they do not prove public read access. CT and DNS results are passive public-source observations, and active-safe requests are limited to scope-checked GET discovery.</p>
          </section>
        )}

        {/* Extension 4 Configuration Agent catalog */}
        {(isCompleted || isFailed) && configuration && (
          <section id="configuration" className="space-y-5 bg-[#0b1714] border border-amber-900/30 rounded-2xl p-6">
            <div className="flex flex-wrap items-end justify-between gap-4 border-b border-amber-900/20 pb-4">
              <div>
                <h2 className="text-xl font-semibold text-amber-300">Configuration Agent</h2>
                <p className="mt-1 text-sm text-emerald-100/50">High-confidence server and application misconfiguration rules over persisted HTTP evidence.</p>
              </div>
              <div className="flex gap-2 text-xs font-mono"><span className="rounded border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-amber-300">{configuration.rule_version}</span><span className="rounded border border-emerald-500/20 px-2.5 py-1 text-emerald-300">{configuration.summary.finding_count} findings · {configuration.summary.rule_count} rules</span></div>
            </div>
            <div className="grid gap-3 sm:grid-cols-3"><div className="rounded-xl border border-red-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">High</p><p className="mt-1 text-2xl font-semibold text-red-300">{configuration.summary.high_count}</p></div><div className="rounded-xl border border-amber-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Medium</p><p className="mt-1 text-2xl font-semibold text-amber-300">{configuration.summary.medium_count}</p></div><div className="rounded-xl border border-emerald-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Low</p><p className="mt-1 text-2xl font-semibold text-emerald-300">{configuration.summary.low_count}</p></div></div>
            {configuration.findings.length > 0 ? <div className="space-y-3">{configuration.findings.map((finding) => { const rule = configuration.rules.find((item) => item.rule_id === finding.rule_id); return <details key={finding.id} className="rounded-xl border border-amber-900/30 bg-[#050b09] p-4"><summary className="cursor-pointer list-none"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-sm font-semibold text-amber-200">{finding.statement}</p><p className="mt-1 text-xs font-mono text-emerald-100/50">{finding.rule_id} · {finding.subject}</p></div><span className="rounded-full border border-amber-500/20 px-3 py-1 text-xs font-mono text-amber-300">{finding.severity} · {finding.confidence ?? "—"}%</span></div></summary><div className="mt-4 grid gap-3 border-t border-amber-900/20 pt-4 text-xs text-emerald-100/65 md:grid-cols-2"><div><p className="font-mono uppercase tracking-wider text-emerald-100/40">Evidence</p><p className="mt-1">{finding.evidence?.map((item) => typeof item === "string" ? item : item.observation).join(" · ") || "Evidence recorded"}</p><p className="mt-3 font-mono uppercase tracking-wider text-emerald-100/40">Limitations</p><p className="mt-1">{finding.limitations || "Passive evidence only"}</p></div><div><p className="font-mono uppercase tracking-wider text-emerald-100/40">Remediation</p><p className="mt-1">{rule?.remediation_guidance || "Review the rule guidance."}</p><p className="mt-3 font-mono uppercase tracking-wider text-emerald-100/40">References</p><p className="mt-1">{rule ? [...rule.cwe, ...rule.owasp].join(", ") : "—"}</p></div></div></details>; })}</div> : <div className="rounded-xl border border-emerald-900/30 bg-[#050b09] p-5 text-sm text-emerald-100/65">No Configuration Agent rules met their prerequisites with the persisted evidence. This is not a guarantee that the target is secure.</div>}
            <details className="rounded-xl border border-amber-900/20 bg-[#050b09] p-4"><summary className="cursor-pointer text-sm font-semibold text-amber-200">View independently testable rule catalog</summary><div className="mt-3 space-y-3">{configuration.rules.map((rule) => <div key={rule.rule_id} className="border-t border-amber-900/20 pt-3 text-xs"><p className="font-mono text-amber-300">{rule.rule_id} · {rule.title} · default {rule.severity} / {rule.confidence}%</p><p className="mt-1 text-emerald-100/60">{rule.detection_logic}</p><p className="mt-1 text-emerald-100/50">Prerequisites: {rule.prerequisites} Remediation: {rule.remediation_guidance}</p></div>)}</div></details>
          </section>
        )}

        {/* Phase 5 API Endpoints Catalog */}
        {(isCompleted || isFailed) && apiEndpoints.length > 0 && (
          <section id="api-intelligence" className="space-y-4 bg-[#0b1714] border border-emerald-900/30 rounded-2xl p-6">
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

        {/* Extension 5 API Agent analysis */}
        {(isCompleted || isFailed) && apiAgent && (
          <section id="api-agent" className="space-y-5 bg-[#0b1714] border border-violet-900/30 rounded-2xl p-6">
            <div className="flex flex-wrap items-end justify-between gap-4 border-b border-violet-900/20 pb-4">
              <div>
                <h2 className="text-xl font-semibold text-violet-300">API Agent</h2>
                <p className="mt-1 text-sm text-emerald-100/50">Evidence-driven API inventory and security indicators from discovered routes, schemas, parameters, and persisted HTTP observations.</p>
              </div>
              <div className="flex gap-2 text-xs font-mono"><span className="rounded border border-violet-500/30 bg-violet-500/10 px-2.5 py-1 text-violet-300">{apiAgent.rule_version}</span><span className="rounded border border-emerald-500/20 px-2.5 py-1 text-emerald-300">{apiAgent.summary.inventory_count} routes · {apiAgent.summary.finding_count} findings</span></div>
            </div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><div className="rounded-xl border border-violet-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Inventory</p><p className="mt-1 text-2xl font-semibold text-violet-300">{apiAgent.summary.inventory_count}</p><p className="mt-1 text-[10px] text-emerald-100/45">{apiAgent.summary.documented_route_count} documented</p></div><div className="rounded-xl border border-red-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">High</p><p className="mt-1 text-2xl font-semibold text-red-300">{apiAgent.summary.high_count}</p></div><div className="rounded-xl border border-amber-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Medium</p><p className="mt-1 text-2xl font-semibold text-amber-300">{apiAgent.summary.medium_count}</p></div><div className="rounded-xl border border-emerald-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Informational</p><p className="mt-1 text-2xl font-semibold text-emerald-300">{apiAgent.summary.info_count}</p></div></div>
            <div className="grid gap-3 md:grid-cols-2"><div className="rounded-xl border border-violet-900/30 bg-[#050b09] p-4"><p className="text-xs font-semibold text-violet-200">Observed API signals</p><p className="mt-2 text-xs text-emerald-100/60">Methods: {Object.entries(apiAgent.summary.method_counts).map(([method, count]) => `${method} ${count}`).join(" · ") || "none observed"}</p><p className="mt-1 text-xs text-emerald-100/60">Rate-limit indicators: {apiAgent.summary.rate_limit_route_count} routes · authentication signals: {apiAgent.summary.auth_signal_route_count} routes · error routes: {apiAgent.summary.error_route_count} · policy routes: {apiAgent.summary.policy_route_count}</p><p className="mt-2 text-[10px] text-emerald-100/40">Absence of rate-limit or authentication signals is not escalated because no repeated probe or authentication attempt was performed.</p></div><div className="rounded-xl border border-violet-900/30 bg-[#050b09] p-4"><p className="text-xs font-semibold text-violet-200">Inventory sources</p><p className="mt-2 text-xs text-emerald-100/60">{Object.entries(apiAgent.summary.source_counts).map(([source, count]) => `${source.replaceAll("_", " ")}: ${count}`).join(" · ")}</p><p className="mt-1 text-xs text-emerald-100/60">Schema documents: {apiAgent.summary.schema_count} · undocumented route candidates: {apiAgent.summary.undocumented_route_count}</p></div></div>
            {apiAgent.findings.length > 0 ? <div className="space-y-3">{apiAgent.findings.map((finding) => { const rule = apiAgent.rules.find((item) => item.rule_id === finding.rule_id); return <details key={finding.id} className="rounded-xl border border-violet-900/30 bg-[#050b09] p-4"><summary className="cursor-pointer list-none"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-sm font-semibold text-violet-200">{finding.statement}</p><p className="mt-1 text-xs font-mono text-emerald-100/50">{finding.rule_id} · {finding.subject}</p></div><span className="rounded-full border border-violet-500/20 px-3 py-1 text-xs font-mono text-violet-300">{finding.severity} · {finding.confidence ?? "—"}%</span></div></summary><div className="mt-4 grid gap-3 border-t border-violet-900/20 pt-4 text-xs text-emerald-100/65 md:grid-cols-2"><div><p className="font-mono uppercase tracking-wider text-emerald-100/40">Evidence</p><p className="mt-1">{finding.evidence?.map((item) => typeof item === "string" ? item : item.observation).join(" · ") || "Evidence recorded"}</p><p className="mt-3 font-mono uppercase tracking-wider text-emerald-100/40">Limitations</p><p className="mt-1">{finding.limitations || "Persisted evidence only"}</p></div><div><p className="font-mono uppercase tracking-wider text-emerald-100/40">Remediation</p><p className="mt-1">{rule?.remediation_guidance || "Review the rule guidance."}</p><p className="mt-3 font-mono uppercase tracking-wider text-emerald-100/40">References</p><p className="mt-1">{rule ? [...rule.cwe, ...rule.owasp].join(", ") : "—"}</p></div></div></details>; })}</div> : <div className="rounded-xl border border-emerald-900/30 bg-[#050b09] p-5 text-sm text-emerald-100/65">No API Agent rules met their prerequisites with the persisted evidence. This is not a guarantee that the target API is secure.</div>}
            <details className="rounded-xl border border-violet-900/20 bg-[#050b09] p-4"><summary className="cursor-pointer text-sm font-semibold text-violet-200">View API route inventory</summary><div className="mt-3 overflow-x-auto"><table className="w-full text-left text-xs"><thead className="text-emerald-100/45"><tr><th className="px-2 py-2">ROUTE</th><th className="px-2 py-2">METHODS</th><th className="px-2 py-2">SOURCES</th><th className="px-2 py-2">STATUS</th><th className="px-2 py-2">PARAMETERS</th></tr></thead><tbody>{apiAgent.inventory.slice(0, 100).map((route) => <tr key={`${route.host}${route.path}`} className="border-t border-violet-900/20"><td className="max-w-[320px] truncate px-2 py-2 font-mono text-violet-200" title={route.route}>{route.route}</td><td className="px-2 py-2 text-emerald-100/60">{route.methods.join(", ") || "observed"}</td><td className="px-2 py-2 text-emerald-100/60">{route.sources.join(", ")}</td><td className="px-2 py-2 text-emerald-100/60">{route.status_codes.join(", ") || "—"}</td><td className="px-2 py-2 text-emerald-100/60">{route.parameter_names.join(", ") || "—"}</td></tr>)}</tbody></table>{apiAgent.inventory.length > 100 && <p className="mt-2 text-[10px] text-emerald-100/40">Showing first 100 routes of {apiAgent.inventory.length}; the API response contains the complete bounded inventory.</p>}{apiAgent.inventory.length === 0 && <p className="p-3 text-sm text-emerald-100/60">No API-like routes were normalized from this scan’s persisted evidence.</p>}</div></details>
            <details className="rounded-xl border border-violet-900/20 bg-[#050b09] p-4"><summary className="cursor-pointer text-sm font-semibold text-violet-200">View captured API schemas and rule catalog</summary><div className="mt-3 space-y-3">{apiAgent.schemas.length > 0 ? apiAgent.schemas.map((schema) => <div key={schema.url} className="border-t border-violet-900/20 pt-3 text-xs text-emerald-100/60"><p className="font-mono text-violet-300">{schema.format} {schema.version || "unknown"} · {schema.url}</p><p className="mt-1">{schema.paths.length} documented paths · security schemes: {schema.security_schemes.join(", ") || "none observed"}</p></div>) : <p className="text-xs text-emerald-100/55">No public OpenAPI/Swagger schema was captured in the bounded evidence.</p>}{apiAgent.rules.map((rule) => <div key={rule.rule_id} className="border-t border-violet-900/20 pt-3 text-xs"><p className="font-mono text-violet-300">{rule.rule_id} · {rule.title} · {rule.severity} / {rule.confidence}%</p><p className="mt-1 text-emerald-100/60">{rule.detection_logic}</p></div>)}</div></details>
          </section>
        )}

        {/* Extension 6 Vulnerability Agent analysis */}
        {(isCompleted || isFailed) && vulnerability && (
          <section id="vulnerability-agent" className="space-y-5 rounded-2xl border border-red-900/30 bg-[#0b1714] p-6">
            <div className="flex flex-wrap items-end justify-between gap-4 border-b border-red-900/20 pb-4">
              <div>
                <h2 className="text-xl font-semibold text-red-300">Vulnerability Agent</h2>
                <p className="mt-1 text-sm text-emerald-100/50">Modular, detection-only OWASP-style triage over persisted evidence. No exploit chains, payloads, authentication attempts, form submissions, or state-changing requests.</p>
              </div>
              <div className="flex gap-2 text-xs font-mono"><span className="rounded border border-red-500/30 bg-red-500/10 px-2.5 py-1 text-red-300">{vulnerability.rule_version}</span><span className="rounded border border-emerald-500/20 px-2.5 py-1 text-emerald-300">{vulnerability.summary.finding_count} findings · {vulnerability.summary.detector_count} detectors</span></div>
            </div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5"><div className="rounded-xl border border-red-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">High</p><p className="mt-1 text-2xl font-semibold text-red-300">{vulnerability.summary.high_count}</p></div><div className="rounded-xl border border-amber-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Medium</p><p className="mt-1 text-2xl font-semibold text-amber-300">{vulnerability.summary.medium_count}</p></div><div className="rounded-xl border border-emerald-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Low</p><p className="mt-1 text-2xl font-semibold text-emerald-300">{vulnerability.summary.low_count}</p></div><div className="rounded-xl border border-sky-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Informational</p><p className="mt-1 text-2xl font-semibold text-sky-300">{vulnerability.summary.info_count}</p></div><div className="rounded-xl border border-red-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Rules</p><p className="mt-1 text-2xl font-semibold text-red-200">{vulnerability.summary.rule_count}</p></div></div>
            <div className="rounded-xl border border-emerald-900/30 bg-[#050b09] p-4"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-xs font-semibold text-emerald-200">Safe validation contract</p><p className="mt-1 text-xs text-emerald-100/60">Mode: {vulnerability.safe_validation.mode}</p></div><div className="flex flex-wrap gap-2 text-[10px] font-mono text-emerald-300"><span>network {vulnerability.safe_validation.network_requests_issued}</span><span>payloads {vulnerability.safe_validation.payloads_sent}</span><span>forms {vulnerability.safe_validation.forms_submitted}</span><span>mutations {vulnerability.safe_validation.mutating_requests_issued}</span><span>auth attempts {vulnerability.safe_validation.authentication_attempts}</span></div></div></div>
            {vulnerability.findings.length > 0 ? <div className="space-y-3">{vulnerability.findings.map((finding) => { const rule = vulnerability.rules.find((item) => item.rule_id === finding.rule_id); return <details key={finding.id} className="rounded-xl border border-red-900/30 bg-[#050b09] p-4"><summary className="cursor-pointer list-none"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-sm font-semibold text-red-200">{finding.statement}</p><p className="mt-1 text-xs font-mono text-emerald-100/50">{finding.rule_id} · {rule?.risk_family || "vulnerability"} · {finding.subject}</p></div><span className="rounded-full border border-red-500/20 px-3 py-1 text-xs font-mono text-red-300">{finding.severity} · {finding.classification} · {finding.confidence ?? "—"}%</span></div></summary><div className="mt-4 grid gap-3 border-t border-red-900/20 pt-4 text-xs text-emerald-100/65 md:grid-cols-2"><div><p className="font-mono uppercase tracking-wider text-emerald-100/40">Evidence</p><p className="mt-1">{finding.evidence?.map((item) => typeof item === "string" ? item : item.observation).join(" · ") || "Evidence recorded"}</p><p className="mt-3 font-mono uppercase tracking-wider text-emerald-100/40">Limitations</p><p className="mt-1">{finding.limitations || "Detection-only persisted evidence"}</p></div><div><p className="font-mono uppercase tracking-wider text-emerald-100/40">Remediation</p><p className="mt-1">{rule?.remediation_guidance || "Review the linked detector guidance."}</p><p className="mt-3 font-mono uppercase tracking-wider text-emerald-100/40">References</p><p className="mt-1">{rule ? [...rule.cwe, ...rule.owasp].join(", ") : "—"}</p></div></div></details>; })}</div> : <div className="rounded-xl border border-emerald-900/30 bg-[#050b09] p-5 text-sm text-emerald-100/65">No Vulnerability Agent detector met its prerequisites with the persisted evidence. This is not a guarantee that the target is secure.</div>}
            <details className="rounded-xl border border-red-900/20 bg-[#050b09] p-4"><summary className="cursor-pointer text-sm font-semibold text-red-200">View independently testable detector catalog</summary><div className="mt-3 space-y-3">{vulnerability.rules.map((rule) => <div key={rule.rule_id} className="border-t border-red-900/20 pt-3 text-xs"><div className="flex flex-wrap items-center justify-between gap-2"><p className="font-mono text-red-300">{rule.rule_id} · {rule.title}</p><span className="text-emerald-100/45">{rule.risk_family} · {rule.severity} · {rule.confidence}%</span></div><p className="mt-1 text-emerald-100/60">{rule.detection_logic}</p><p className="mt-1 text-emerald-100/45">Validation: {rule.validation_mode}</p></div>)}</div></details>
          </section>
        )}

        {/* Extension 7 Secrets & Sensitive Data analysis */}
        {(isCompleted || isFailed) && secrets && (
          <section id="secrets" className="space-y-5 rounded-2xl border border-amber-900/30 bg-[#0b1714] p-6">
            <div className="flex flex-wrap items-end justify-between gap-4 border-b border-amber-900/20 pb-4">
              <div><h2 className="text-xl font-semibold text-amber-300">Secrets &amp; Sensitive Data Agent</h2><p className="mt-1 text-sm text-emerald-100/50">High-confidence leakage detection over bounded persisted responses, JavaScript, source-map/configuration artifacts, and headers. Secret values are never displayed.</p></div>
              <div className="flex gap-2 text-xs font-mono"><span className="rounded border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-amber-300">{secrets.rule_version}</span><span className="rounded border border-emerald-500/20 px-2.5 py-1 text-emerald-300">{secrets.summary.finding_count} findings</span></div>
            </div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5"><div className="rounded-xl border border-red-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Critical</p><p className="mt-1 text-2xl font-semibold text-red-300">{secrets.summary.critical_count}</p></div><div className="rounded-xl border border-orange-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">High</p><p className="mt-1 text-2xl font-semibold text-orange-300">{secrets.summary.high_count}</p></div><div className="rounded-xl border border-amber-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Medium</p><p className="mt-1 text-2xl font-semibold text-amber-300">{secrets.summary.medium_count}</p></div><div className="rounded-xl border border-emerald-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Low</p><p className="mt-1 text-2xl font-semibold text-emerald-300">{secrets.summary.low_count}</p></div><div className="rounded-xl border border-amber-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Rules</p><p className="mt-1 text-2xl font-semibold text-amber-200">{secrets.summary.rule_count}</p></div></div>
            <div className="rounded-xl border border-emerald-900/30 bg-[#050b09] p-4"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-xs font-semibold text-emerald-200">Redaction contract</p><p className="mt-1 text-xs text-emerald-100/60">{secrets.redaction.stored_evidence_mode}</p></div><div className="flex flex-wrap gap-2 text-[10px] font-mono text-emerald-300"><span>persisted: {secrets.redaction.values_persisted ? "yes" : "no"}</span><span>logged: {secrets.redaction.values_logged ? "yes" : "no"}</span><span>returned: {secrets.redaction.values_returned ? "yes" : "no"}</span></div></div></div>
            {secrets.findings.length > 0 ? <div className="space-y-3">{secrets.findings.map((finding) => { const rule = secrets.rules.find((item) => item.rule_id === finding.rule_id); return <details key={finding.id} className="rounded-xl border border-amber-900/30 bg-[#050b09] p-4"><summary className="cursor-pointer list-none"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-sm font-semibold text-amber-200">{finding.statement}</p><p className="mt-1 text-xs font-mono text-emerald-100/50">{finding.rule_id} · {finding.subject}</p></div><span className="rounded-full border border-amber-500/20 px-3 py-1 text-xs font-mono text-amber-300">{finding.severity} · {finding.confidence ?? "—"}%</span></div></summary><div className="mt-4 grid gap-3 border-t border-amber-900/20 pt-4 text-xs text-emerald-100/65 md:grid-cols-2"><div><p className="font-mono uppercase tracking-wider text-emerald-100/40">Redacted evidence</p><p className="mt-1">{finding.evidence?.map((item) => typeof item === "string" ? item : item.observation).join(" · ") || "Redacted evidence recorded"}</p><p className="mt-3 font-mono uppercase tracking-wider text-emerald-100/40">Limitations</p><p className="mt-1">{finding.limitations || "Secret values are not retained"}</p></div><div><p className="font-mono uppercase tracking-wider text-emerald-100/40">Remediation</p><p className="mt-1">{rule?.remediation_guidance || "Review the linked secret-handling guidance."}</p><p className="mt-3 font-mono uppercase tracking-wider text-emerald-100/40">References</p><p className="mt-1">{rule ? [...rule.cwe, ...rule.owasp].join(", ") : "—"}</p></div></div></details>; })}</div> : <div className="rounded-xl border border-emerald-900/30 bg-[#050b09] p-5 text-sm text-emerald-100/65">No high-confidence secret or sensitive-identifier rule met its prerequisites in the bounded evidence. This is not proof that the target contains no secrets.</div>}
            <details className="rounded-xl border border-amber-900/20 bg-[#050b09] p-4"><summary className="cursor-pointer text-sm font-semibold text-amber-200">View signature catalog and suppression rules</summary><div className="mt-3 space-y-3">{secrets.rules.map((rule) => <div key={rule.rule_id} className="border-t border-amber-900/20 pt-3 text-xs"><div className="flex flex-wrap items-center justify-between gap-2"><p className="font-mono text-amber-300">{rule.rule_id} · {rule.title}</p><span className="text-emerald-100/45">{rule.confidence_tier} · {rule.confidence}%</span></div><p className="mt-1 text-emerald-100/60">{rule.detection_logic}</p><p className="mt-1 text-emerald-100/45">Suppression: {rule.suppression_logic}</p></div>)}</div></details>
          </section>
        )}

        {/* Extension 8 CVE & Technology Intelligence analysis */}
        {(isCompleted || isFailed) && cveIntelligence && (
          <section id="cve-intelligence" className="space-y-5 rounded-2xl border border-cyan-900/30 bg-[#0b1714] p-6">
            <div className="flex flex-wrap items-end justify-between gap-4 border-b border-cyan-900/20 pb-4"><div><h2 className="text-xl font-semibold text-cyan-300">CVE &amp; Technology Intelligence Agent</h2><p className="mt-1 text-sm text-emerald-100/50">Conservative public-feed matching. A technology family without explicit version evidence is never reported as CVE-applicable.</p></div><div className="flex gap-2 text-xs font-mono"><span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-1 text-cyan-300">{cveIntelligence.rule_version}</span><span className="rounded border border-emerald-500/20 px-2.5 py-1 text-emerald-300">{cveIntelligence.summary.matched_count} matched</span></div></div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-6"><div className="rounded-xl border border-cyan-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Technologies</p><p className="mt-1 text-2xl font-semibold text-cyan-200">{cveIntelligence.summary.technology_count}</p></div><div className="rounded-xl border border-red-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">CVE matches</p><p className="mt-1 text-2xl font-semibold text-red-300">{cveIntelligence.summary.matched_count}</p></div><div className="rounded-xl border border-amber-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Version insufficient</p><p className="mt-1 text-2xl font-semibold text-amber-300">{cveIntelligence.summary.version_insufficient_count}</p></div><div className="rounded-xl border border-emerald-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">No match</p><p className="mt-1 text-2xl font-semibold text-emerald-300">{cveIntelligence.summary.no_match_count}</p></div><div className="rounded-xl border border-orange-900/30 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">KEV listed</p><p className="mt-1 text-2xl font-semibold text-orange-300">{cveIntelligence.summary.kev_count}</p></div><div className="rounded-xl border border-slate-800 bg-[#050b09] p-4"><p className="text-[10px] font-mono uppercase tracking-wider text-emerald-100/40">Feed runs</p><p className="mt-1 text-2xl font-semibold text-slate-200">{cveIntelligence.summary.feed_count}</p></div></div>
            <div className="rounded-xl border border-cyan-900/30 bg-[#050b09] p-4 text-xs text-emerald-100/65"><p className="font-semibold text-cyan-200">Confidence separation</p><p className="mt-1">Detection confidence, version-evidence confidence, and CVE-applicability confidence are stored separately. Family-only detections remain `version_insufficient` and cannot produce a matched CVE finding.</p></div>
            {cveIntelligence.matches.length > 0 ? <div className="space-y-3">{cveIntelligence.matches.map((match) => <details key={match.id} className="rounded-xl border border-cyan-900/30 bg-[#050b09] p-4"><summary className="cursor-pointer list-none"><div className="flex flex-wrap items-center justify-between gap-3"><div><p className="text-sm font-semibold text-cyan-200">{match.product}{match.detected_version ? ` ${match.detected_version}` : ""}{match.cve_id ? ` · ${match.cve_id}` : ""}</p><p className="mt-1 text-xs font-mono text-emerald-100/50">{match.vendor || "vendor unknown"} · {match.applicability_state} · detected {Math.round(match.detection_confidence)}% · applicability {Math.round(match.applicability_confidence)}%</p></div>{match.kev_listed && <span className="rounded-full border border-orange-500/30 px-3 py-1 text-xs font-mono text-orange-300">CISA KEV</span>}</div></summary><div className="mt-4 grid gap-3 border-t border-cyan-900/20 pt-4 text-xs text-emerald-100/65 md:grid-cols-2"><div><p className="font-mono uppercase tracking-wider text-emerald-100/40">Match reason</p><p className="mt-1">{match.match_reason}</p><p className="mt-3 font-mono uppercase tracking-wider text-emerald-100/40">Version evidence</p><p className="mt-1">{match.detected_version ? `${match.detected_version} from ${match.version_source || "stored evidence"} (${Math.round(match.version_evidence_confidence)}%)` : "No explicit version evidence; applicability withheld."}</p><p className="mt-3 font-mono uppercase tracking-wider text-emerald-100/40">Feed provenance</p><p className="mt-1">{match.source_url || "No CVE feed record"} · {match.feed_retrieved_at || "not retrieved"}{match.feed_is_stale ? " · STALE" : ""}</p></div><div><p className="font-mono uppercase tracking-wider text-emerald-100/40">CVE metadata</p><p className="mt-1">CVSS {match.cvss_score ?? "—"}{match.cvss_vector ? ` · ${match.cvss_vector}` : ""} · CWE {match.cwe.length ? match.cwe.join(", ") : "—"}</p><p className="mt-3 text-emerald-100/60">{match.description || "No CVE record matched this product/version."}</p></div></div></details>)}</div> : <div className="rounded-xl border border-emerald-900/30 bg-[#050b09] p-5 text-sm text-emerald-100/65">No normalized technology/CVE matches were persisted for this scan. The report does not infer applicability from family-only technology detection.</div>}
            <details className="rounded-xl border border-cyan-900/20 bg-[#050b09] p-4"><summary className="cursor-pointer text-sm font-semibold text-cyan-200">Feed provenance and freshness</summary><div className="mt-3 space-y-3">{cveIntelligence.feed_runs.map((feed) => <div key={feed.id} className="border-t border-cyan-900/20 pt-3 text-xs"><div className="flex flex-wrap justify-between gap-2"><p className="font-mono text-cyan-300">{feed.source_name} · {feed.status}</p><span className={feed.is_stale ? "text-orange-300" : "text-emerald-300"}>{feed.is_stale ? "STALE" : "fresh at retrieval"}</span></div><p className="mt-1 text-emerald-100/55">{feed.record_count} records · retrieved {feed.retrieved_at} · stale threshold {feed.stale_after_seconds}s</p>{feed.error && <p className="mt-1 text-orange-300">{feed.error}</p>}</div>)}</div></details>
          </section>
        )}

        {/* Existing Technology DNA Section */}
        {(isCompleted || isFailed) && (
          <section id="technology-dna" className="space-y-4">
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
                <details key={technology.id} id={`evidence-${technology.id}`} className="rounded-xl border border-white/5 bg-black/20 p-5 group target:ring-2 target:ring-blue-500 transition-all duration-500">
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
                    {technology.evidence?.map((item) => (
                      <div key={item.id} id={`evidence-${item.id}`} className="rounded-lg bg-white/[0.03] p-3 text-sm target:ring-2 target:ring-blue-500 target:bg-blue-900/30 transition-all duration-500">
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

        {/* Phase 8 Performance Section */}
        {(isCompleted || isFailed) && performance && (
          <section id="performance" className="space-y-5 rounded-2xl border border-emerald-900/30 bg-[#0b1714] p-6">
            <div className="flex items-end justify-between border-b border-emerald-900/20 pb-4">
              <div>
                <h2 className="text-xl font-semibold text-emerald-400">Performance</h2>
                <p className="mt-1 text-sm text-emerald-100/50">
                  Deterministic metrics computed only from stored HTTP, resource, and browser timing evidence. Missing browser timing is shown as UNKNOWN.
                </p>
              </div>
              <span className="text-xs font-mono text-emerald-100/50">{performance.metrics.length} METRICS</span>
            </div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {(performance.site_metrics ?? []).filter((metric) => ["site_total_document_size_bytes", "site_average_document_size_bytes", "site_total_static_resource_reference_count", "site_average_request_count", "site_average_page_load_time_ms"].includes(metric.metric_name)).map((metric) => (
                <div key={metric.id} id={`evidence-${metric.id}`} className="rounded-xl border border-white/5 bg-black/20 p-4 target:ring-2 target:ring-blue-500 transition-all duration-500">
                  <p className="text-xs uppercase tracking-wider text-emerald-100/45">{metric.metric_name.replaceAll("_", " ")}</p>
                  <p className="mt-2 text-lg font-semibold text-emerald-50">
                    {metric.value === null ? "UNKNOWN" : metric.unit === "bytes" ? `${(metric.value / 1024 / 1024).toFixed(2)} MB` : `${metric.value.toFixed(1)} ${metric.unit}`}
                  </p>
                  <p className="mt-1 text-xs text-emerald-100/45">{metric.classification} · {metric.capture_mode}</p>
                </div>
              ))}
            </div>
            <div>
              <div className="mb-2 flex items-center justify-between text-xs text-emerald-100/45">
                <span>Payload composition from captured size evidence</span>
                <span>JS · CSS · Images · Fonts</span>
              </div>
              <div className="flex h-4 overflow-hidden rounded-full bg-white/5">
                {(["js", "css", "image", "font"] as const).map((kind) => {
                  const metric = performance.metrics.find((item) => item.scope === "site" && item.metric_name === `site_total_${kind}_payload_size_bytes`);
                  const total = ["js", "css", "image", "font"].reduce((sum, name) => sum + (performance.metrics.find((item) => item.scope === "site" && item.metric_name === `site_total_${name}_payload_size_bytes`)?.value ?? 0), 0);
                  const width = metric?.value !== null && metric?.value !== undefined && total > 0 ? (metric.value / total) * 100 : 0;
                  return <div key={kind} title={`${kind}: ${metric?.value ?? "UNKNOWN"}`} className={`${kind === "js" ? "bg-amber-400" : kind === "css" ? "bg-sky-400" : kind === "image" ? "bg-emerald-400" : "bg-purple-400"} h-full`} style={{ width: `${width}%` }} />;
                })}
              </div>
              <div className="rounded-xl border border-white/5 bg-black/20 p-4">
                <p className="text-xs text-emerald-100/45">LCP (Largest Contentful Paint)</p>
                <p className="mt-1 text-2xl font-semibold text-emerald-200">{performance.lcp_seconds !== undefined && performance.lcp_seconds !== null ? `${performance.lcp_seconds.toFixed(2)}s` : "N/A"}</p>
              </div>
              <div className="rounded-xl border border-white/5 bg-black/20 p-4">
                <p className="text-xs text-emerald-100/45">TTFB (Time to First Byte)</p>
                <p className="mt-1 text-2xl font-semibold text-emerald-200">{performance.ttfb_ms !== undefined && performance.ttfb_ms !== null ? `${Math.round(performance.ttfb_ms)}ms` : "N/A"}</p>
              </div>
              <div className="rounded-xl border border-white/5 bg-black/20 p-4">
                <p className="text-xs text-emerald-100/45">FID (First Input Delay)</p>
                <p className="mt-1 text-2xl font-semibold text-emerald-200">{performance.fid_ms !== undefined && performance.fid_ms !== null ? `${Math.round(performance.fid_ms)}ms` : "N/A"}</p>
              </div>
              <div className="rounded-xl border border-white/5 bg-black/20 p-4">
                <p className="text-xs text-emerald-100/45">CLS (Cumulative Layout Shift)</p>
                <p className="mt-1 text-2xl font-semibold text-emerald-200">{performance.cls !== undefined && performance.cls !== null ? performance.cls.toFixed(3) : "N/A"}</p>
              </div>
            </div>

            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-emerald-100/60 uppercase tracking-wider">Performance Diagnoses</h3>
              {performance.diagnostics?.map((diagnostic) => (
                <details key={diagnostic.id} id={`evidence-${diagnostic.id}`} className="rounded-xl border border-white/5 bg-black/20 p-4 group target:ring-2 target:ring-blue-500 transition-all duration-500">
                  <summary className="cursor-pointer list-none">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-emerald-50">{diagnostic.metric_name}</span>
                      <span className="text-xs font-mono text-emerald-100/50">{diagnostic.classification}</span>
                    </div>
                  </summary>
                  <p className="mt-3 text-sm text-emerald-50/80">{diagnostic.statement}</p>
                  <p className="mt-2 text-xs text-emerald-100/45">Evidence: {diagnostic.evidence?.length ?? 0} item(s)</p>
                  <div className="mt-3 space-y-2">
                    {diagnostic.evidence?.map((item) => (
                      <div key={item.id} id={`evidence-${item.id}`} className="rounded-lg bg-black/20 p-3 text-xs target:ring-2 target:ring-blue-500 target:bg-blue-900/30 transition-all duration-500">
                        <p className="text-emerald-100/45">{item.type}</p>
                        <p className="mt-1 text-emerald-50/80">{item.observation}</p>
                        <p className="mt-1 break-all text-emerald-100/40">{item.source}</p>
                      </div>
                    ))}
                  </div>
                </details>
              ))}
              {(!performance.diagnostics || performance.diagnostics.length === 0) && <p className="text-sm text-emerald-100/45">No deterministic performance diagnoses were triggered.</p>}
            </div>
            {performance.page_metrics && performance.page_metrics.length > 0 && (
              <div className="overflow-auto rounded-xl border border-white/5 bg-black/20">
                <table className="w-full text-left text-sm">
                  <thead className="bg-white/5 text-xs uppercase tracking-wider text-emerald-100/40"><tr><th className="px-4 py-3">Page</th><th className="px-4 py-3">Metrics</th><th className="px-4 py-3">UNKNOWN timing</th></tr></thead>
                  <tbody className="divide-y divide-white/5">
                    {performance.page_metrics.map((pageMetric) => {
                      const unknownTiming = pageMetric.metrics.filter((metric) => metric.metric_name.endsWith("_ms") && metric.value === null).length;
                      return <tr key={pageMetric.page_id}><td className="max-w-[360px] truncate px-4 py-3 text-emerald-50" title={pageMetric.url}>{pageMetric.url}</td><td className="px-4 py-3 text-emerald-100/60">{pageMetric.metrics.length}</td><td className="px-4 py-3 text-emerald-100/60">{unknownTiming}</td></tr>;
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}

        {/* Phase 7 Passive Security Section */}
        {(isCompleted || isFailed) && (
          <section id="security" className="space-y-4">
            <div className="flex items-end justify-between">
              <div>
                <h2 className="text-xl font-semibold">Security</h2>
                <p className="mt-1 text-sm text-emerald-100/50">
                  Passive analysis of stored headers, cookies, redirects, HTML, resources, and browser evidence. No new target requests are issued.
                </p>
              </div>
              <span className="text-xs font-mono bg-white/5 px-2 py-0.5 rounded text-emerald-100/50">
                {securityFindings.length} FINDINGS
              </span>
            </div>
            <div className="space-y-3">
              {securityFindings.map((finding) => (
                <details key={finding.id} id={`evidence-${finding.id}`} className="rounded-xl border border-white/5 bg-black/20 p-5 group target:ring-2 target:ring-blue-500 transition-all duration-500">
                  <summary className="cursor-pointer list-none">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <p className="text-base font-semibold text-emerald-50">{finding.subject}</p>
                        <p className="mt-1 text-xs uppercase tracking-wider text-emerald-100/45">
                          {finding.classification} · {(finding.rule_id ?? "").replaceAll("_", " ")}
                        </p>
                      </div>
                      <div className="flex shrink-0 items-center gap-2 text-xs font-mono">
                        <span className={`rounded-full px-2.5 py-1 ${
                          finding.severity === "high" || finding.severity === "HIGH" ? "bg-red-500/15 text-red-300" :
                          finding.severity === "medium" || finding.severity === "MEDIUM" ? "bg-amber-500/15 text-amber-300" :
                          finding.severity === "low" || finding.severity === "LOW" ? "bg-sky-500/15 text-sky-300" :
                          "bg-emerald-500/15 text-emerald-300"
                        }`}>{finding.severity}</span>
                        <span className="rounded-full bg-white/5 px-2.5 py-1 text-emerald-100/60">{Math.round(finding.confidence ?? 0)}%</span>
                      </div>
                    </div>
                  </summary>
                  <div className="mt-4 space-y-3 border-t border-white/5 pt-4">
                    <p className="text-sm text-emerald-50/85">{finding.statement}</p>
                    <p className="text-xs text-emerald-100/45">Ruleset {finding.rule_version ?? "1.0"} · Confidence band {finding.confidence_band ?? "unknown"} · Evidence {finding.evidence?.length ?? 0}</p>
                    {finding.limitations && <p className="text-xs text-[#fca5a5]">Limitation: {finding.limitations}</p>}
                    {finding.evidence?.map((item) => {
                      const id = typeof item === "string" ? item : item.id;
                      const type = typeof item === "string" ? "EVIDENCE" : item.type;
                      const obs = typeof item === "string" ? item : item.observation;
                      const src = typeof item === "string" ? "N/A" : item.source;
                      return (
                        <div key={id} id={`evidence-${id}`} className="rounded-lg bg-white/[0.03] p-3 text-sm target:ring-2 target:ring-blue-500 target:bg-blue-900/30 transition-all duration-500">
                          <p className="text-xs uppercase tracking-wider text-emerald-100/45">{type}</p>
                          <p className="mt-1 break-words text-emerald-50/85">{obs}</p>
                          <p className="mt-1 break-all text-xs text-emerald-100/40">Source: {src}</p>
                        </div>
                      );
                    })}
                  </div>
                </details>
              ))}
              {securityFindings.length === 0 && (
                <div className="rounded-xl border border-white/5 bg-black/20 px-5 py-8 text-center text-emerald-100/45">
                  No passive security findings were produced from the stored evidence.
                </div>
              )}
            </div>
          </section>
        )}

        {/* Phase 9 Accessibility Section */}
        {(isCompleted || isFailed) && (
          <section id="accessibility" className="space-y-4">
            <div className="flex items-end justify-between">
              <div>
                <h2 className="text-xl font-semibold flex items-center gap-2">
                  <span className="text-emerald-400">Accessibility (Automated)</span>
                </h2>
                <p className="mt-1 text-sm text-emerald-100/50">
                  Deterministic accessibility checks against rendered DOM.
                </p>
              </div>
              <span className="text-xs font-mono bg-white/5 px-2 py-0.5 rounded text-emerald-100/50">
                {accessibilityFindings.length} FINDINGS
              </span>
            </div>
            
            {accessibilityFindings.length > 0 && (
              <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-4 mb-4">
                <p className="text-amber-200/90 text-sm font-medium">
                  {accessibilityFindings[0].disclaimer}
                </p>
              </div>
            )}

            <div className="space-y-3">
              {accessibilityFindings.map((finding) => (
                <details key={finding.id} id={`evidence-${finding.id}`} className="rounded-xl border border-white/5 bg-black/20 p-5 group target:ring-2 target:ring-blue-500 transition-all duration-500">
                  <summary className="cursor-pointer list-none">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <p className="text-base font-semibold text-emerald-50">{finding.subject}</p>
                        <p className="mt-1 text-xs uppercase tracking-wider text-emerald-100/45">
                          {finding.classification}
                        </p>
                      </div>
                      <div className="flex shrink-0 items-center gap-2 text-xs font-mono">
                         <span className={`rounded-full px-2.5 py-1 ${
                          finding.classification === "OBSERVED" ? "bg-emerald-500/15 text-emerald-300" :
                          finding.classification === "INFERRED" ? "bg-amber-500/15 text-amber-300" :
                          "bg-slate-500/15 text-slate-300"
                        }`}>{finding.classification}</span>
                      </div>
                    </div>
                  </summary>
                  <div className="mt-4 space-y-3 border-t border-white/5 pt-4">
                    <p className="text-sm text-emerald-50/85">{finding.statement}</p>
                    {finding.evidence && finding.evidence.map((item, idx) => (
                      <div key={item.id ?? `acc-ev-${idx}`} id={`evidence-${item.id}`} className="rounded-lg bg-white/[0.03] p-3 text-sm target:ring-2 target:ring-blue-500 target:bg-blue-900/30 transition-all duration-500">
                        <p className="text-xs uppercase tracking-wider text-emerald-100/45">{item.type}</p>
                        <p className="mt-1 break-words text-emerald-50/85">{item.observation}</p>
                        <p className="mt-1 break-all text-xs text-emerald-100/40">Source: {item.source}</p>
                      </div>
                    ))}
                  </div>
                </details>
              ))}
              {accessibilityFindings.length === 0 && (
                <div className="rounded-xl border border-white/5 bg-black/20 px-5 py-8 text-center text-emerald-100/45">
                  No automated accessibility findings were produced from the stored evidence.
                </div>
              )}
            </div>
          </section>
        )}

        {/* Phase 9 Content Section */}
        {(isCompleted || isFailed) && (
          <section id="content-seo" className="space-y-4">
            <div className="flex items-end justify-between">
              <div>
                <h2 className="text-xl font-semibold flex items-center gap-2">
                  <span className="text-emerald-400">Content & SEO</span>
                </h2>
                <p className="mt-1 text-sm text-emerald-100/50">
                  Metadata analysis, duplicate content detection, and structural SEO checks.
                </p>
              </div>
              <span className="text-xs font-mono bg-white/5 px-2 py-0.5 rounded text-emerald-100/50">
                {contentFindings.length} FINDINGS
              </span>
            </div>
            
            <div className="space-y-3">
              {contentFindings.map((finding) => (
                <details key={finding.id} id={`evidence-${finding.id}`} className="rounded-xl border border-white/5 bg-black/20 p-5 group target:ring-2 target:ring-blue-500 transition-all duration-500">
                  <summary className="cursor-pointer list-none">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <p className="text-base font-semibold text-emerald-50">{finding.subject}</p>
                        <p className="mt-1 text-xs uppercase tracking-wider text-emerald-100/45">
                          {finding.classification}
                        </p>
                      </div>
                      <div className="flex shrink-0 items-center gap-2 text-xs font-mono">
                         <span className={`rounded-full px-2.5 py-1 ${
                          finding.classification === "OBSERVED" ? "bg-emerald-500/15 text-emerald-300" :
                          finding.classification === "INFERRED" ? "bg-amber-500/15 text-amber-300" :
                          "bg-slate-500/15 text-slate-300"
                        }`}>{finding.classification}</span>
                      </div>
                    </div>
                  </summary>
                  <div className="mt-4 space-y-3 border-t border-white/5 pt-4">
                    <p className="text-sm text-emerald-50/85">{finding.statement}</p>
                    {finding.evidence && finding.evidence.map((item, idx) => (
                      <div key={item.id ?? `cnt-ev-${idx}`} id={`evidence-${item.id}`} className="rounded-lg bg-white/[0.03] p-3 text-sm target:ring-2 target:ring-blue-500 target:bg-blue-900/30 transition-all duration-500">
                        <p className="text-xs uppercase tracking-wider text-emerald-100/45">{item.type}</p>
                        <p className="mt-1 break-words text-emerald-50/85">{item.observation}</p>
                        <p className="mt-1 break-all text-xs text-emerald-100/40">Source: {item.source}</p>
                      </div>
                    ))}
                  </div>
                </details>
              ))}
              {contentFindings.length === 0 && (
                <div className="rounded-xl border border-white/5 bg-black/20 px-5 py-8 text-center text-emerald-100/45">
                  No automated content/SEO findings were produced from the stored evidence.
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
          <section id="raw-evidence" className="space-y-4">
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
                    <tr key={obs.id} id={`evidence-${obs.id}`} className="hover:bg-white/[0.02] transition-colors target:ring-2 target:ring-blue-500 target:bg-blue-900/30">
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

