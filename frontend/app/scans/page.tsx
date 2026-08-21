"use client";

import Link from "next/link";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { createScan, type ScanAuthentication } from "@/lib/api";

const PROFILE_COPY = {
  safe: {
    title: "Safe profile",
    description: "Passive, low-volume collection: depth 2, up to 30 requests, concurrency 2, and at least 1 second per host.",
    maxDepth: 2,
    maxRequests: 30,
    maxConcurrency: 2,
    rate: 1000,
  },
  normal: {
    title: "Normal profile",
    description: "Moderate bounded collection: depth 3, up to 50 requests, concurrency 3, and at least 500ms per host.",
    maxDepth: 3,
    maxRequests: 50,
    maxConcurrency: 3,
    rate: 500,
  },
  aggressive: {
    title: "Aggressive profile",
    description: "Highest bounded profile: depth 5, up to 100 requests, concurrency 4. Explicit allowed-domain confirmation is required.",
    maxDepth: 5,
    maxRequests: 100,
    maxConcurrency: 4,
    rate: 250,
  },
} as const;

type Profile = keyof typeof PROFILE_COPY;
type AuthType = "none" | "cookie" | "header" | "basic";

export default function NewScanPage() {
  const [url, setUrl] = useState("");
  const [profile, setProfile] = useState<Profile>("safe");
  const [reconMode, setReconMode] = useState<"passive_only" | "active_safe">("passive_only");
  const [sqliValidationEnabled, setSqliValidationEnabled] = useState(false);
  const [sqliExtendedValidationEnabled, setSqliExtendedValidationEnabled] = useState(false);
  const [maxDepth, setMaxDepth] = useState("2");
  const [maxPages, setMaxPages] = useState("30");
  const [maxConcurrency, setMaxConcurrency] = useState("2");
  const [maxRequests, setMaxRequests] = useState("30");
  const [rateLimit, setRateLimit] = useState("1000");
  const [allowedDomains, setAllowedDomains] = useState("");
  const [allowedPorts, setAllowedPorts] = useState("");
  const [allowedPaths, setAllowedPaths] = useState("");
  const [excludedPaths, setExcludedPaths] = useState("");
  const [robotsOverride, setRobotsOverride] = useState(false);
  const [authType, setAuthType] = useState<AuthType>("none");
  const [cookieName, setCookieName] = useState("");
  const [cookieValue, setCookieValue] = useState("");
  const [headerName, setHeaderName] = useState("");
  const [headerValue, setHeaderValue] = useState("");
  const [basicUsername, setBasicUsername] = useState("");
  const [basicPassword, setBasicPassword] = useState("");
  const [testAccountRef, setTestAccountRef] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  const commaSeparated = (value: string) => value.split(",").map((item) => item.trim()).filter(Boolean);
  const numericCommaSeparated = (value: string) => commaSeparated(value).map(Number).filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);
  const handleProfileChange = (nextProfile: Profile) => {
    const next = PROFILE_COPY[nextProfile];
    setProfile(nextProfile);
    setMaxDepth(String(next.maxDepth));
    setMaxPages(String(next.maxRequests));
    setMaxRequests(String(next.maxRequests));
    setMaxConcurrency(String(next.maxConcurrency));
    setRateLimit(String(next.rate));
  };

  const buildAuthentication = (): ScanAuthentication | undefined => {
    if (authType === "cookie") return { type: "cookie", name: cookieName, value: cookieValue };
    if (authType === "header") return { type: "header", name: headerName, value: headerValue };
    if (authType === "basic") return { type: "basic", username: basicUsername, password: basicPassword };
    return undefined;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!acknowledged) {
      setError("You must acknowledge authorization to scan this target.");
      return;
    }
    if (profile === "aggressive" && commaSeparated(allowedDomains).length === 0) {
      setError("Aggressive assessments require an explicit allowed-domain list.");
      return;
    }
    setError(null);
    setLoading(true);
    try {
      const scan = await createScan(url, acknowledged, {
        max_depth: Number(maxDepth),
        max_pages: Number(maxPages),
        assessment_profile: profile,
        recon_mode: reconMode,
        sqli_validation_enabled: sqliValidationEnabled,
        sqli_extended_validation_enabled: sqliExtendedValidationEnabled,
        allowed_domains: commaSeparated(allowedDomains),
        allowed_ports: numericCommaSeparated(allowedPorts),
        allowed_paths: commaSeparated(allowedPaths),
        excluded_paths: commaSeparated(excludedPaths),
        max_requests: Number(maxRequests),
        max_concurrency: Number(maxConcurrency),
        rate_limit_per_host_ms: Number(rateLimit),
        robots_override: robotsOverride,
        authentication: buildAuthentication(),
        test_account_ref: testAccountRef.trim() || undefined,
      });
      router.push(`/scans/${scan.id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred.");
      setLoading(false);
    }
  };

  const copy = PROFILE_COPY[profile];
  const fieldClass = "w-full bg-[#0d1a17] border border-emerald-500/20 rounded-lg px-4 py-3 text-emerald-50 focus:outline-none focus:ring-2 focus:ring-emerald-500/50";

  return (
    <main className="min-h-screen bg-[#08110f] text-[#ecf4ee] px-6 py-12 sm:px-10">
      <div className="max-w-3xl mx-auto">
        <header className="mb-10">
          <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">New Autopsy Scan</h1>
          <p className="mt-3 text-emerald-100/60 text-lg">Define a public target, explicit scope, and bounded authorization before evidence collection begins.</p>
        </header>

        <form onSubmit={handleSubmit} className="space-y-6 bg-black/20 p-8 rounded-2xl border border-white/5">
          <div>
            <label htmlFor="url" className="block text-sm font-medium text-emerald-100/80 mb-2">Target URL or domain</label>
            <input id="url" type="text" required placeholder="https://example.com" value={url} onChange={(e) => setUrl(e.target.value)} className={fieldClass} />
            <p className="mt-2 text-xs text-emerald-100/45">Only public HTTP(S) targets are admitted. Private, loopback, link-local, metadata, reserved, and documentation networks are blocked.</p>
          </div>

          <div>
            <label htmlFor="profile" className="block text-sm font-medium text-emerald-100/80 mb-2">Assessment profile</label>
            <select id="profile" value={profile} onChange={(e) => handleProfileChange(e.target.value as Profile)} className={fieldClass}>
              <option value="safe">Safe</option>
              <option value="normal">Normal</option>
              <option value="aggressive">Aggressive</option>
            </select>
            <p className="mt-2 text-xs text-emerald-100/60">{copy.title}: {copy.description}</p>
          </div>

          <div>
            <label htmlFor="recon-mode" className="block text-sm font-medium text-emerald-100/80 mb-2">Recon Agent mode</label>
            <select id="recon-mode" value={reconMode} onChange={(e) => { const nextMode = e.target.value as "passive_only" | "active_safe"; setReconMode(nextMode); if (nextMode !== "active_safe") { setSqliValidationEnabled(false); setSqliExtendedValidationEnabled(false); } }} className={fieldClass}>
              <option value="passive_only">Passive-only</option>
              <option value="active_safe">Active-safe</option>
            </select>
            <p className="mt-2 text-xs text-emerald-100/60">Passive-only uses stored crawl evidence plus public Certificate Transparency and DNS observations. Active-safe adds bounded, scope-checked GET requests for robots/sitemaps and a small path list; it never submits forms or mutates target state.</p>
          </div>

          <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4">
            <div className="flex items-start gap-3"><input id="sqli-validation" type="checkbox" checked={sqliValidationEnabled} onChange={(e) => { const enabled = e.target.checked; setSqliValidationEnabled(enabled); if (!enabled) setSqliExtendedValidationEnabled(false); }} disabled={reconMode !== "active_safe"} className="mt-1 h-4 w-4 rounded border-orange-500/30 bg-[#0d1a17] text-orange-500 focus:ring-orange-500" /><label htmlFor="sqli-validation" className="text-sm text-orange-100/80">Enable safe SQL injection validation for eligible GET parameters</label></div>
            <p className="mt-2 text-xs text-orange-100/60">Requires Active-safe Recon. Sends only bounded syntax/boolean canaries to in-scope GET URLs; never submits forms, sends JSON/XML bodies, extracts data, or performs mutating requests. Headers, cookies, POST forms, and API bodies are reported as not tested.</p>
            <div className="mt-3 flex items-start gap-3"><input id="sqli-extended-validation" type="checkbox" checked={sqliExtendedValidationEnabled} onChange={(e) => setSqliExtendedValidationEnabled(e.target.checked)} disabled={!sqliValidationEnabled || reconMode !== "active_safe"} className="mt-1 h-4 w-4 rounded border-orange-500/30 bg-[#0d1a17] text-orange-500 focus:ring-orange-500" /><label htmlFor="sqli-extended-validation" className="text-xs text-orange-100/70">Enable capped timing-safe and NULL-only union stages</label></div>
            <p className="mt-2 text-[11px] text-orange-100/50">This optional extension never sends heavy/unbounded delays or data-bearing UNION expressions. It is disabled unless separately checked.</p>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div><label htmlFor="max-depth" className="block text-sm font-medium text-emerald-100/80 mb-2">Max crawl depth</label><input id="max-depth" type="number" min="0" max={copy.maxDepth} value={maxDepth} onChange={(e) => setMaxDepth(e.target.value)} className={fieldClass} /></div>
            <div><label htmlFor="max-pages" className="block text-sm font-medium text-emerald-100/80 mb-2">Max pages</label><input id="max-pages" type="number" min="1" max={copy.maxRequests} value={maxPages} onChange={(e) => setMaxPages(e.target.value)} className={fieldClass} /></div>
            <div><label htmlFor="max-requests" className="block text-sm font-medium text-emerald-100/80 mb-2">Maximum requests</label><input id="max-requests" type="number" min="1" max={copy.maxRequests} value={maxRequests} onChange={(e) => setMaxRequests(e.target.value)} className={fieldClass} /></div>
            <div><label htmlFor="max-concurrency" className="block text-sm font-medium text-emerald-100/80 mb-2">Concurrency</label><input id="max-concurrency" type="number" min="1" max={copy.maxConcurrency} value={maxConcurrency} onChange={(e) => setMaxConcurrency(e.target.value)} className={fieldClass} /></div>
            <div><label htmlFor="rate-limit" className="block text-sm font-medium text-emerald-100/80 mb-2">Per-host rate limit (ms)</label><input id="rate-limit" type="number" min={copy.rate} value={rateLimit} onChange={(e) => setRateLimit(e.target.value)} className={fieldClass} /></div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div><label htmlFor="allowed-domains" className="block text-sm font-medium text-emerald-100/80 mb-2">Allowed domains</label><input id="allowed-domains" type="text" placeholder="example.com, static.example.com" value={allowedDomains} onChange={(e) => setAllowedDomains(e.target.value)} className={fieldClass} /><p className="mt-2 text-xs text-emerald-100/45">Comma-separated. Empty means the submitted hostname only, except aggressive requires explicit confirmation.</p></div>
            <div><label htmlFor="allowed-paths" className="block text-sm font-medium text-emerald-100/80 mb-2">Allowed paths</label><input id="allowed-paths" type="text" placeholder="/, /docs, /jobs/*" value={allowedPaths} onChange={(e) => setAllowedPaths(e.target.value)} className={fieldClass} /><p className="mt-2 text-xs text-emerald-100/45">Comma-separated prefixes or simple wildcard patterns.</p></div>
            <div><label htmlFor="allowed-ports" className="block text-sm font-medium text-emerald-100/80 mb-2">Additional authorized ports</label><input id="allowed-ports" type="text" inputMode="numeric" placeholder="8102" value={allowedPorts} onChange={(e) => setAllowedPorts(e.target.value)} className={fieldClass} /><p className="mt-2 text-xs text-emerald-100/45">Optional comma-separated lab ports. Default HTTP/HTTPS ports remain allowed; every additional port is recorded in the signed scope.</p></div>
          </div>
          <div><label htmlFor="excluded-paths" className="block text-sm font-medium text-emerald-100/80 mb-2">Excluded paths</label><input id="excluded-paths" type="text" placeholder="/logout, /admin, /checkout/*" value={excludedPaths} onChange={(e) => setExcludedPaths(e.target.value)} className={fieldClass} /></div>

          <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-4">
            <div className="flex items-start gap-3"><input id="robots-override" type="checkbox" checked={robotsOverride} onChange={(e) => setRobotsOverride(e.target.checked)} disabled={profile !== "aggressive"} className="mt-1 h-4 w-4 rounded border-amber-500/30 bg-[#0d1a17] text-amber-500 focus:ring-amber-500" /><label htmlFor="robots-override" className="text-sm text-amber-100/75">Explicitly authorize a robots.txt override for this assessment.</label></div>
            <p className="mt-2 text-xs text-amber-100/55">Robots rules are respected by default. Override is disabled for Safe and Normal profiles and remains subject to deployment policy.</p>
          </div>

          <div className="border-t border-white/5 pt-6">
            <h2 className="text-sm font-semibold text-emerald-100/85">Optional test-account authentication</h2>
            <p className="mt-1 text-xs text-emerald-100/45">Secrets are encrypted before persistence and are never included in the authorization response or audit payload. Authenticated workflow checks remain unconfigured without a dedicated test account reference.</p>
            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <div><label htmlFor="auth-type" className="block text-sm font-medium text-emerald-100/80 mb-2">Authentication type</label><select id="auth-type" value={authType} onChange={(e) => setAuthType(e.target.value as AuthType)} className={fieldClass}><option value="none">None</option><option value="cookie">Cookie</option><option value="header">Header</option><option value="basic">Basic authentication</option></select></div>
              <div><label htmlFor="test-account-ref" className="block text-sm font-medium text-emerald-100/80 mb-2">Test account reference</label><input id="test-account-ref" type="text" placeholder="ticket or vault reference" value={testAccountRef} onChange={(e) => setTestAccountRef(e.target.value)} className={fieldClass} /></div>
            </div>
            {authType === "cookie" && <div className="mt-4 grid gap-4 sm:grid-cols-2"><input aria-label="Cookie name" type="text" placeholder="Cookie name" value={cookieName} onChange={(e) => setCookieName(e.target.value)} className={fieldClass} /><input aria-label="Cookie value" type="password" placeholder="Cookie value" value={cookieValue} onChange={(e) => setCookieValue(e.target.value)} className={fieldClass} /></div>}
            {authType === "header" && <div className="mt-4 grid gap-4 sm:grid-cols-2"><input aria-label="Header name" type="text" placeholder="Header name" value={headerName} onChange={(e) => setHeaderName(e.target.value)} className={fieldClass} /><input aria-label="Header value" type="password" placeholder="Header value" value={headerValue} onChange={(e) => setHeaderValue(e.target.value)} className={fieldClass} /></div>}
            {authType === "basic" && <div className="mt-4 grid gap-4 sm:grid-cols-2"><input aria-label="Basic username" type="text" placeholder="Username" value={basicUsername} onChange={(e) => setBasicUsername(e.target.value)} className={fieldClass} /><input aria-label="Basic password" type="password" placeholder="Password" value={basicPassword} onChange={(e) => setBasicPassword(e.target.value)} className={fieldClass} /></div>}
          </div>

          <div className="flex items-start gap-3"><input id="auth" type="checkbox" checked={acknowledged} onChange={(e) => setAcknowledged(e.target.checked)} className="mt-1 h-4 w-4 rounded border-emerald-500/30 bg-[#0d1a17] text-emerald-500 focus:ring-emerald-500 focus:ring-offset-[#08110f]" /><label htmlFor="auth" className="text-sm text-emerald-100/70">I confirm that I am authorized to scan this target or that it is a publicly accessible website permissible to scan under standard terms. I understand the selected scope, rate limits, and non-destructive assessment policy will be recorded with this scan.</label></div>

          {error && <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm">{error}</div>}
          <div className="pt-4 flex items-center justify-between"><Link href="/" className="text-sm text-emerald-500 hover:text-emerald-400 transition-colors">&larr; Back to Home</Link><button type="submit" disabled={loading} className="inline-flex h-11 items-center justify-center rounded-lg bg-emerald-500 px-6 text-sm font-medium text-emerald-950 transition-colors hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-400 focus:ring-offset-2 focus:ring-offset-[#08110f] disabled:opacity-50 disabled:cursor-not-allowed">{loading ? "Queueing..." : "Queue Assessment"}</button></div>
        </form>
      </div>
    </main>
  );
}
