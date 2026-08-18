import {
  ScanResponse,
  CrawledPage,
  TechnologyDetection,
  ObservationResponse,
  SiteArchitecture,
  DependencyItem,
  ApiEndpointItem,
  SecurityFinding,
  PerformanceResponse,
  AccessibilityFinding,
  ContentFinding,
  CauseOfDeathDiagnosis,
} from "./api";

export const DEMO_SCAN_ID = "demo-scan-autopsy";

export const DEMO_SCAN: ScanResponse = {
  id: DEMO_SCAN_ID,
  website_id: "demo-website-123",
  requested_url: "https://demo-autopsy.store",
  state: "COMPLETED",
  error_reason: null,
  max_depth: 2,
  max_pages: 15,
  max_concurrency: 2,
  request_delay_ms: 1000,
  same_domain_mode: "hostname",
  created_at: "2026-08-18T08:00:00Z",
  updated_at: "2026-08-18T08:05:00Z",
};

export const DEMO_PAGES: CrawledPage[] = [
  { id: "page_home", url: "https://demo-autopsy.store/", status_code: 200, depth: 0, title: "Demo Store - Home" },
  { id: "page_cart", url: "https://demo-autopsy.store/cart", status_code: 200, depth: 1, title: "Demo Store - Cart" },
  { id: "page_api", url: "https://demo-autopsy.store/api/v1/products", status_code: 200, depth: 1, title: "Products API" },
];

export const DEMO_TECHNOLOGIES: TechnologyDetection[] = [
  { id: "tech_next", name: "Next.js", category: "Framework", confidence: 0.98, evidence_ids: ["obs_next_meta"] },
  { id: "tech_react", name: "React", category: "UI Library", confidence: 0.95, evidence_ids: ["obs_react_dom"] },
  { id: "tech_tailwind", name: "Tailwind CSS", category: "Styling", confidence: 0.90, evidence_ids: ["obs_tw_class"] },
  { id: "tech_jquery", name: "jQuery (Legacy 1.12.4)", category: "Scripting", confidence: 0.85, evidence_ids: ["obs_jq_src"] },
];

export const DEMO_EVIDENCE: ObservationResponse[] = [
  { id: "obs_csp_missing", category: "SECURITY", subject: "Content-Security-Policy", observation: "HTTP header Content-Security-Policy is missing on initial HTML response.", classification: "OBSERVED" },
  { id: "obs_hsts_missing", category: "SECURITY", subject: "Strict-Transport-Security", observation: "HSTS header not present on HTTPS origin.", classification: "OBSERVED" },
  { id: "obs_lcp_delay", category: "PERFORMANCE", subject: "Largest Contentful Paint", observation: "LCP measured at 4.2 seconds due to unoptimized 3.5MB hero image.", classification: "OBSERVED" },
  { id: "inf_bundle_bloat", category: "PERFORMANCE", subject: "JavaScript Payload", observation: "Inferred execution bottleneck: 1.8MB synchronous JS parsed before paint.", classification: "INFERRED" },
  { id: "ai_summary_1", category: "SUMMARY", subject: "Executive Forensic Summary", observation: "The target exhibits severe render-blocking script overhead combined with missing security header defenses.", classification: "AI_INTERPRETATION" },
];

export const DEMO_SECURITY: SecurityFinding[] = [
  { id: "sec_csp_missing", category: "SECURITY", subject: "Content-Security-Policy", severity: "HIGH", statement: "Missing Content-Security-Policy header permits unauthorized cross-site script execution.", evidence: ["obs_csp_missing"], classification: "OBSERVED" },
  { id: "sec_hsts", category: "SECURITY", subject: "HSTS Header", severity: "MEDIUM", statement: "Strict-Transport-Security missing, exposing traffic to SSL stripping attacks.", evidence: ["obs_hsts_missing"], classification: "OBSERVED" },
];

export const DEMO_PERFORMANCE: PerformanceResponse = {
  page_id: "page_home",
  lcp_seconds: 4.2,
  fid_ms: 185,
  cls: 0.12,
  ttfb_ms: 320,
  metrics: [
    { id: "pm_lcp", metric_name: "LCP", value: 4.2, unit: "s", statement: "Largest Contentful Paint exceeds recommended 2.5s threshold.", classification: "OBSERVED" },
    { id: "pm_js", metric_name: "JavaScript Size", value: 1.8, unit: "MB", statement: "Excessive client JS bundle size.", classification: "OBSERVED" },
  ],
};

export const DEMO_DIAGNOSIS: CauseOfDeathDiagnosis = {
  id: "diag-demo-1",
  scan_id: DEMO_SCAN_ID,
  primary_issue_id: "sec_csp_missing",
  primary_category: "SECURITY",
  statement: "Critical Security Risk: Unprotected origin lacking Content-Security-Policy & excessive uncompressed JavaScript bundles causing render blocking.",
  impact_score: 88.5,
  confidence: 0.94,
  disclaimer: "Non-literal diagnostic summary based on observable HTTP, security headers, and browser performance metrics.",
  evidence: ["sec_csp_missing", "obs_lcp_delay", "inf_bundle_bloat"],
  created_at: new Date().toISOString(),
};
