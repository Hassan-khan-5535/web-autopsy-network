import {
  ScanResponse,
  CrawledPage,
  TechnologyDetection,
  ObservationResponse,
  SecurityFinding,
  PerformanceResponse,
  CauseOfDeathDiagnosis,
  AttackSurfaceGraphResponse,
  RiskPrioritizationResponse,
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

export const DEMO_ATTACK_SURFACE_GRAPH: AttackSurfaceGraphResponse = {
  scan_id: DEMO_SCAN_ID,
  correlation_version: "demo-preview-v1",
  nodes: [
    { id: "graph-domain", entity_type: "Domain", label: "demo-autopsy.store", classification: "OBSERVED", confidence: 100, attributes: {}, provenance: [{ source_type: "demo", source: "pre-analyzed report" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
    { id: "graph-host", entity_type: "Host", label: "demo-autopsy.store", classification: "OBSERVED", confidence: 100, attributes: {}, provenance: [{ source_type: "demo", source: "pre-analyzed report" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
    { id: "graph-service", entity_type: "Service", label: "https://demo-autopsy.store", classification: "OBSERVED", confidence: 100, attributes: { protocol: "https" }, provenance: [{ source_type: "demo", source: "stored target origin" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
    { id: "graph-app", entity_type: "Application", label: "Demo Store", classification: "OBSERVED", confidence: 100, attributes: { target: "https://demo-autopsy.store" }, provenance: [{ source_type: "demo", source: "stored scan" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
    { id: "graph-endpoint", entity_type: "Endpoint", label: "https://demo-autopsy.store/", classification: "OBSERVED", confidence: 100, attributes: { status_code: 200 }, provenance: [{ source_type: "demo", source: "stored crawled page" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
    { id: "graph-technology", entity_type: "Technology", label: "Next.js", classification: "INFERRED", confidence: 98, attributes: { category: "Framework" }, provenance: [{ source_type: "demo", source: "obs_next_meta" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
    { id: "graph-finding", entity_type: "Finding", label: "Content-Security-Policy", classification: "OBSERVED", confidence: 94, attributes: { severity: "HIGH", rule_id: "SEC-CSP-001" }, provenance: [{ source_type: "demo", source: "obs_csp_missing" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
    { id: "graph-evidence", entity_type: "Evidence", label: "Missing CSP header observation", classification: "OBSERVED", confidence: 100, attributes: { redacted: true }, provenance: [{ source_type: "demo", source: "obs_csp_missing" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
  ],
  edges: [
    { id: "edge-domain-host", source_node_id: "graph-domain", target_node_id: "graph-host", relationship_type: "OWNS", classification: "OBSERVED", confidence: 100, attributes: {}, provenance: [{ source_type: "demo", source: "stored target origin" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
    { id: "edge-host-service", source_node_id: "graph-host", target_node_id: "graph-service", relationship_type: "EXPOSES", classification: "OBSERVED", confidence: 100, attributes: {}, provenance: [{ source_type: "demo", source: "stored target origin" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
    { id: "edge-service-app", source_node_id: "graph-service", target_node_id: "graph-app", relationship_type: "ASSOCIATED_WITH", classification: "OBSERVED", confidence: 100, attributes: {}, provenance: [{ source_type: "demo", source: "stored scan" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
    { id: "edge-app-endpoint", source_node_id: "graph-app", target_node_id: "graph-endpoint", relationship_type: "EXPOSES", classification: "OBSERVED", confidence: 100, attributes: {}, provenance: [{ source_type: "demo", source: "stored crawled page" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
    { id: "edge-app-tech", source_node_id: "graph-app", target_node_id: "graph-technology", relationship_type: "DEPENDS_ON", classification: "INFERRED", confidence: 98, attributes: {}, provenance: [{ source_type: "demo", source: "obs_next_meta" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
    { id: "edge-finding-endpoint", source_node_id: "graph-finding", target_node_id: "graph-endpoint", relationship_type: "AFFECTS", classification: "OBSERVED", confidence: 94, attributes: { severity: "HIGH" }, provenance: [{ source_type: "demo", source: "obs_csp_missing" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
    { id: "edge-finding-evidence", source_node_id: "graph-finding", target_node_id: "graph-evidence", relationship_type: "HAS_EVIDENCE", classification: "OBSERVED", confidence: 94, attributes: {}, provenance: [{ source_type: "demo", source: "obs_csp_missing" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
    { id: "edge-priority", source_node_id: "graph-finding", target_node_id: "graph-endpoint", relationship_type: "POTENTIAL_ESCALATION_PRIORITY", classification: "INFERRED", confidence: 94, attributes: { priority_only: true, not_exploit_path: true }, provenance: [{ source_type: "demo", source: "prioritization preview" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" },
  ],
  updates: [{ id: "graph-update-demo", source_event: "demo:pre-analyzed", correlation_version: "demo-preview-v1", inserted_node_count: 8, refreshed_node_count: 0, inserted_edge_count: 8, refreshed_edge_count: 0, summary: { preview: true }, created_at: "2026-08-18T08:05:00Z" }],
  summary: { node_count: 8, edge_count: 8, entity_counts: { Application: 1, Domain: 1, Endpoint: 1, Evidence: 1, Finding: 1, Host: 1, Service: 1, Technology: 1 }, relationship_counts: { AFFECTS: 1, ASSOCIATED_WITH: 1, DEPENDS_ON: 1, EXPOSES: 2, HAS_EVIDENCE: 1, OWNS: 1, POTENTIAL_ESCALATION_PRIORITY: 1 }, priority_path_count: 1 },
  priority_paths: [{ finding: { id: "graph-finding", entity_type: "Finding", label: "Content-Security-Policy", classification: "OBSERVED", confidence: 94, attributes: { severity: "HIGH", rule_id: "SEC-CSP-001" }, provenance: [{ source_type: "demo", source: "obs_csp_missing" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" }, affected_asset: { id: "graph-endpoint", entity_type: "Endpoint", label: "https://demo-autopsy.store/", classification: "OBSERVED", confidence: 100, attributes: { status_code: 200 }, provenance: [{ source_type: "demo", source: "stored crawled page" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" }, relationship: { id: "edge-priority", source_node_id: "graph-finding", target_node_id: "graph-endpoint", relationship_type: "POTENTIAL_ESCALATION_PRIORITY", classification: "INFERRED", confidence: 94, attributes: { priority_only: true, not_exploit_path: true }, provenance: [{ source_type: "demo", source: "prioritization preview" }], first_seen_at: "2026-08-18T08:00:00Z", last_seen_at: "2026-08-18T08:05:00Z" }, disclaimer: "Prioritization only — not an exploit path or proof of exploitability." }],
  safety_contract: { prioritization_only: true, autonomous_exploitation_supported: false, network_requests_performed: false, secret_values_excluded: true, inferred_relationships_are_not_proof: true },
};

const demoRiskComponents = {
  severity: { weight: 25, score: 80, weighted_contribution: 20, explanation: "Stored finding severity: high." },
  confidence: { weight: 15, score: 94, weighted_contribution: 14.1, explanation: "Confidence derives from the pre-analyzed stored evidence." },
  exposure: { weight: 15, score: 70, weighted_contribution: 10.5, explanation: "The stored graph links the finding to the public application endpoint." },
  exploitability_indicators: { weight: 10, score: 65, weighted_contribution: 6.5, explanation: "Passive indicator only; no exploit attempt was performed." },
  asset_criticality: { weight: 15, score: 70, weighted_contribution: 10.5, explanation: "The affected stored asset is an application endpoint." },
  business_impact: { weight: 10, score: 80, weighted_contribution: 8, explanation: "Heuristic from stored severity and category only." },
  evidence_quality: { weight: 10, score: 75, weighted_contribution: 7.5, explanation: "Pre-analyzed evidence is marked moderate in this demo preview." },
};

export const DEMO_RISK_PRIORITIZATION: RiskPrioritizationResponse = {
  scan_id: DEMO_SCAN_ID,
  deterministic_version: "demo-preview-v1",
  summary: { available: true, overall_score: 77.1, risk_band: "high", eligible_assessment_count: 2, assessment_count: 2, summary: { overall_formula: "0.6 × highest eligible score + 0.4 × mean of highest five eligible scores" }, updated_at: "2026-08-18T08:05:00Z" },
  assessments: [
    { id: "risk-csp", security_finding_id: "sec_csp_missing", subject: "Content-Security-Policy", category: "security", severity: "high", rule_id: "SEC-CSP-001", risk_score: 77.1, risk_band: "high", eligible_for_prioritization: true, evidence_state: "candidate", score_components: demoRiskComponents, decision_notes: ["Demo preview uses deterministic, visible score components.", "This score prioritizes review and does not prove exploitability or business impact."], evidence_snapshot: { finding_evidence_count: 1, review_state: "candidate", secret_values_included: false }, updated_at: "2026-08-18T08:05:00Z" },
    { id: "risk-hsts", security_finding_id: "sec_hsts", subject: "HSTS Header", category: "security", severity: "medium", rule_id: "SEC-HSTS-001", risk_score: 52.4, risk_band: "medium", eligible_for_prioritization: true, evidence_state: "candidate", score_components: { ...demoRiskComponents, severity: { weight: 25, score: 55, weighted_contribution: 13.75, explanation: "Stored finding severity: medium." }, business_impact: { weight: 10, score: 55, weighted_contribution: 5.5, explanation: "Heuristic from stored severity and category only." } }, decision_notes: ["Demo preview uses deterministic, visible score components."], evidence_snapshot: { finding_evidence_count: 1, review_state: "candidate", secret_values_included: false }, updated_at: "2026-08-18T08:05:00Z" },
  ],
  trend: { prior_scan: null, score_delta: null, movement: "baseline", series: [{ scan_id: DEMO_SCAN_ID, overall_score: 77.1, risk_band: "high", updated_at: "2026-08-18T08:05:00Z" }], finding_changes: [], limitation: "No prior completed same-target risk summary is available for the demo preview." },
  scoring_contract: { model: "deterministic_heuristic", component_weights: { severity: 25, confidence: 15, exposure: 15, exploitability_indicators: 10, asset_criticality: 15, business_impact: 10, evidence_quality: 10 }, components_are_transparent: true, ml_assistance_enabled: false, ml_requirement: "Additive ML assistance requires sufficient documented training and evaluation data, calibration, and governance.", validated_evidence_can_be_overridden_by_ml: false, opaque_override_allowed: false, active_exploitation_supported: false, network_requests_performed: false },
};
