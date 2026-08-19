export type HealthResponse = {
  status: "ok";
  service: string;
  database: "connected" | "unavailable";
  environment: string;
};

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL || "/api";

function apiErrorMessage(payload: unknown, fallback: string): string {
  if (typeof payload === "string" && payload.trim()) return payload;
  if (payload && typeof payload === "object") {
    const value = payload as { detail?: unknown; message?: unknown };
    const detail = value.detail ?? value.message;
    if (typeof detail === "string" && detail.trim()) return detail;
    if (Array.isArray(detail)) {
      const messages = detail.map((item) => {
        if (typeof item === "string") return item;
        if (item && typeof item === "object" && "msg" in item && typeof item.msg === "string") return item.msg;
        try {
          return JSON.stringify(item);
        } catch {
          return String(item);
        }
      }).filter(Boolean);
      if (messages.length > 0) return messages.join("; ");
    }
    try {
      return JSON.stringify(detail ?? payload);
    } catch {
      return fallback;
    }
  }
  return fallback;
}

export async function getHealth(): Promise<HealthResponse> {
  const response = await fetch(`${apiBaseUrl}/health`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Health request failed with ${response.status}`);
  }

  return response.json() as Promise<HealthResponse>;
}

export type DiagnosisIssue = {
  finding_id: string | null;
  category: string;
  subject: string;
  statement: string;
  classification: string;
  score: number;
  dimensions?: Record<string, number>;
  evidence?: Array<{ id: string; type: string; observation: string; source: string }> | string[];
  evidence_count?: number;
  dependency_context?: string | null;
};

export type CauseOfDeathDiagnosis = {
  id: string;
  scan_id: string;
  primary_issue?: DiagnosisIssue | null;
  secondary_issues?: DiagnosisIssue[];
  contributing_factors?: DiagnosisIssue[];
  primary_issue_id?: string | null;
  primary_category?: string;
  statement?: string;
  impact_score?: number;
  confidence: number;
  evidence_count?: number;
  evidence?: Array<{ id: string; type: string; observation: string; source: string }> | string[];
  ai_narrative?: string | null;
  ai_evidence?: string[];
  disclaimer: string;
  rubric?: Record<string, unknown>;
  created_at?: string | null;
  updated_at?: string | null;
};

export type ScanResponse = {
  id: string;
  website_id: string;
  state: string;
  status?: "queued" | "running" | "paused" | "completed" | "failed" | "cancelled";
  requested_url: string;
  error_reason: string | null;
  max_depth: number;
  max_pages: number;
  max_concurrency?: number;
  request_delay_ms?: number;
  same_domain_mode?: string;
  assessment_profile?: string | null;
  max_requests?: number | null;
  recon_mode?: "disabled" | "passive_only" | "active_safe" | string;
  requests_used?: number;
  created_at?: string;
  updated_at?: string;
  diagnosis?: CauseOfDeathDiagnosis | null;
};

export type ScanAuthentication =
  | { type: "cookie"; name: string; value: string }
  | { type: "header"; name: string; value: string }
  | { type: "basic"; username: string; password: string };

export type ScanOptions = {
  max_depth?: number;
  max_pages?: number;
  assessment_profile?: "safe" | "normal" | "aggressive";
  allowed_paths?: string[];
  excluded_paths?: string[];
  allowed_domains?: string[];
  max_requests?: number;
  max_concurrency?: number;
  rate_limit_per_host_ms?: number;
  robots_override?: boolean;
  authentication?: ScanAuthentication;
  test_account_ref?: string;
  expires_at?: string;
  recon_mode?: "passive_only" | "active_safe";
};

export type AssessmentAuthorization = {
  id: string | null;
  scan_id: string;
  authorization_type: string;
  actor_id: string;
  target_url: string;
  allowed_paths: string[];
  excluded_paths: string[];
  allowed_domains: string[];
  assessment_profile: string;
  robots_override: boolean;
  max_depth: number;
  max_pages: number;
  max_requests: number;
  max_concurrency: number;
  rate_limit_per_host_ms: number;
  test_account_ref: string | null;
  authentication_type: string;
  authentication_configured: boolean;
  secret_fingerprint: string | null;
  consent_hash: string | null;
  authorized_at: string | null;
  expires_at: string | null;
  policy_version: string;
  scope_json: Record<string, unknown>;
};

export type AssessmentAuditEvent = {
  id: string;
  scan_id: string;
  authorization_id: string | null;
  sequence_number: number;
  event_type: string;
  actor_id: string;
  payload: Record<string, unknown>;
  previous_hash: string;
  event_hash: string;
  created_at: string | null;
};

export type ObservationResponse = {
  id: string;
  category: string;
  subject: string;
  observation: string;
  classification: string;
  created_at?: string;
  page_id?: string | null;
  evidence?: string[];
};

export type TechnologyEvidence = {
  id: string;
  type: string;
  source: string;
  observation: string;
  match_rule: string;
  weight: number;
  page_id: string | null;
  created_at: string;
};

export type TechnologyDetection = {
  id: string;
  name: string;
  category: string;
  classification?: "inferred";
  confidence: number;
  confidence_band?: "low" | "medium" | "high";
  rule_version?: string;
  evidence?: TechnologyEvidence[];
  evidence_ids?: string[];
};

export type SecurityEvidence = {
  id: string;
  type: string;
  source: string;
  observation: string;
  page_id: string | null;
  captured_at: string;
};

export type SecurityFinding = {
  id: string;
  category: "security" | "SECURITY" | "configuration" | "api" | "vulnerability" | "secrets";
  subject: string;
  statement: string;
  classification: "OBSERVED" | "INFERRED";
  confidence?: number;
  confidence_band?: "low" | "medium" | "high";
  severity: "info" | "low" | "medium" | "high" | "HIGH" | "MEDIUM" | "LOW";
  rule_id?: string;
  rule_version?: string;
  limitations?: string | null;
  page_id?: string | null;
  evidence?: SecurityEvidence[] | string[];
  created_at?: string;
};

export type ConfigurationRule = {
  rule_id: string;
  title: string;
  prerequisites: string;
  detection_logic: string;
  evidence_requirements: string;
  severity: string;
  confidence: number;
  remediation_guidance: string;
  cwe: string[];
  owasp: string[];
  rule_version: string;
};

export type ConfigurationResponse = {
  scan_id: string;
  rule_version: string;
  rules: ConfigurationRule[];
  findings: SecurityFinding[];
  summary: {
    rule_count: number;
    finding_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
  };
};

export type VulnerabilityRule = {
  rule_id: string;
  title: string;
  risk_family: string;
  prerequisites: string;
  detection_logic: string;
  validation_mode: string;
  evidence_requirements: string;
  severity: string;
  confidence: number;
  remediation_guidance: string;
  cwe: string[];
  owasp: string[];
  rule_version: string;
};

export type SecretsRule = {
  rule_id: string;
  title: string;
  source_types: string[];
  prerequisites: string;
  detection_logic: string;
  suppression_logic: string;
  evidence_requirements: string;
  severity: string;
  confidence_tier: string;
  confidence: number;
  remediation_guidance: string;
  cwe: string[];
  owasp: string[];
  rule_version: string;
};

export type CVEIntelligenceMatch = {
  id: string;
  technology_id: string;
  cve_id: string | null;
  vendor: string | null;
  product: string;
  detected_version: string | null;
  version_source: string | null;
  detection_confidence: number;
  version_evidence_confidence: number;
  applicability_confidence: number;
  applicability_state: "matched" | "version_insufficient" | "no_match" | "stale_feed";
  match_reason: string;
  provenance: Record<string, unknown>;
  cwe: string[];
  cvss_score: number | null;
  cvss_vector: string | null;
  description: string | null;
  kev_listed: boolean;
  source_url: string | null;
  feed_retrieved_at: string | null;
  feed_is_stale: boolean | null;
  created_at: string;
};

export type CVEFeedRun = {
  id: string;
  source_name: string;
  source_url: string;
  retrieved_at: string;
  source_last_modified_at: string | null;
  record_count: number;
  stale_after_seconds: number;
  is_stale: boolean;
  status: string;
  error: string | null;
};

export type EvidenceReview = {
  id: string;
  security_finding_id: string | null;
  candidate_key: string;
  target: string;
  endpoint_or_asset: string;
  source_agent: string;
  rule_id: string;
  finding_state: "candidate" | "validated" | "rejected" | "inconclusive";
  evidence_quality: "strong" | "moderate" | "weak" | "none";
  confidence: number;
  prerequisites_valid: boolean;
  reproducibility_state: "not_run" | "reproduced_from_persisted_response" | "not_reproducible";
  observations: Array<Record<string, unknown>>;
  safe_request_metadata: Record<string, unknown> | null;
  provenance: Array<Record<string, unknown>>;
  redacted: boolean;
  created_at: string;
};

export type EvidenceResponse = {
  scan_id: string;
  rule_version: string;
  reviews: EvidenceReview[];
  summary: {
    candidate_count: number;
    state_counts: Record<string, number>;
    quality_counts: Record<string, number>;
    reproducibility_counts: Record<string, number>;
    validated_count: number;
    inconclusive_count: number;
    rejected_count: number;
  };
  provenance_contract: {
    required_fields: string[];
    safe_request_metadata_included_when_available: boolean;
    secret_values_redacted: boolean;
    signature_alone_is_proof: boolean;
  };
};

export type AttackSurfaceGraphNode = {
  id: string;
  entity_type: string;
  label: string;
  classification: string;
  confidence: number;
  attributes: Record<string, unknown>;
  provenance: Array<Record<string, unknown>>;
  first_seen_at: string;
  last_seen_at: string;
};

export type AttackSurfaceGraphEdge = {
  id: string;
  source_node_id: string;
  target_node_id: string;
  relationship_type: string;
  classification: string;
  confidence: number;
  attributes: Record<string, unknown>;
  provenance: Array<Record<string, unknown>>;
  first_seen_at: string;
  last_seen_at: string;
};

export type AttackSurfaceGraphUpdate = {
  id: string;
  source_event: string;
  correlation_version: string;
  inserted_node_count: number;
  refreshed_node_count: number;
  inserted_edge_count: number;
  refreshed_edge_count: number;
  summary: Record<string, unknown>;
  created_at: string;
};

export type AttackSurfaceGraphResponse = {
  scan_id: string;
  correlation_version: string;
  nodes: AttackSurfaceGraphNode[];
  edges: AttackSurfaceGraphEdge[];
  updates: AttackSurfaceGraphUpdate[];
  summary: {
    node_count: number;
    edge_count: number;
    entity_counts: Record<string, number>;
    relationship_counts: Record<string, number>;
    priority_path_count: number;
  };
  priority_paths: Array<{
    finding: AttackSurfaceGraphNode;
    affected_asset: AttackSurfaceGraphNode;
    relationship: AttackSurfaceGraphEdge;
    disclaimer: string;
  }>;
  safety_contract: {
    prioritization_only: boolean;
    autonomous_exploitation_supported: boolean;
    network_requests_performed: boolean;
    secret_values_excluded: boolean;
    inferred_relationships_are_not_proof: boolean;
  };
};

export type RiskScoreComponent = {
  weight: number;
  score: number;
  weighted_contribution: number;
  explanation: string;
};

export type RiskAssessmentResponse = {
  id: string;
  security_finding_id: string;
  subject: string;
  category: string;
  severity: string;
  rule_id: string;
  risk_score: number;
  risk_band: string;
  eligible_for_prioritization: boolean;
  evidence_state: string;
  score_components: Record<string, RiskScoreComponent>;
  decision_notes: string[];
  evidence_snapshot: Record<string, unknown>;
  updated_at: string;
};

export type RiskPrioritizationResponse = {
  scan_id: string;
  deterministic_version: string;
  summary: {
    available: boolean;
    overall_score: number;
    risk_band: string;
    eligible_assessment_count: number;
    assessment_count: number;
    summary: Record<string, unknown>;
    updated_at?: string;
  };
  assessments: RiskAssessmentResponse[];
  trend: {
    prior_scan: { scan_id: string; overall_score: number; risk_band: string; updated_at: string } | null;
    score_delta: number | null;
    movement: string;
    series: Array<{ scan_id: string; overall_score: number; risk_band: string; updated_at: string }>;
    finding_changes: Array<Record<string, unknown>>;
    limitation: string;
  };
  scoring_contract: {
    model: string;
    component_weights: Record<string, number>;
    components_are_transparent: boolean;
    ml_assistance_enabled: boolean;
    ml_requirement: string;
    validated_evidence_can_be_overridden_by_ml: boolean;
    opaque_override_allowed: boolean;
    active_exploitation_supported: boolean;
    network_requests_performed: boolean;
  };
};

export type PostureTimelineSnapshot = {
  scan_id: string;
  overall_risk_score: number;
  risk_band: string;
  posture_summary: {
    asset_count: number;
    endpoint_count: number;
    header_observation_count: number;
    technology_count: number;
    security_finding_count: number;
    vulnerability_count: number;
    configuration_finding_count: number;
    secret_finding_count: number;
    severity_counts: Record<string, number>;
  };
  comparison_summary: {
    baseline: boolean;
    prior_scan_id: string | null;
    difference_id: string | null;
    change_counts: Record<string, number>;
    item_count?: number;
    limitation?: string;
  };
  created_at: string;
};

export type PostureTimelineResponse = {
  website_id: string;
  posture_version: string;
  snapshots: PostureTimelineSnapshot[];
  limitation: string;
};

export type RecurringScheduleResponse = {
  id: string;
  website_id: string;
  source_scan_id: string;
  target_url: string;
  cadence: "weekly" | string;
  enabled: boolean;
  next_run_at: string;
  last_run_at: string | null;
  last_scan_id: string | null;
  blocked_at: string | null;
  last_block_reason: string | null;
  created_by: string;
  created_at: string;
};

export type CVEIntelligenceResponse = {
  scan_id: string;
  rule_version: string;
  matches: CVEIntelligenceMatch[];
  feed_runs: CVEFeedRun[];
  summary: {
    technology_count: number;
    matched_count: number;
    version_insufficient_count: number;
    no_match_count: number;
    stale_feed_count: number;
    kev_count: number;
    feed_count: number;
  };
  confidence_contract: {
    detected_version_confidence_is_separate: boolean;
    cve_applicability_requires_explicit_version: boolean;
    family_only_detection_is_not_applicable: boolean;
  };
};

export type SecretsResponse = {
  scan_id: string;
  rule_version: string;
  rules: SecretsRule[];
  findings: SecurityFinding[];
  summary: {
    rule_count: number;
    finding_count: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    confidence_tiers: Record<string, number>;
  };
  redaction: {
    values_persisted: boolean;
    values_logged: boolean;
    values_returned: boolean;
    stored_evidence_mode: string;
  };
};

export type VulnerabilityResponse = {
  scan_id: string;
  rule_version: string;
  rules: VulnerabilityRule[];
  findings: SecurityFinding[];
  summary: {
    rule_count: number;
    detector_count: number;
    finding_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    info_count: number;
    classification_counts: Record<string, number>;
  };
  safe_validation: {
    mode: string;
    network_requests_issued: number;
    payloads_sent: number;
    forms_submitted: number;
    mutating_requests_issued: number;
    authentication_attempts: number;
  };
};

export type PerformanceEvidence = {
  id: string;
  type: string;
  source: string;
  observation: string;
  page_id: string | null;
  captured_at: string;
};

export type PerformanceMetric = {
  id: string;
  scope?: "page" | "site";
  metric_name: string;
  value: number | null;
  unit: string;
  classification: "OBSERVED" | "INFERRED" | "UNKNOWN";
  confidence?: number;
  confidence_band?: "low" | "medium" | "high" | "unknown";
  capture_mode?: string;
  statement: string;
  limitations?: string | null;
  page_id?: string | null;
  evidence?: PerformanceEvidence[];
  created_at?: string;
};

export type PerformancePageMetrics = {
  page_id: string;
  url: string;
  metrics: PerformanceMetric[];
};

export type PerformanceResponse = {
  scan_id?: string;
  rule_version?: string;
  page_id?: string;
  lcp_seconds?: number | null;
  fid_ms?: number | null;
  cls?: number | null;
  ttfb_ms?: number | null;
  metrics: PerformanceMetric[];
  page_metrics?: PerformancePageMetrics[];
  site_metrics?: PerformanceMetric[];
  diagnostics?: PerformanceMetric[];
};

export type CrawledPage = {
  id: string;
  url: string;
  canonical_url?: string | null;
  depth: number;
  status_code: number | null;
  title: string | null;
  discovered_from?: string | null;
  discovered_from_page_id?: string | null;
};

export async function createScan(
  url: string,
  authorization_acknowledged: boolean,
  options: ScanOptions = {},
): Promise<ScanResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ url, authorization_acknowledged, ...options }),
    cache: "no-store",
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(apiErrorMessage(errorData, `Scan creation failed with ${response.status}`));
  }

  return response.json() as Promise<ScanResponse>;
}

export async function getAssessmentAuthorization(id: string): Promise<AssessmentAuthorization> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/assessment/authorization`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Failed to fetch assessment authorization for scan ${id}`);
  return response.json() as Promise<AssessmentAuthorization>;
}

export async function getAssessmentAudit(id: string): Promise<AssessmentAuditEvent[]> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/assessment/audit`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Failed to fetch assessment audit for scan ${id}`);
  return response.json() as Promise<AssessmentAuditEvent[]>;
}

export async function pauseScan(id: string): Promise<ScanProgressResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/pause`, { method: "POST", cache: "no-store" });
  if (!response.ok) throw new Error(`Pause request failed with ${response.status}`);
  return response.json() as Promise<ScanProgressResponse>;
}

export async function resumeScan(id: string): Promise<ScanProgressResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/resume`, { method: "POST", cache: "no-store" });
  if (!response.ok) throw new Error(`Resume request failed with ${response.status}`);
  return response.json() as Promise<ScanProgressResponse>;
}

export async function getScanDiagnosis(id: string): Promise<CauseOfDeathDiagnosis> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/diagnosis`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Failed to fetch diagnosis for scan ${id}`);
  return response.json() as Promise<CauseOfDeathDiagnosis>;
}

export async function getScan(id: string): Promise<ScanResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch scan ${id}`);
  }

  return response.json() as Promise<ScanResponse>;
}

export async function getScanEvidence(id: string): Promise<ObservationResponse[]> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/evidence`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch evidence for scan ${id}`);
  }

  return response.json() as Promise<ObservationResponse[]>;
}

export async function getScanTechnologies(id: string): Promise<TechnologyDetection[]> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/technologies`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch technologies for scan ${id}`);
  }

  return response.json() as Promise<TechnologyDetection[]>;
}

export async function getScanSecurity(id: string): Promise<SecurityFinding[]> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/security`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch security findings for scan ${id}`);
  }

  return response.json() as Promise<SecurityFinding[]>;
}

export async function getScanConfiguration(id: string): Promise<ConfigurationResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/configuration`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch configuration findings for scan ${id}`);
  }

  return response.json() as Promise<ConfigurationResponse>;
}

export async function getScanAPIAgent(id: string): Promise<APIAgentResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/api-agent`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch API Agent report for scan ${id}`);
  }

  return response.json() as Promise<APIAgentResponse>;
}

export async function getScanEvidenceReviews(id: string): Promise<EvidenceResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/evidence-agent`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch evidence reviews for scan ${id}`);
  }
  return response.json() as Promise<EvidenceResponse>;
}

export async function getScanAttackSurfaceGraph(id: string): Promise<AttackSurfaceGraphResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/attack-surface-graph`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch Attack Surface Graph for scan ${id}`);
  }
  return response.json() as Promise<AttackSurfaceGraphResponse>;
}

export async function getScanRiskPrioritization(id: string): Promise<RiskPrioritizationResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/risk-prioritization`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch Risk Prioritization for scan ${id}`);
  }
  return response.json() as Promise<RiskPrioritizationResponse>;
}

export async function getScanPostureTimeline(id: string): Promise<PostureTimelineResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/posture-timeline`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Failed to fetch security posture timeline for scan ${id}`);
  return response.json() as Promise<PostureTimelineResponse>;
}

export async function getRecurringSchedule(id: string): Promise<RecurringScheduleResponse | null> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/recurring-schedule`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Failed to fetch recurring schedule for scan ${id}`);
  return response.json() as Promise<RecurringScheduleResponse | null>;
}

export async function createWeeklySchedule(id: string): Promise<RecurringScheduleResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/recurring-schedule`, {
    method: "POST",
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(apiErrorMessage(payload, `Failed to create recurring schedule for scan ${id}`));
  }
  return response.json() as Promise<RecurringScheduleResponse>;
}

export async function updateRecurringSchedule(id: string, enabled: boolean): Promise<RecurringScheduleResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/recurring-schedules/${id}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ enabled }),
    cache: "no-store",
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(apiErrorMessage(payload, `Failed to update recurring schedule ${id}`));
  }
  return response.json() as Promise<RecurringScheduleResponse>;
}

export async function getScanCVEIntelligence(id: string): Promise<CVEIntelligenceResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/cve-intelligence`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch CVE intelligence for scan ${id}`);
  }

  return response.json() as Promise<CVEIntelligenceResponse>;
}

export async function getScanSecrets(id: string): Promise<SecretsResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/secrets`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch Secrets Agent report for scan ${id}`);
  }

  return response.json() as Promise<SecretsResponse>;
}

export async function getScanVulnerabilityAgent(id: string): Promise<VulnerabilityResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/vulnerability-agent`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch Vulnerability Agent report for scan ${id}`);
  }

  return response.json() as Promise<VulnerabilityResponse>;
}

export async function getScanPerformance(id: string): Promise<PerformanceResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/performance`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch performance metrics for scan ${id}`);
  }

  return response.json() as Promise<PerformanceResponse>;
}

export async function getScanPages(id: string): Promise<CrawledPage[]> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/pages`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch pages for scan ${id}`);
  }

  return response.json() as Promise<CrawledPage[]>;
}

export type SiteTreeNode = {
  id: string;
  url: string;
  title: string | null;
  depth: number;
  status_code: number | null;
  children: SiteTreeNode[];
};

export type LinkSummary = {
  total_internal_links: number;
  total_external_links: number;
  total_links: number;
};

export type FormField = {
  tag: string;
  name: string | null;
  type: string;
  required: boolean;
  placeholder: string | null;
};

export type FormItem = {
  page_id: string;
  page_url: string;
  action: string;
  method: string;
  name: string | null;
  id: string | null;
  fields: FormField[];
};

export type PageTypeInference = {
  page_id: string;
  url: string;
  inferred_type: string;
  classification: "inferred";
  confidence: number;
  reason: string;
};

export type SiteArchitecture = {
  site_tree: SiteTreeNode[];
  link_summary: LinkSummary;
  form_inventory: FormItem[];
  page_types: PageTypeInference[];
};

export type DependencyItem = {
  id: string;
  domain: string;
  category: string;
  classification: "inferred";
  confidence: number;
  reference_count: number;
  sample_resource_urls: string[];
  created_at: string;
};

export type ApiEndpointItem = {
  id: string;
  url_or_path: string;
  http_method: string;
  content_type: string | null;
  classification: "inferred";
  confidence: number;
  discovered_from_source: string;
  created_at: string;
};

export type APIAgentRule = {
  rule_id: string;
  title: string;
  prerequisites: string;
  detection_logic: string;
  evidence_requirements: string;
  severity: string;
  confidence: number;
  remediation_guidance: string;
  cwe: string[];
  owasp: string[];
  rule_version: string;
};

export type APIAgentInventoryItem = {
  route: string;
  path: string;
  host: string;
  methods: string[];
  content_types: string[];
  sources: string[];
  status_codes: number[];
  scope_statuses: string[];
  confidence: number;
  parameter_names: string[];
  documented: boolean;
  observed: boolean;
  is_schema: boolean;
};

export type APIAgentSchema = {
  url: string;
  host: string;
  format: string;
  version: string | null;
  paths: string[];
  security_schemes: string[];
  publicly_observable: boolean;
};

export type APIAgentResponse = {
  scan_id: string;
  rule_version: string;
  rules: APIAgentRule[];
  inventory: APIAgentInventoryItem[];
  schemas: APIAgentSchema[];
  indicators: {
    rate_limit: { observed: boolean; routes: Array<Record<string, unknown>>; absence_not_escalated: boolean };
    authentication: { routes: Array<Record<string, unknown>>; absence_not_escalated: boolean };
    errors: Array<Record<string, unknown>>;
    policy: Array<Record<string, unknown>>;
    methods: Array<{ route: string; methods: string[] }>;
  };
  findings: SecurityFinding[];
  summary: {
    inventory_count: number;
    schema_count: number;
    documented_route_count: number;
    undocumented_route_count: number;
    source_counts: Record<string, number>;
    method_counts: Record<string, number>;
    rate_limit_route_count: number;
    auth_signal_route_count: number;
    error_route_count: number;
    policy_route_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    info_count: number;
    finding_count: number;
  };
};

export type ReconAsset = {
  id: string;
  asset_type: string;
  value: string;
  hostname: string | null;
  source: string;
  discovery_mode: string;
  classification: string;
  scope_status: string;
  confidence: number;
  attributes: Record<string, unknown>;
  evidence: string[];
  created_at: string;
};

export type ReconEndpoint = {
  id: string;
  endpoint_kind: string;
  url_or_path: string;
  http_method: string;
  source: string;
  discovery_mode: string;
  classification: string;
  confidence: number;
  scope_status: string;
  status_code: number | null;
  content_type: string | null;
  page_id: string | null;
  attributes: Record<string, unknown>;
  evidence: string[];
  created_at: string;
};

export type ReconParameter = {
  id: string;
  endpoint_id: string | null;
  page_id: string | null;
  name: string;
  location: string;
  source: string;
  discovery_mode: string;
  classification: string;
  confidence: number;
  scope_status: string;
  example_value: string | null;
  evidence: string[];
  created_at: string;
};

export type ReconResponse = {
  scan_id: string;
  mode: string;
  requests_used: number;
  max_requests: number;
  assets: ReconAsset[];
  endpoints: ReconEndpoint[];
  parameters: ReconParameter[];
  summary: {
    asset_count: number;
    endpoint_count: number;
    parameter_count: number;
    cloud_asset_candidates: number;
    subdomain_count: number;
    login_admin_sensitive_count: number;
  };
};

export type HTTPObservation = {
  id: string;
  page_id: string | null;
  http_response_id: string | null;
  observation_type: string;
  subject: string;
  source: string;
  classification: string;
  confidence: number;
  value: Record<string, unknown>;
  redacted: boolean;
  truncated: boolean;
  created_at: string;
};

export type HTTPObservationResponse = {
  scan_id: string;
  rule_version: string;
  observations: HTTPObservation[];
  summary: {
    observation_count: number;
    types: Record<string, number>;
    redacted_count: number;
    truncated_count: number;
  };
};

export async function getScanArchitecture(id: string): Promise<SiteArchitecture> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/architecture`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch architecture for scan ${id}`);
  }

  return response.json() as Promise<SiteArchitecture>;
}

export async function getScanDependencies(id: string): Promise<DependencyItem[]> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/dependencies`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch dependencies for scan ${id}`);
  }

  return response.json() as Promise<DependencyItem[]>;
}

export async function getScanApiEndpoints(id: string): Promise<ApiEndpointItem[]> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/api-endpoints`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch API endpoints for scan ${id}`);
  }

  return response.json() as Promise<ApiEndpointItem[]>;
}

export async function getScanRecon(id: string): Promise<ReconResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/recon`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch recon data for scan ${id}`);
  }

  return response.json() as Promise<ReconResponse>;
}

export async function getScanHTTPObservations(id: string): Promise<HTTPObservationResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/http-observations`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch HTTP observations for scan ${id}`);
  }

  return response.json() as Promise<HTTPObservationResponse>;
}

export type PageRenderedResponse = {
  page_id: string;
  url: string;
  raw_body: string | null;
  rendered_body: string | null;
  timing_data: Record<string, unknown> | null;
  resources: Array<{

    id: string;
    url: string;
    type: string;
    capture_source: string;
  }>;
  console_logs: Array<{
    id: string;
    type: string;
    text: string;
  }>;
};

export async function getScanPageRendered(
  scanId: string,
  pageId: string
): Promise<PageRenderedResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${scanId}/pages/${pageId}/rendered`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch rendered DOM for page ${pageId}`);
  }

  return response.json() as Promise<PageRenderedResponse>;
}


export type AccessibilityFinding = {
  id: string;
  category: "ACCESSIBILITY";
  subject: string;
  statement: string;
  classification: "OBSERVED" | "INFERRED" | "UNKNOWN";
  disclaimer: string;
  page_id: string | null;
  evidence: Array<{ id?: string; type: string; observation: string; source: string; [key: string]: unknown }>;
  created_at: string;
};

export type ContentFinding = {
  id: string;
  category: "CONTENT";
  subject: string;
  statement: string;
  classification: "OBSERVED" | "INFERRED" | "UNKNOWN";
  page_id: string | null;
  evidence: Array<{ id?: string; type: string; observation: string; source: string; [key: string]: unknown }>;
  created_at: string;
};

export async function getScanAccessibility(id: string): Promise<AccessibilityFinding[]> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/accessibility`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch accessibility findings for scan ${id}`);
  }

  return response.json() as Promise<AccessibilityFinding[]>;
}

export async function getScanContent(id: string): Promise<ContentFinding[]> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/content`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch content findings for scan ${id}`);
  }

  return response.json() as Promise<ContentFinding[]>;
}

export type AIInterpretationResponse = {
  id: string;
  category: string;
  subject: string;
  statement: string;
  classification: "ai_interpretation";
  evidence: string[];
  created_at: string;
};

export async function askScanQuestion(
  scanId: string,
  question: string
): Promise<AIInterpretationResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${scanId}/ask`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ question }),
    cache: "no-store",
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(apiErrorMessage(errorData, `Question failed with status ${response.status}`));
  }

  return response.json() as Promise<AIInterpretationResponse>;
}


export type WebsiteScanHistoryItem = {
  id: string;
  state: string;
  requested_url: string;
  created_at: string;
  page_count: number;
};

export type DiffItem = {
  id: string;
  category: "structure" | "technology" | "dependencies" | "security" | "performance" | "content";
  change: string;
  before: unknown;
  after: unknown;
  classification: "OBSERVED" | "INFERRED" | "AI_INTERPRETATION" | "UNKNOWN";
  evidence: string[];
  note: string | null;
};

export type ScanDifferenceResponse = {
  difference_id: string;
  scan_a: { id: string; website_id: string; requested_url: string; state: string; created_at: string | null };
  scan_b: { id: string; website_id: string; requested_url: string; state: string; created_at: string | null };
  categories: Record<string, { items: DiffItem[]; [key: string]: unknown }>;
  items: DiffItem[];
  item_count: number;
  performance_threshold: number;
  ai_summary: {
    summary: string;
    evidence: string[];
    classification: string;
    status: string;
  };
};

export type WebsiteScanHistoryResponse = {
  website_id: string;
  canonical_origin: string;
  scans: WebsiteScanHistoryItem[];
};

export async function getWebsiteScans(websiteId: string): Promise<WebsiteScanHistoryResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/websites/${websiteId}/scans`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Failed to fetch scan history for website ${websiteId}`);
  return response.json() as Promise<WebsiteScanHistoryResponse>;
}

export async function compareScans(scanA: string, scanB: string): Promise<ScanDifferenceResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/compare`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ scan_a: scanA, scan_b: scanB }),
    cache: "no-store",
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Comparison failed with status ${response.status}`);
  }
  return response.json() as Promise<ScanDifferenceResponse>;
}


export type ScanTaskProgress = {
  id: string;
  task_key: string;
  task_type: string;
  queue: string;
  status: string;
  attempt: number;
  max_retries: number;
  progress: number;
  dependencies: string[];
  event_requirements: string[];
  error_reason: string | null;
  started_at: string | null;
  finished_at: string | null;
  deadline_at: string | null;
};

export type ScanProgressResponse = {
  scan_id: string;
  state: string;
  status?: "queued" | "running" | "paused" | "completed" | "failed" | "cancelled";
  cancel_requested: boolean;
  percent: number;
  completed_tasks: number;
  total_tasks: number;
  queue_position: number | null;
  estimated_wait_seconds: number;
  tasks: ScanTaskProgress[];
  events: Array<{ type: string; event_key: string | null; payload: Record<string, unknown>; created_at: string }>;
  orchestration: Record<string, unknown>;
  budget: Record<string, unknown>;
};

export async function getScanProgress(id: string): Promise<ScanProgressResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/progress`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error(`Failed to fetch progress for scan ${id}`);
  return response.json() as Promise<ScanProgressResponse>;
}

export async function cancelScan(id: string): Promise<ScanProgressResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${id}/cancel`, {
    method: "POST",
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.detail || `Cancellation failed with status ${response.status}`);
  }
  return response.json() as Promise<ScanProgressResponse>;
}
