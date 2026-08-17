export type HealthResponse = {
  status: "ok";
  service: string;
  database: "connected" | "unavailable";
  environment: string;
};

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

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

export type ScanResponse = {
  id: string;
  state: string;
  requested_url: string;
  error_reason: string | null;
  max_depth: number;
  max_pages: number;
};

export type ScanOptions = {
  max_depth?: number;
  max_pages?: number;
};

export type ObservationResponse = {
  id: string;
  category: string;
  subject: string;
  observation: string;
  classification: string;
  created_at: string;
  page_id: string | null;
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
  classification: "inferred";
  confidence: number;
  confidence_band: "low" | "medium" | "high";
  rule_version: string;
  evidence: TechnologyEvidence[];
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
  category: "security";
  subject: string;
  statement: string;
  classification: "OBSERVED" | "INFERRED";
  confidence: number;
  confidence_band: "low" | "medium" | "high";
  severity: "info" | "low" | "medium" | "high";
  rule_id: string;
  rule_version: string;
  limitations: string | null;
  page_id: string | null;
  evidence: SecurityEvidence[];
  created_at: string;
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
  scope: "page" | "site";
  metric_name: string;
  value: number | null;
  unit: string;
  classification: "OBSERVED" | "INFERRED" | "UNKNOWN";
  confidence: number;
  confidence_band: "low" | "medium" | "high" | "unknown";
  capture_mode: string;
  statement: string;
  limitations: string | null;
  page_id: string | null;
  evidence: PerformanceEvidence[];
  created_at?: string;
};

export type PerformancePageMetrics = {
  page_id: string;
  url: string;
  metrics: PerformanceMetric[];
};

export type PerformanceResponse = {
  scan_id: string;
  rule_version: string;
  metrics: PerformanceMetric[];
  page_metrics: PerformancePageMetrics[];
  site_metrics: PerformanceMetric[];
  diagnostics: PerformanceMetric[];
};

export type CrawledPage = {
  id: string;
  url: string;
  canonical_url: string;
  depth: number;
  status_code: number | null;
  title: string | null;
  discovered_from: string | null;
  discovered_from_page_id: string | null;
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
    throw new Error(errorData.detail || `Scan creation failed with ${response.status}`);
  }

  return response.json() as Promise<ScanResponse>;
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
  evidence: Array<{ type: string; observation: string; source: string; [key: string]: unknown }>;
  created_at: string;
};

export type ContentFinding = {
  id: string;
  category: "CONTENT";
  subject: string;
  statement: string;
  classification: "OBSERVED" | "INFERRED" | "UNKNOWN";
  page_id: string | null;
  evidence: Array<{ type: string; observation: string; source: string; [key: string]: unknown }>;
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
