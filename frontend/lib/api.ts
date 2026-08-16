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
