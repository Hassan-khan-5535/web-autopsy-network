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

