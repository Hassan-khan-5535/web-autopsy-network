# Extension 5 — API Agent Integration Design

## Purpose

The API Agent builds a normalized API inventory from existing `ApiEndpoint`, `ReconEndpoint`, `ReconParameter`, `HTTPResponse`, and `HTTPObservation` evidence. It then applies deterministic, low-noise API security rules without issuing new target requests. The existing `/v1/scans/{scan_id}/api-endpoints` endpoint remains unchanged; Extension 5 adds `/v1/scans/{scan_id}/api-agent` for the richer analysis report.

## Task integration

The `api_agent` task runs in the analysis queue after `collection`, `api_intelligence`, and `http_agent`. When recon is enabled, it also waits for `recon` so its normalized endpoint and parameter inventory is complete. Diagnosis waits for `api_agent` in addition to the existing analysis tasks. No new database table or Alembic migration is required because findings use the existing `SecurityFinding` table with `category="api"`.

## Inventory inputs

| Input | Use |
|---|---|
| `ApiEndpoint` | Existing static API candidates from forms, JavaScript patterns, and JSON-like resources |
| `ReconEndpoint` | Normalized API, schema, GraphQL, and RPC route observations with scope and confidence |
| `ReconParameter` | Parameter names and locations; example values are never copied into findings |
| `HTTPResponse` and headers | Persisted status, content type, bounded body, `Allow`, auth, rate-limit, CORS, and error signals |
| Schema bodies | Bounded JSON OpenAPI/Swagger documents and conservative YAML-style path extraction |

The agent deduplicates routes by lowercased host and path, aggregates methods/content types/sources/statuses, and marks routes as documented only when a same-host captured schema lists the normalized path. It does not treat missing schema or missing auth/rate-limit headers as proof of a vulnerability.

## Rule catalog

| Rule ID | Detection |
|---|---|
| `API-INV-001` | Route discovered in bounded inventory but absent from a captured same-host schema |
| `API-METHOD-001` | Observed `TRACE` method from route inventory or `Allow` header |
| `API-PARAM-001` | Sensitive parameter name in URL/query/path location; values are omitted |
| `API-AUTH-001` | Informational review item when a sensitive route succeeds without an observed auth/session signal |
| `API-AUTH-002` | Basic authentication challenge observed over HTTP |
| `API-DATA-001` | High-signal sensitive field names in a successful bounded JSON-like response; values are omitted |
| `API-RATE-001` | Observed `Retry-After`, `X-RateLimit-*`, `RateLimit-*`, or 429 indicators |
| `API-ERROR-001` | High-signal stack, exception, SQL, debug, or framework markers in an API error body |
| `API-POLICY-001` | Wildcard CORS on a JSON-like API response; credentialed wildcard CORS remains Configuration Agent coverage |
| `API-SCHEMA-001` | Informational inventory item for a captured OpenAPI/Swagger schema and its security-scheme names |

Every finding includes rule ID, classification, confidence, severity, evidence, rule version, limitation text, and the existing `SecurityFinding` persistence contract. The report also exposes method counts, source counts, schema metadata, authentication and rate-limit indicators, and route inventory.

## Safety and limitations

The API Agent is passive and evidence-driven. It does not probe undocumented routes, send `OPTIONS` or method-variation requests, authenticate, submit forms, replay traffic, mutate state, exploit API methods, test IDOR/BOLA, or claim authorization failure based on an absent signal. Runtime browser network telemetry is only included where the existing persistence layer has stored a compatible response or normalized resource observation; the agent does not introduce a second browser instrumentation path.

An empty inventory is a valid outcome. It means that the current bounded scan did not capture API-like routes or schemas. It does not mean the target has no API or that the API is secure.
