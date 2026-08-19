# Web Autopsy Network

**Web Autopsy Network** is an evidence-backed web intelligence and security assessment platform for authorized research. It collects observable HTTP and browser evidence, normalizes reconnaissance results, analyzes configuration and security posture with deterministic rules, and produces a report that distinguishes measured facts from derived conclusions and unknowns.

> **Safety boundary:** The platform is detection- and reporting-only. Every assessment requires recorded authorization, explicit scope, bounded request controls, SSRF-resistant admission checks, robots-policy handling, and an immutable audit record. It does not perform destructive exploitation, persistence, credential theft, evasion, denial of service, or target data modification.

| Resource | Link |
|---|---|
| Live frontend | [Open the running Web Autopsy Network UI](https://3001-iuz98nix5x3egg8bbruc3-2761d934.us2.manus.computer) |
| Repository | [atifkhani397/web-autopsy-network](https://github.com/atifkhani397/web-autopsy-network) |
| Live verification record | [`docs/extension5-live-verification.md`](docs/extension5-live-verification.md) |
| API Agent design | [`docs/extension5-api-agent-integration-design.md`](docs/extension5-api-agent-integration-design.md) |
| Configuration Agent design | [`docs/configuration-agent-integration-design.md`](docs/configuration-agent-integration-design.md) |

## Platform status

Extensions 1 through 5 are implemented. Extension 5, the **API Agent**, is included in the `main` branch and has been verified against a fresh real bounded scan of `https://www.python.org/`. The verification scan completed at 100%, and its `api_agent` task reached `SUCCEEDED` after the existing API Intelligence, HTTP Agent, and Recon Agent dependencies completed.

The latest completed release before this extension was `431cdfd`; the Extension 5 implementation is pending its final release commit after validation.

## Implemented capabilities

| Extension | Capability | Implementation status |
|---|---|---|
| Extension 1 | Scope, consent, authorization records, encrypted authentication secrets, immutable audit trail, scan pause/resume/cancel, assessment profiles, bounded crawl controls, and SSRF-resistant admission | Complete |
| Extension 2 | Passive Certificate Transparency and DNS observations, technology fingerprints, scoped crawling, robots and sitemap processing, JavaScript/API/parameter extraction, sensitive-path classification, and cloud-asset candidate detection | Complete |
| Extension 3 | Central HTTP behavior analysis with bounded response capture, secret redaction, status and header observations, cookies, redirects, cache behavior, content type, TLS, CORS, compression, security policy, and anomalies | Complete |
| Extension 4 | Configuration Agent with 11 independently testable, low-false-positive rules and a report UI backed by persisted `SecurityFinding` records | Complete |
| Extension 5 | API Agent with normalized route/schema inventory, method and parameter analysis, authentication-boundary indicators, data-exposure and error checks, rate-limit and CORS indicators, and a typed report UI | Complete |

The API Agent combines the existing API Intelligence catalog, normalized Recon endpoints and parameters, captured OpenAPI/Swagger documents, and persisted HTTP response evidence. It does not probe undocumented routes, send method-variation requests, authenticate, submit forms, or mutate target data. Its report endpoint is:

```text
GET /v1/scans/{scan_id}/api-agent
```

The API Agent rules are:

| Rule ID | Detection area |
|---|---|
| `API-INV-001` | Undocumented API route candidates against captured same-host schemas |
| `API-METHOD-001` | Observed TRACE method exposure |
| `API-PARAM-001` | Sensitive parameter names in URL/query/path locations |
| `API-AUTH-001` | Informational authentication-boundary review for sensitive routes |
| `API-AUTH-002` | Basic authentication challenge over HTTP |
| `API-DATA-001` | Sensitive field names in bounded JSON-like API responses |
| `API-RATE-001` | Retry-After, rate-limit headers, and 429 indicators |
| `API-ERROR-001` | High-signal API error detail markers |
| `API-POLICY-001` | Wildcard CORS on JSON-like API responses |
| `API-SCHEMA-001` | Captured public OpenAPI/Swagger schema metadata |

The Configuration Agent rules are:

| Rule ID | Detection area |
|---|---|
| `CFG-HEADERS-001` | Missing or weak security headers |
| `CFG-CORS-001` | Unsafe CORS configuration |
| `CFG-TLS-001` | TLS transport weakness observations |
| `CFG-TLS-002` | TLS certificate or protocol observations that require review |
| `CFG-DIR-001` | Directory-listing indicators |
| `CFG-EXPOSED-ARTIFACT-001` | Safely detectable `.git`, `.env`, configuration, backup, and similar artifacts |
| `CFG-ERROR-001` | Verbose error-message disclosure |
| `CFG-CACHE-001` | Unsafe caching behavior |
| `CFG-DISCLOSURE-001` | Server or framework information disclosure |
| `CFG-COOKIE-001` | Insecure cookie attributes |
| `CFG-HTTP-001` | Dangerous HTTP methods or behavior |

Each rule carries a rule ID, prerequisites, detection logic, evidence requirements, severity, confidence, remediation guidance, and CWE/OWASP references where applicable. Findings are classified as observed evidence and are not presented as proof of exploitability.

## Scan lifecycle and task graph

A scan moves through the persisted lifecycle `QUEUED`, `COLLECTING`, `ANALYZING`, `SYNTHESIZING`, and `COMPLETED`, with explicit failure, pause, and cancellation states. The frontend streams or polls persisted progress and displays task-level status, elapsed time, estimated remaining time, expected completion, retry state, and terminal results.

The current task graph is:

```text
admission → collection →
  [technology, structure, api_intelligence, network_intelligence,
   http_agent, configuration, api_agent, security, content, recon]
  → performance → accessibility → diagnosis → synthesis
```

The Configuration Agent waits for both `collection` and `http_agent`. The API Agent waits for `collection`, `api_intelligence`, `http_agent`, and, when enabled, `recon`. Both agents consume persisted evidence and do not perform a separate unbounded request pass. The API Agent response includes the complete rule catalog, normalized inventory, schemas, indicators, matched findings, a ruleset version, and severity counts:

```text
GET /v1/scans/{scan_id}/configuration
GET /v1/scans/{scan_id}/api-agent
```

## What the platform observes

The platform is designed to report real observations from the supplied public target rather than fabricate demo values in live scans. Evidence includes response status and headers, redirect chains, cookies, cache directives, content types, compression, TLS metadata, CORS behavior, security policies, DNS and CT observations where permitted, page structure, browser telemetry, dependencies, discovered API routes, and normalized parameters.

A live scan can produce no findings when rule prerequisites are not met. That result means the configured evidence did not satisfy a detection rule; it is **not** a guarantee that the target is secure. Every report includes limitations and evidence provenance so users can distinguish observed, inferred, AI-interpreted, and unknown information.

## Scope and safety controls

Before collection begins, the API records the actor, target, authorization acknowledgement, allowed domains, allowed paths, excluded paths, assessment profile, robots setting, request limits, concurrency, rate limit, authentication type, and optional expiration. Authentication values are encrypted and only fingerprints are used in authorization records. Runtime credentials and API keys must remain outside Git.

Admission validates canonical URLs and applies hostname, DNS, IP, path, and redirect controls to prevent access to private or internal resources unless a deployment policy explicitly permits it. Active-safe discovery is restricted to scope-checked, bounded requests. The default posture is passive-only recon with robots respected.

## Honest coverage and limitations

This is a security assessment foundation, not an unrestricted penetration-testing tool. It currently provides high-confidence passive and active-safe observations, but it does not verify SQL injection, reflected or stored XSS, CSRF, authentication or authorization flaws, IDOR/BOLA, SSRF exploitation, command injection, file-upload vulnerabilities, deserialization, RCE, authenticated API behavior, session weaknesses, dependency CVEs, port and service exposure, subdomain takeover, or meaningful open-redirect exploitability. It also does not log into targets or submit target forms.

Those limitations are intentional. Any future active checks must preserve explicit consent, scope enforcement, rate limits, non-destructive behavior, audit logging, and evidence-based reporting.

## Architecture

| Layer | Current implementation |
|---|---|
| Frontend | Next.js 15, React 19, TypeScript, Tailwind CSS, standalone production output |
| Backend | FastAPI, Python 3.12 runtime, SQLAlchemy 2.0, Alembic, Structlog |
| Database | SQLite for the current manual runtime; PostgreSQL-compatible SQLAlchemy patterns are retained where supported |
| Browser worker | Playwright microservice with Chromium, isolated from the API process |
| Task execution | Inline synchronous queue mode for the current runtime; persisted task graph and retry states |
| Evidence model | Shared observations, normalized assets/endpoints/parameters, `HTTPObservation`, and `SecurityFinding` records |
| Optional AI | Citation-grounded synthesis may be enabled through deployment configuration; deterministic assessment and configuration rules do not require an LLM |

Extension 5 does not require a new Alembic migration because it stores API findings in the existing `SecurityFinding` table using `category="api"`; the existing `/api-endpoints` inventory endpoint remains backward-compatible. The active database remains at Alembic head `20260819_extension3`.

## Manual setup without Docker

Docker is not required for the supported local workflow. The commands below start the browser worker, backend, and frontend as separate processes.

### Prerequisites

Install Node.js 18 or newer, Python 3.11 or newer, npm, and a Chromium-compatible browser. On the current Linux runtime, Chromium is available at `/usr/bin/chromium`.

### Backend environment

Create and activate the backend virtual environment, then install dependencies:

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Set runtime configuration in the shell or a local untracked environment file. Do not copy real credentials into this README or commit them to Git:

```bash
export APP_ENV=PROD
export DATABASE_URL="sqlite:///web-autopsy-demo.db"
export QUEUE_MODE="inline"
export BROWSER_WORKER_URL="http://127.0.0.1:8001"
export ASSESSMENT_ENCRYPTION_KEY="<generate-a-fernet-key-for-this-deployment>"
# Optional AI configuration; keep the key outside Git and outside public logs.
# export LLM_API_KEY="<runtime-only-key>"
# export LLM_API_BASE="https://generativelanguage.googleapis.com/v1beta/openai/"
# export LLM_MODEL="gemini-2.5-flash"
```

Generate a Fernet key for a fresh deployment with a local, uncommitted command:

```bash
python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

### Start the browser worker

In one terminal:

```bash
cd browser_worker
BROWSER_EXECUTABLE_PATH="/usr/bin/chromium" \
  ../backend/venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8001
```

Verify the worker:

```bash
curl http://127.0.0.1:8001/health
```

### Apply migrations and start the backend

In a second terminal:

```bash
cd backend
source venv/bin/activate
export DATABASE_URL="sqlite:///web-autopsy-demo.db"
export QUEUE_MODE="inline"
export BROWSER_WORKER_URL="http://127.0.0.1:8001"
export ASSESSMENT_ENCRYPTION_KEY="<same-runtime-only-key-as-above>"
PYTHONPATH=. alembic upgrade head
PYTHONPATH=. python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Verify the API:

```bash
curl http://127.0.0.1:8000/health
```

The expected health response reports the API service, a connected database, and the current environment.

### Build and start the frontend

In a third terminal:

```bash
cd frontend
npm ci
npm run lint
npm run typecheck
npm run build
npm run start:3001
```

Open `http://localhost:3001`. The default frontend API base is same-origin `/api`, which allows the Next.js server to proxy API requests without exposing a browser-side `localhost:8000` dependency. Set `NEXT_PUBLIC_API_BASE_URL` only when the backend is intentionally hosted on another origin and the CORS policy is configured for it.

## Creating a bounded authorized scan

The scan endpoint requires `authorization_acknowledged: true`. A minimal safe request should provide the target, explicit domain scope, path scope, bounded limits, and an actor identifier:

```bash
curl -X POST http://127.0.0.1:8000/v1/scans \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -H 'X-Actor-ID: authorized-researcher' \
  -d '{
    "url": "https://www.python.org/",
    "authorization_acknowledged": true,
    "assessment_profile": "safe",
    "allowed_domains": ["python.org", "www.python.org"],
    "allowed_paths": ["/"],
    "excluded_paths": ["/downloads/"],
    "max_depth": 1,
    "max_pages": 5,
    "max_requests": 10,
    "max_concurrency": 1,
    "rate_limit_per_host_ms": 500,
    "robots_override": false,
    "recon_mode": "passive_only",
    "test_account_ref": "authorized-research-record"
  }'
```

Use the returned scan ID to inspect progress and reports:

```bash
SCAN_ID="<returned-scan-id>"
curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}/progress"
curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}/http-observations"
curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}/configuration"
curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}/diagnosis"
```

The frontend report exposes Configuration, Security, HTTP Agent, Recon Agent, API Intelligence, performance, accessibility, content, evidence, diagnosis, and synthesis sections when the corresponding data is available.

## Testing and release verification

Run the complete local validation sequence from the repository root:

```bash
backend/venv/bin/python -m compileall -q backend/app
PYTHONPATH=backend backend/venv/bin/python -m pytest backend/tests -q
(cd frontend && npm run lint && npm run typecheck && npm run build)
(cd backend && DATABASE_URL=sqlite:///web-autopsy-demo.db PYTHONPATH=. ../backend/venv/bin/alembic current)
```

The Extension 4 release was validated with **83 backend tests passing**, and Extension 5 raised the full backend regression total to **87 tests passing**. The combined release passed Python compilation, frontend linting, TypeScript checking, production build, and Alembic validation at `20260819_extension3 (head)`. A fresh bounded Python.org scan completed with `requests_used: 7`, `state: COMPLETED`, `status: completed`, and `api_agent: SUCCEEDED`; its API Agent report contained 10 rules, zero findings, and an empty route inventory because no API-like route or schema was captured.

The Extension 4 live verification details are recorded in [`docs/extension4-live-verification.md`](docs/extension4-live-verification.md). The Extension 5 live verification details are recorded in [`docs/extension5-live-verification.md`](docs/extension5-live-verification.md). The API Agent design and rule catalog are documented in [`docs/extension5-api-agent-integration-design.md`](docs/extension5-api-agent-integration-design.md), and the Configuration Agent design is documented in [`docs/configuration-agent-integration-design.md`](docs/configuration-agent-integration-design.md).

## Repository documentation

| Document | Purpose |
|---|---|
| [`LOCAL_VERIFICATION.md`](LOCAL_VERIFICATION.md) | Local verification notes and runtime checks |
| [`docs/configuration-agent-integration-design.md`](docs/configuration-agent-integration-design.md) | Configuration Agent integration design and rule metadata |
| [`docs/extension4-live-verification.md`](docs/extension4-live-verification.md) | Real-target live verification record |
| [`PHASE11_IMPLEMENTATION.md`](PHASE11_IMPLEMENTATION.md) | Historical implementation notes for the existing platform |
| [`PHASE12_IMPLEMENTATION.md`](PHASE12_IMPLEMENTATION.md) | Historical implementation notes for the existing platform |
| [`PHASE13_IMPLEMENTATION.md`](PHASE13_IMPLEMENTATION.md) | Historical implementation notes for the existing platform |

## Contributing

Contributions should preserve the platform’s authorization, scope, SSRF, rate-limit, audit, evidence, and non-destructive guarantees. New security rules should be independently testable, low-false-positive, explicit about prerequisites and limitations, and backed by persisted evidence. Changes that introduce credentials, destructive actions, unbounded network behavior, or unreviewed exploit automation should not be merged.

```bash
git checkout -b feature/your-change
# make and test the change
git add .
git commit -m "feat: describe the change"
git push origin feature/your-change
```

## References

[1]: https://fastapi.tiangolo.com/ "FastAPI documentation"
[2]: https://nextjs.org/docs "Next.js documentation"
[3]: https://playwright.dev/python/ "Playwright Python documentation"
[4]: https://docs.sqlalchemy.org/ "SQLAlchemy documentation"
[5]: https://alembic.sqlalchemy.org/ "Alembic documentation"
[6]: https://owasp.org/www-project-top-ten/ "OWASP Top 10"
