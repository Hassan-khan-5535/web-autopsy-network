# Web Autopsy Network

**Web Autopsy Network** is an evidence-backed web intelligence and continuous security-assessment platform for **authorized** targets. It combines bounded collection, deterministic analysis, provenance-aware correlation, transparent risk prioritization, and safe reporting into a persisted investigation workflow.

The platform distinguishes **observed evidence**, **inference**, **AI interpretation**, and **unknowns**. It is designed to help authorized teams understand an application’s security posture without turning the scanner into an exploitation framework.

> **Safety contract:** Web Autopsy Network is detection- and reporting-oriented. Every scan requires recorded authorization acknowledgement, explicit scope, bounded request controls, audit events, and SSRF-resistant admission. The platform does not perform destructive exploitation, credential theft, evasion, persistence, denial of service, target-data modification, or autonomous exploit execution.

| Resource | Description |
|---|---|
| Repository | [atifkhani397/web-autopsy-network](https://github.com/atifkhani397/web-autopsy-network) |
| API reference | [`docs/API.md`](docs/API.md) |
| System architecture | [`docs/SYSTEM_ARCHITECTURE.md`](docs/SYSTEM_ARCHITECTURE.md) |
| Production review | [`docs/extension19-production-review.md`](docs/extension19-production-review.md) |
| Controlled benchmark protocol and results | [`docs/extension18-benchmark-production-validation.md`](docs/extension18-benchmark-production-validation.md) and [`docs/BENCHMARK_RESULTS.md`](docs/BENCHMARK_RESULTS.md) |

## Platform capabilities

The repository contains the completed foundation and the agent layer through **Extension 19**. Each component is designed to operate within stored authorization and current scope, and to preserve evidence provenance rather than make unsupported claims.

| Capability area | Included functionality |
|---|---|
| Admission, consent, and audit | Canonical URL validation, authorization acknowledgement, allowed domains/paths, excluded paths, assessment profiles, robots policy, request budgets, encrypted authentication material, audit records, pause/resume/cancel, and authorization-expiry safeguards. |
| Evidence collection | Bounded crawling, normalized HTTP observations, redirect/header/cookie/TLS/CORS evidence, browser rendering, recon assets, endpoints, parameters, technology indicators, public DNS/CT observations, and redaction-aware storage. |
| Security analysis | Deterministic configuration, API, vulnerability-indicator, secrets/sensitive-data, CVE intelligence, and independent evidence-validation agents with explicit prerequisites, confidence, remediation, and limitation metadata. |
| Correlation and risk | Incremental attack-surface graph, asset associations, safe prioritization paths, duplicate-finding relationships, transparent score components, posture/risk trends, and same-target comparisons. |
| Continuous posture | Scan-to-scan differential analysis, historical posture timeline, safe-profile recurring schedules, scope/authorization revalidation, and regression visibility. |
| Orchestration | Event-driven, dependency-aware multi-agent execution with task events, idempotency, retries, deadlines, cancellation, resource budgets, and isolated scan state. |
| Reporting and exports | Executive/technical reports, evidence, remediation, safe high-level breakpoint context, attack-surface summaries, posture trends, and PDF, JSON, and SARIF export formats. |
| Platform interfaces | REST API capability catalog, CLI workflows, scan setup/consent flow, live task activity, graph and evidence views, severity/confidence filters, trends, regressions, and export controls. |
| Update lifecycle | Versioned technology signatures, configuration rules, vulnerability checks, secret patterns, CVE intelligence, and remediation metadata with signature verification, schema/compatibility checks, staged activation, rollback, provenance, and offline fallback. |
| Scanner hardening | Scope-aware transport controls, DNS/redirect revalidation, response/output bounds, browser-worker contracts, redaction, rootless containers, and security regression tests. |
| Benchmarking and production review | Controlled ground-truth measurements, reproducible baseline artifacts, full regression/build validation, and a documented targeted production review. |

## Extensions 10–19 at a glance

| Extension | Delivered capability | Primary reference |
|---|---|---|
| 10 | Correlation Agent and incremental attack-surface graph | [`extension10-correlation-graph-design.md`](docs/extension10-correlation-graph-design.md) |
| 11 | Transparent deterministic risk and heuristic prioritization | [`extension11-risk-prioritization-design.md`](docs/extension11-risk-prioritization-design.md) |
| 12 | Differential analysis, posture timeline, and authorization-gated recurring scans | [`extension12-differential-continuous-assessment-design.md`](docs/extension12-differential-continuous-assessment-design.md) |
| 13 | Event-driven multi-agent investigation orchestration | [`extension13-multi-agent-orchestrator-design.md`](docs/extension13-multi-agent-orchestrator-design.md) |
| 14 | Security posture reports and safe PDF/JSON/SARIF exports | [`extension14-reporting-security-posture-design.md`](docs/extension14-reporting-security-posture-design.md) |
| 15 | Discoverable API, CLI, and professional dashboard workbench | [`extension15-api-cli-dashboard-design.md`](docs/extension15-api-cli-dashboard-design.md) |
| 16 | Verified template/signature update packages with rollback and offline fallback | [`extension16-template-signature-updates-design.md`](docs/extension16-template-signature-updates-design.md) |
| 17 | Scanner SSRF, redirect, browser, resource, and isolation hardening | [`extension17-scanner-security-isolation-design.md`](docs/extension17-scanner-security-isolation-design.md) |
| 18 | Controlled benchmarks, reproducible measurements, and production validation | [`extension18-benchmark-production-validation.md`](docs/extension18-benchmark-production-validation.md) |
| 19 | Targeted production review, graph race recovery, configuration/CORS protection, rootless runtime, and deployment limitations | [`extension19-production-review.md`](docs/extension19-production-review.md) |

## Architecture

The application uses a Next.js frontend, a FastAPI backend, a relational persistence layer, a queue/worker topology, and a separate Playwright browser worker. The orchestration layer schedules eligible agents from persisted events rather than forcing a single rigid scan pipeline.

```text
Authorized user / API client
          │
          ▼
  Admission, authorization, scope, and audit controls
          │
          ▼
FastAPI API ──► persisted scan, evidence, task, graph, risk, and report records
          │                               │
          │                               ▼
          │                    dependency-aware task orchestration
          │                               │
          ├───────────► crawl / HTTP / recon worker pools
          ├───────────► isolated browser worker
          └───────────► analysis, correlation, risk, report, and export services
                                          │
                                          ▼
                              Next.js dashboard, API, CLI, exports
```

| Layer | Implementation |
|---|---|
| Frontend | Next.js 15, React 19, TypeScript, Tailwind CSS, standalone production output. |
| API and services | FastAPI, SQLAlchemy, Alembic, structured application logging, typed request models. |
| Persistence | SQLite is supported for local development; PostgreSQL is the intended production database. |
| Work distribution | Inline dispatcher for local development; Redis/Celery worker topology for production-oriented execution. |
| Browser isolation | Separate Playwright/Chromium service with strict request models, domain/path policy, network interception, final-URL validation, bounded artifacts, and redacted errors. |
| Trust model | Persisted authorization and scope, deterministic rule outputs, evidence provenance, confidence/evidence-quality states, and explicit safety contracts. |

## Safety, evidence, and scope model

A scan is not a blanket permission to probe a target. The request must record authorization acknowledgement and the precise target boundary. The backend normalizes the URL, checks the hostname against the stored allowed-domain list, applies path allowlists/exclusions, enforces profile ceilings, and records relevant audit events. Stored authentication values are encrypted; only safe metadata and fingerprints are used in audit/report flows.

The default `safe` profile is intentionally conservative. Recurring scans are limited to the safe profile and must revalidate stored authorization and current scope before dispatch. The graph’s escalation relationships are **prioritization-only** and never constitute exploit paths or proof of exploitability. Similarly, a rule match or scanner signature is an evidence-backed indicator, not a claim that the target is compromised.

| Explicitly supported | Explicitly out of scope |
|---|---|
| Scoped, rate-limited collection and persisted-evidence analysis | Payload delivery, active exploitation, credential validation, login automation, form submission, or object-ID substitution |
| Deterministic configuration/API/vulnerability-indicator/secrets/CVE checks | Destructive testing, denial-of-service, evasion, persistence, or target modification |
| Evidence quality, provenance, confidence, trends, graph/risk prioritization, reports, and exports | Treating inferred graph links, a technology family match, or a secret signature as proof of impact |
| Strict browser-worker egress checks, bounded output, and redacted diagnostics | Public exposure of the browser worker or reliance on app-level checks as the only network control |

## Quick start for local development

### Prerequisites

Use **Python 3.11+**, **Node.js 20+** (Node.js 18+ may work where supported by Next.js), npm, and a Chromium-compatible browser for the browser worker. PostgreSQL and Redis are recommended when validating production-oriented queue behavior; SQLite and inline execution are useful for local development and tests.

### 1. Prepare the backend

```bash
git clone https://github.com/atifkhani397/web-autopsy-network.git
cd web-autopsy-network

python3 -m venv backend/venv
backend/venv/bin/pip install -r backend/requirements.txt -r backend/requirements-dev.txt
```

Copy or adapt [`backend/config.env.example`](backend/config.env.example) into a local, untracked environment file. The following local values show the minimum shape; replace them with deployment-specific values and never commit secrets.

```bash
export APP_ENV=development
export DATABASE_URL="sqlite:///$(pwd)/web-autopsy-local.db"
export QUEUE_MODE=inline
export BROWSER_WORKER_URL="http://127.0.0.1:8001"
export CORS_ORIGINS="http://localhost:3000,http://localhost:3001"
export ASSESSMENT_ENCRYPTION_KEY="<local Fernet key>"
```

Generate a local Fernet key, if needed:

```bash
backend/venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

### 2. Start the browser worker

In a separate terminal, point the worker to the local Chromium binary where necessary:

```bash
cd browser_worker
BROWSER_EXECUTABLE_PATH="/usr/bin/chromium" \
  ../backend/venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8001
```

Verify the worker locally:

```bash
curl http://127.0.0.1:8001/health
```

### 3. Apply migrations and start the API

```bash
cd backend
PYTHONPATH=. ../backend/venv/bin/alembic upgrade head
PYTHONPATH=. ../backend/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Verify the backend:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/v1/capabilities
```

### 4. Build or run the frontend

In a third terminal:

```bash
cd frontend
npm ci
npm run dev:3001
```

For a production build check:

```bash
cd frontend
NODE_ENV=production npm run build
npm run start:3001
```

Open `http://localhost:3001`. The dashboard only uses persisted scan UUIDs; there are no demo scan routes or fabricated report payloads.

## Creating an authorized bounded scan

Only scan systems you are authorized to assess. The following example uses the repository’s designated authorized verification target and deliberately conservative limits. Review and adapt the scope to your authorization before sending any request.

```bash
curl -X POST http://127.0.0.1:8000/v1/scans \
  -H 'Content-Type: application/json' \
  -H 'X-Actor-ID: authorized-researcher' \
  -d '{
    "url": "https://www.w3schools.com/",
    "authorization_acknowledged": true,
    "assessment_profile": "safe",
    "allowed_domains": ["w3schools.com", "www.w3schools.com"],
    "allowed_paths": ["/"],
    "excluded_paths": [],
    "max_depth": 1,
    "max_pages": 5,
    "max_requests": 10,
    "max_concurrency": 1,
    "rate_limit_per_host_ms": 1000,
    "robots_override": false,
    "recon_mode": "passive_only",
    "test_account_ref": "authorized-research-record"
  }'
```

Use the returned `id` in subsequent report requests:

```bash
SCAN_ID="<persisted-scan-uuid>"
curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}/progress"
curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}/attack-surface-graph"
curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}/risk"
curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}/posture-timeline"
curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}/report"
```

The complete endpoint catalog, including findings filtering, scan comparison, recurring schedules, agent activity, reports, and exports, is documented in [`docs/API.md`](docs/API.md) and exposed through `GET /v1/capabilities`.

## Verification

Run validation from the repository root. The explicit `APP_ENV=test` prevents production-only secret/CORS guards from blocking test discovery; the guard itself is covered by Extension 19 regression tests.

```bash
# Python syntax and import compilation
backend/venv/bin/python -m compileall -q backend/app

# Full backend regression suite
APP_ENV=test PYTHONPATH=backend backend/venv/bin/python -m pytest backend/tests -q

# Frontend quality and production build
(cd frontend && npm run lint && npm run typecheck && NODE_ENV=production npm run build)

# Controlled local benchmark; no external target is contacted
PYTHONPATH=backend backend/venv/bin/python backend/scripts/run_benchmark.py --exercise-local-target
```

The Extension 19 review recorded **143 passing backend tests**, focused browser-worker and graph-race regressions, and a successful Next.js production build. Benchmark results are controlled measurements, not claims of universal or state-of-the-art detection performance. [1] [2]

## Docker and production deployment

`docker-compose.yml` is a **development-only** composition. It intentionally uses source mounts, hot reload, and frontend development commands. Do not deploy it unchanged to production. [1]

For production, build immutable images from a reviewed commit and provide a separate production manifest. Before serving traffic, apply Alembic migrations; use PostgreSQL and Redis on private networks; inject secrets with a secret manager; keep the browser worker private; set concrete CORS origins; configure egress filtering, resource/PID/timeouts, log forwarding, monitoring, backups, and health checks.

Production startup fails closed when `APP_ENV=production` or `prod` is used with the default/short `JWT_SECRET`, the default/short `UPDATE_PACKAGE_HMAC_KEY`, or a wildcard `CORS_ORIGINS` value. The backend and browser-worker images run as unprivileged users, but the deployment platform should additionally enforce container resource limits, dropped capabilities, `no-new-privileges`, seccomp, writable temporary storage for the browser, and restrictive service-network policies. [1]

| Production setting | Requirement |
|---|---|
| `APP_ENV` | Set to `production` only with complete production configuration. |
| `JWT_SECRET` | Unique secret of at least 32 characters, supplied outside source control. |
| `UPDATE_PACKAGE_HMAC_KEY` | Unique secret of at least 32 characters for update-package verification, supplied outside source control. |
| `CORS_ORIGINS` | Concrete trusted origins, supplied as a comma-separated list; no wildcard. |
| `DATABASE_URL` / `QUEUE_BACKEND_URL` | Private PostgreSQL/Redis endpoints and deployment-managed credentials. |
| `BROWSER_WORKER_URL` | Internal service address only; do not publish `/render` to the public Internet. |
| Scanner and browser limits | Preserve request, redirect, response, artifact, timeout, CPU, and memory caps; enforce CPU/memory/PID limits at the orchestrator layer. |

## Documentation map

| Document | Purpose |
|---|---|
| [`docs/API.md`](docs/API.md) | REST endpoint and request/response reference. |
| [`docs/SYSTEM_ARCHITECTURE.md`](docs/SYSTEM_ARCHITECTURE.md) | System topology, evidence taxonomy, worker model, and trust boundaries. |
| [`docs/security-assessment-integration-audit.md`](docs/security-assessment-integration-audit.md) | Security assessment integration and compatibility context. |
| [`docs/extension10-correlation-graph-design.md`](docs/extension10-correlation-graph-design.md) through [`docs/extension19-production-review.md`](docs/extension19-production-review.md) | The design, validation, hardening, benchmark, and production-review record for the advanced agent layer. |
| [`docs/BENCHMARK_RESULTS.md`](docs/BENCHMARK_RESULTS.md) | Controlled benchmark results and methodology links. |
| [`docs/real-authorized-url-testing.md`](docs/real-authorized-url-testing.md) | Authorized real-target testing standard. |
| [`LOCAL_VERIFICATION.md`](LOCAL_VERIFICATION.md) | Local runtime and manual verification notes. |

## Contributing

Contributions must preserve the platform’s authorization, scope, evidence, non-destructive, and false-positive safeguards. New rules should be deterministic where possible, independently testable, bounded by explicit prerequisites, tied to persisted evidence, transparent about confidence and limitations, and covered by regression tests. Do not add secrets to source control, public browser-worker exposure, unbounded network behavior, destructive actions, exploit automation, fabricated reviews, or static demo scan data.

```bash
git checkout -b feature/your-change
# make a targeted change and run the relevant checks
git add <files>
git commit -m "feat: describe the change"
git push origin feature/your-change
```

## References

[1]: docs/extension19-production-review.md "Extension 19 targeted production review"
[2]: docs/extension18-benchmark-production-validation.md "Extension 18 benchmark and production validation"
