# Web Autopsy Network

> **Evidence-backed web intelligence and authorized security assessment — designed for bounded observation, not exploitation.**

Web Autopsy Network is a full-stack platform for helping website owners and authorized security teams understand the externally observable posture of a web application. It combines consent and scope controls, bounded collection, deterministic analysis agents, provenance-aware evidence review, attack-surface correlation, transparent prioritization, continuous posture tracking, and safe report exports in one persisted workflow.

The project is intentionally **detection- and reporting-oriented**. It does not attempt to become an exploitation framework, credential-testing system, persistence tool, or autonomous offensive agent.

> **Core safety contract:** every assessment records authorization, target scope, profile limits, and audit events; every agent operates within those persisted boundaries; every report distinguishes observation from inference and interpretation; and no scanner signature alone is treated as proof of a vulnerability.

**Navigate:** [Capabilities](#capability-map) · [Safety boundaries](#safety-boundaries) · [Architecture](#architecture) · [Quick start](#quick-start--manual-no-docker-required) · [API](#api-surface-at-a-glance) · [Verification](#verification-and-benchmarks) · [Contributing](#contributing-safely)

## Contents

- [Project status](#project-status)
- [What the platform does](#what-the-platform-does)
- [Capability map](#capability-map)
- [Extension map](#extension-map)
- [Evidence model](#evidence-model)
- [Safety boundaries](#safety-boundaries)
- [Architecture](#architecture)
- [Quick start](#quick-start--manual-no-docker-required)
- [Create an authorized bounded scan](#create-an-authorized-bounded-scan)
- [CLI](#cli)
- [API surface](#api-surface-at-a-glance)
- [Verification and benchmarks](#verification-and-benchmarks)
- [Production deployment guidance](#production-deployment-guidance)
- [Repository layout](#repository-layout)
- [Documentation map](#documentation-map)
- [Contributing safely](#contributing-safely)
- [Project governance and license](#project-governance-and-license)

## Project status

| Area | Current state |
|---|---|
| Product scope | Foundation plus Extensions 1–19 implemented in the repository |
| Primary interface | Next.js dashboard, versioned FastAPI API, and scope-safe CLI |
| Local runtime | Manual startup supported with SQLite, inline task execution, and a private Playwright worker |
| Production posture | Targeted production review completed; production deployment still requires infrastructure-level egress, resource, secrets, monitoring, and migration controls |
| Latest recorded validation | 143 backend tests passing, focused security/reliability regressions passing, frontend production build passing, and controlled benchmark artifacts published [1] [2] |
| Security posture | Authorized, non-destructive, bounded assessment only |

This status describes the current engineering boundary; it is **not** a claim of universal detection coverage, absence of defects, or independent production readiness.

## What the platform does

Web Autopsy Network turns a permitted target into a persisted investigation record. A scan is admitted only after URL normalization, scope checks, authorization acknowledgement, profile validation, and SSRF-resistant target validation. Collection then produces reusable observations and normalized assets. Independent agents consume those observations, emit findings with prerequisites and evidence requirements, and publish task events. Correlation, risk, diagnosis, synthesis, and reporting consume the resulting records without bypassing the evidence model.

The platform supports real target responses and persisted UUID-based scans. It does not rely on fabricated report payloads or a static demo scan shortcut in the production report flow.

## Capability map

| Capability | Included behavior | Primary output |
|---|---|---|
| **Admission and consent** | Canonical URL validation, authorization acknowledgement, allowed domains and paths, exclusions, profiles, robots policy, request budgets, encrypted authentication material, expiry checks, and immutable audit events | Scope and consent record |
| **Bounded collection** | Same-domain crawling, HTTP observations, redirects, headers, cookies, TLS, CORS, compression, content type, browser rendering, and response-size limits | Persisted observations and pages |
| **Reconnaissance** | Assets, endpoints, parameters, technology indicators, public DNS/CT observations, sitemaps, JavaScript route clues, and sensitive-path classification | Normalized asset, endpoint, and parameter inventory |
| **Security analysis** | Configuration, API, vulnerability-indicator, secrets, sensitive-data, CVE/technology, and evidence-quality agents | Evidence-backed findings with confidence and limitations |
| **Correlation and risk** | Incremental attack-surface graph, asset associations, deterministic score components, prioritization paths, posture snapshots, and same-target comparison | Graph, risk assessments, trends, and diffs |
| **Continuous assessment** | Safe-profile recurring schedules, authorization revalidation, scope revalidation, update records, and regression visibility | Historical posture and schedule state |
| **Orchestration** | Dependency-aware task graph, persisted events, task budgets, idempotency, retry/backoff, deadlines, pause/resume/cancel, and terminal-state handling | Observable scan lifecycle |
| **Reporting** | Executive and technical reports, Cause of Death diagnosis, AI Doctor citation-grounded answers, evidence views, graph views, remediation, and safe high-level breakpoints | Dashboard, JSON, PDF, and SARIF outputs |
| **Platform lifecycle** | Discoverable capability catalog, CLI, verified signature/update packages, rollback, offline fallback, benchmarks, and focused production review artifacts | Maintainable and auditable operations |

## Extension map

The system is built as a cumulative extension layer over the original Web Autopsy Network foundation. Each extension preserves the scan-centered persistence model and existing API behavior unless a versioned capability is explicitly added.

| Extension | Capability | Reference |
|---:|---|---|
| 1 | Scope, consent, authorization, scan controls, and SSRF-resistant admission | [`docs/extension1-live-verification.md`](docs/extension1-live-verification.md) |
| 2 | Recon Agent and normalized discovery inventory | [`docs/extension2-live-verification.md`](docs/extension2-live-verification.md) |
| 3 | Central HTTP Agent and reusable response observations | [`docs/http-agent-integration-design.md`](docs/http-agent-integration-design.md) |
| 4 | High-confidence Configuration Agent | [`docs/configuration-agent-integration-design.md`](docs/configuration-agent-integration-design.md) |
| 5 | API inventory and API Agent | [`docs/extension5-api-agent-integration-design.md`](docs/extension5-api-agent-integration-design.md) |
| 6 | Detection-only Vulnerability Agent | [`docs/extension6-vulnerability-agent-integration-design.md`](docs/extension6-vulnerability-agent-integration-design.md) |
| 7 | Secrets and Sensitive Data Agent with redaction | [`docs/extension7-secrets-agent-integration-design.md`](docs/extension7-secrets-agent-integration-design.md) |
| 8 | CVE and Technology Intelligence Agent | [`docs/extension8-cve-intelligence-design.md`](docs/extension8-cve-intelligence-design.md) |
| 9 | Independent Evidence Agent and false-positive reduction | [`docs/extension9-evidence-agent-design.md`](docs/extension9-evidence-agent-design.md) |
| 10 | Correlation Agent and incremental attack-surface graph | [`docs/extension10-correlation-graph-design.md`](docs/extension10-correlation-graph-design.md) |
| 11 | Transparent risk and heuristic prioritization | [`docs/extension11-risk-prioritization-design.md`](docs/extension11-risk-prioritization-design.md) |
| 12 | Differential analysis, posture timeline, and recurring assessment | [`docs/extension12-differential-continuous-assessment-design.md`](docs/extension12-differential-continuous-assessment-design.md) |
| 13 | Event-driven multi-agent orchestration | [`docs/extension13-multi-agent-orchestrator-design.md`](docs/extension13-multi-agent-orchestrator-design.md) |
| 14 | Security posture reports and PDF/JSON/SARIF exports | [`docs/extension14-reporting-security-posture-design.md`](docs/extension14-reporting-security-posture-design.md) |
| 15 | Discoverable API, CLI, and dashboard workbench | [`docs/extension15-api-cli-dashboard-design.md`](docs/extension15-api-cli-dashboard-design.md) |
| 16 | Verified template/signature update packages | [`docs/extension16-template-signature-updates-design.md`](docs/extension16-template-signature-updates-design.md) |
| 17 | Scanner security and browser/network isolation | [`docs/extension17-scanner-security-isolation-design.md`](docs/extension17-scanner-security-isolation-design.md) |
| 18 | Controlled benchmarks and reproducible validation | [`docs/extension18-benchmark-production-validation.md`](docs/extension18-benchmark-production-validation.md) |
| 19 | Targeted production review and hardening follow-up | [`docs/extension19-production-review.md`](docs/extension19-production-review.md) |

## Evidence model

The central design decision is to make uncertainty visible instead of hiding it behind a single severity number.

| Classification | Meaning |
|---|---|
| **Observed** | Directly measured telemetry such as status codes, headers, cookies, timings, DOM data, or persisted response content |
| **Inferred** | A deterministic conclusion derived from multiple observations and an explicit rule or scoring function |
| **AI interpretation** | A narrative or answer constrained to cited, persisted evidence; unsupported claims are rejected or marked unavailable |
| **Unknown** | A property that cannot be established externally without invasive, authenticated, destructive, or otherwise unauthorized action |

The Evidence Agent adds a second layer of discipline to candidate findings. It validates prerequisites, compares observations, checks reproducibility from persisted responses without issuing new network requests, redacts secret values, records provenance, and assigns a state such as `candidate`, `validated`, `rejected`, or `inconclusive`. A signature, technology-family match, graph edge, or inferred relationship is never sufficient by itself to establish exploitability.

## Safety boundaries

A scan is not blanket permission to probe a target. The request must identify the authorized target and persist the precise boundary that every downstream task receives.

| Supported within authorization | Explicitly not performed |
|---|---|
| Scoped, rate-limited, non-destructive collection | Exploit payload delivery or exploit-chain automation |
| Passive and active-safe discovery modes | Credential guessing, credential validation, or credential theft |
| Safe configuration, API, vulnerability-indicator, secrets, CVE, and evidence checks | Login automation, authenticated form submission, or session manipulation |
| Evidence provenance, confidence, redaction, graphing, prioritization, and reporting | SQL injection exploitation, XSS exploitation, RCE, command injection, or destructive testing |
| Browser rendering through a private, scope-aware worker | Denial of service, persistence, evasion, target-data modification, or public worker access |

Application-level protections are necessary but not sufficient. A production deployment must also keep the browser worker private, enforce egress policy outside the application, use resource quotas, manage secrets externally, and operate a production database and queue on private networks.

## Architecture

```text
                         Authorized user or API client
                                      │
                                      ▼
                  Admission · consent · scope · audit · SSRF gates
                                      │
                                      ▼
                         FastAPI API and capability catalog
                                      │
                ┌─────────────────────┼─────────────────────┐
                ▼                     ▼                     ▼
        Persisted scan state   Task/event graph       CLI/dashboard
        pages · observations   dependencies · retries  reports · exports
        findings · evidence    budgets · deadlines
                │                     │
                └──────────────┬──────┴──────────────┐
                               ▼                     ▼
                   Crawl / HTTP / analysis     Private Playwright worker
                   agents and services         bounded browser rendering
                               │                     │
                               └──────────────┬──────┘
                                              ▼
                             Correlation · risk · diagnosis
                               synthesis · report services
                                              │
                                              ▼
                          Next.js dashboard · API · CLI · exports
```

| Layer | Current implementation |
|---|---|
| Frontend | Next.js 15, React 19, TypeScript, Tailwind CSS, standalone production output |
| API and services | FastAPI, SQLAlchemy, Alembic, typed request models, structured logging |
| Persistence | SQLite for local development and tests; PostgreSQL intended for production |
| Work distribution | Inline dispatcher for local execution; Redis/Celery topology for production-oriented execution |
| Browser isolation | Separate Playwright/Chromium service with strict request models, scope checks, redirect/final-URL validation, bounded artifacts, and redacted errors |
| Trust model | Persisted authorization, deterministic rules, provenance, evidence-quality states, confidence, uncertainty, and explicit safety contracts |

## Quick start — manual, no Docker required

The following workflow is designed for a clean local checkout. Docker is not required for development or verification. The tracked Compose file is intentionally development-only and should not be treated as a production manifest.

### Prerequisites

Use **Python 3.11+**, **Node.js 20+**, npm, and a Chromium-compatible browser. SQLite and inline task execution are sufficient for local development. PostgreSQL, Redis, private service networking, and infrastructure resource controls are required for a serious production deployment.

### 1. Clone and install backend dependencies

```bash
git clone https://github.com/atifkhani397/web-autopsy-network.git
cd web-autopsy-network

python3 -m venv backend/venv
backend/venv/bin/pip install -r backend/requirements.txt -r backend/requirements-dev.txt
```

Create an untracked local environment file from [`backend/config.env.example`](backend/config.env.example) or export the minimum local settings:

```bash
export APP_ENV=development
export DATABASE_URL="sqlite:///$(pwd)/backend/web-autopsy-local.db"
export QUEUE_MODE=inline
export BROWSER_WORKER_URL="http://127.0.0.1:8001"
export CORS_ORIGINS="http://localhost:3000,http://localhost:3001"
export ASSESSMENT_ENCRYPTION_KEY="$(backend/venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
```

Never commit `.env` files, API keys, encryption keys, signing keys, cookies, authorization headers, or runtime logs containing sensitive values.

### 2. Start the private browser worker

In a separate terminal:

```bash
cd browser_worker
BROWSER_EXECUTABLE_PATH="/usr/bin/chromium" \
  ../backend/venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8001
```

Verify the worker:

```bash
curl http://127.0.0.1:8001/health
```

The browser worker is an internal service. Do not publish its `/render` endpoint to the Internet.

### 3. Apply migrations and start the API

In another terminal:

```bash
cd backend
PYTHONPATH=. ../backend/venv/bin/alembic upgrade head
PYTHONPATH=. ../backend/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Verify the API and capability catalog:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/v1/capabilities
```

### 4. Install and start the dashboard

In a third terminal:

```bash
cd frontend
npm ci
npm run dev:3001
```

Open <http://localhost:3001>. For a production build check:

```bash
npm run lint
npm run typecheck
NODE_ENV=production npm run build
npm run start:3001
```

The report dashboard expects persisted scan UUIDs and reads report data from the API. It does not synthesize static scan results for the real report path.

## Create an authorized bounded scan

Only assess systems for which you have explicit permission. Replace the example target, scope, and authorization reference with values from your own authorization record before sending a request.

```bash
curl -X POST http://127.0.0.1:8000/v1/scans \
  -H 'Content-Type: application/json' \
  -H 'X-Actor-ID: authorized-researcher' \
  -d '{
    "url": "https://target.example/",
    "authorization_acknowledged": true,
    "assessment_profile": "safe",
    "allowed_domains": ["target.example"],
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

The API returns a persisted scan UUID. Use that UUID for all follow-up requests:

```bash
export SCAN_ID="<persisted-scan-uuid>"

curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}"
curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}/progress"
curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}/evidence-agent"
curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}/attack-surface-graph"
curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}/risk-prioritization"
curl "http://127.0.0.1:8000/v1/scans/${SCAN_ID}/report"
```

The complete versioned endpoint catalog is maintained in [`docs/API.md`](docs/API.md) and exposed at `GET /v1/capabilities` [3]. The existing raw observation route `/evidence` and the independent review route `/evidence-agent` are deliberately different endpoints.

## CLI

The CLI calls the platform API; it never contacts assessment targets directly. It requires the same authorization and scope controls as the API.

```bash
# Show the discoverable API capability catalog
PYTHONPATH=backend backend/venv/bin/python backend/scripts/web_autopsy_cli.py capabilities

# Create a conservative, authorized scan
PYTHONPATH=backend backend/venv/bin/python backend/scripts/web_autopsy_cli.py create \
  --url https://target.example/ \
  --authorized \
  --profile safe \
  --recon-mode passive_only \
  --allowed-domain target.example \
  --allowed-path / \
  --max-depth 1 \
  --max-pages 5 \
  --max-requests 10 \
  --max-concurrency 1 \
  --rate-limit-ms 1000

# Read persisted results
PYTHONPATH=backend backend/venv/bin/python backend/scripts/web_autopsy_cli.py progress "$SCAN_ID"
PYTHONPATH=backend backend/venv/bin/python backend/scripts/web_autopsy_cli.py graph "$SCAN_ID"
PYTHONPATH=backend backend/venv/bin/python backend/scripts/web_autopsy_cli.py report "$SCAN_ID"
```

Authentication configuration, when explicitly authorized and required by the target, must be supplied through an owner-readable JSON file. The CLI rejects group- or world-readable authentication files and never prints their contents.

## API surface at a glance

| Route family | Purpose |
|---|---|
| `/health`, `/v1/workers/health` | API, database, and worker health |
| `/v1/capabilities` | Discoverable capability and endpoint catalog |
| `/v1/scans` | Authorization-gated scan creation and lifecycle |
| `/v1/scans/{id}/progress`, `/progress/stream` | Persisted progress and live SSE updates |
| `/assessment/authorization`, `/assessment/audit` | Consent record and audit trail |
| `/recon`, `/technologies`, `/architecture`, `/dependencies`, `/pages` | Discovery and normalized site inventory |
| `/http-observations`, `/evidence`, `/evidence-agent` | Raw observations and independent evidence reviews |
| `/configuration`, `/api-agent`, `/vulnerability-agent`, `/secrets`, `/cve-intelligence` | Specialized security-analysis outputs |
| `/performance`, `/accessibility`, `/content`, `/security` | Quality, performance, accessibility, and passive security outputs |
| `/attack-surface-graph`, `/risk-prioritization`, `/risk` | Correlation and deterministic prioritization |
| `/diagnosis`, `/report`, `/report/export/{pdf,json,sarif}` | Cause of Death, report generation, and exports |
| `/posture-timeline`, `/recurring-schedule`, `/compare` | Continuous posture and persisted same-target comparison |
| `/ask` | Citation-grounded AI Doctor interaction |

For request and response details, use [`docs/API.md`](docs/API.md) and the live capability catalog instead of inferring contracts from frontend calls.

## Verification and benchmarks

Run the full local validation loop from the repository root:

```bash
# Python compilation
backend/venv/bin/python -m compileall -q backend/app

# Backend regression suite
APP_ENV=test PYTHONPATH=backend backend/venv/bin/python -m pytest backend/tests -q

# Frontend quality and production build
(cd frontend && npm run lint && npm run typecheck && NODE_ENV=production npm run build)

# Controlled benchmark using the repository’s local target fixture
PYTHONPATH=backend backend/venv/bin/python backend/scripts/run_benchmark.py --exercise-local-target
```

The latest recorded Extension 19 review reports **143 passing backend tests**, focused browser-worker and graph-race regressions, and a successful production frontend build. Extension 18 benchmark results are controlled measurements against a known fixture; they are not a claim of universal, real-world, or state-of-the-art detection performance. See [`docs/extension18-benchmark-production-validation.md`](docs/extension18-benchmark-production-validation.md) and [`docs/BENCHMARK_RESULTS.md`](docs/BENCHMARK_RESULTS.md).

## Production deployment guidance

The checked-in `docker-compose.yml` is explicitly **development-only**. It uses source mounts and development commands for iteration and must not be promoted unchanged to production. This README does not require Docker for local development; production operators may choose any reviewed deployment technology that preserves the following controls.

| Control | Production requirement |
|---|---|
| Secrets | Supply unique `JWT_SECRET`, `UPDATE_PACKAGE_HMAC_KEY`, encryption keys, and provider credentials through a secret manager; never commit them |
| Database | Use PostgreSQL, apply Alembic migrations before admitting traffic, and configure backups and recovery |
| Queue | Use private Redis/Celery or an equivalent worker topology with explicit retry, timeout, and resource policy |
| Browser worker | Keep `/render` private to trusted application services; do not expose it through a public load balancer |
| Network | Enforce egress filtering and DNS/network policy outside the application; application SSRF checks are defense in depth |
| Runtime | Run services as unprivileged users and enforce CPU, memory, PID, temporary-storage, timeout, and no-new-privileges controls |
| CORS | Use concrete trusted origins; production rejects wildcard CORS configuration |
| Observability | Forward structured logs, metrics, health signals, and alerts to an operated monitoring system |
| Deployment | Build immutable images or artifacts from a reviewed commit; disable source mounts and hot reload |

Production startup intentionally fails closed when required security configuration is missing or unsafe. The application layer reduces risk but cannot replace infrastructure policy, isolation, or human authorization.

## Repository layout

```text
backend/
  app/                 FastAPI application, agents, orchestration, persistence
  alembic/             Versioned database migrations
  benchmarks/          Controlled local target and benchmark fixture
  scripts/             CLI, benchmark runner, and schedule utilities
  tests/               Backend regression and safety tests
browser_worker/
  app.py               Private Playwright/Chromium rendering service
frontend/
  app/                 Next.js routes and report experience
  components/          Dashboard and scan-report components
  lib/                 Typed API client and shared frontend utilities
docs/
  API.md               Versioned REST API reference
  SYSTEM_ARCHITECTURE.md  As-built topology and trust boundaries
  extension*.md        Design and verification records for each extension
config/
  local.env.example    Local configuration shape; never place secrets here
```

## Documentation map

| Document | Why it matters |
|---|---|
| [`docs/API.md`](docs/API.md) | Versioned REST endpoint and payload reference |
| [`docs/SYSTEM_ARCHITECTURE.md`](docs/SYSTEM_ARCHITECTURE.md) | As-built service topology, queues, evidence taxonomy, and trust boundaries |
| [`docs/security-assessment-integration-audit.md`](docs/security-assessment-integration-audit.md) | Compatibility and integration baseline for the assessment layer |
| [`docs/real-authorized-url-testing.md`](docs/real-authorized-url-testing.md) | Standard for real-target authorized verification |
| [`docs/extension10-correlation-graph-design.md`](docs/extension10-correlation-graph-design.md) through [`docs/extension19-production-review.md`](docs/extension19-production-review.md) | Advanced design, validation, hardening, benchmark, and production-review records |
| [`docs/BENCHMARK_RESULTS.md`](docs/BENCHMARK_RESULTS.md) | Controlled benchmark summary and methodology |
| [`LOCAL_VERIFICATION.md`](LOCAL_VERIFICATION.md) | Manual local runtime and verification notes |
| [`todo.md`](todo.md) | Current engineering follow-up items |

## Contributing safely

Contributions are welcome when they strengthen the platform without weakening its trust model. New agents and rules should be deterministic where practical, independently testable, explicit about prerequisites, tied to persisted observations, redaction-aware, bounded by scope and resource controls, and transparent about confidence and limitations.

A contribution must not add exploit automation, destructive actions, unbounded network behavior, public browser-worker exposure, fabricated report data, secret material, or a rule that treats a signature alone as proof. Changes affecting authorization, scope, SSRF, browser isolation, task orchestration, evidence provenance, report correctness, or update-package verification require regression coverage.

```bash
git checkout -b feature/short-description
# make a focused change
APP_ENV=test PYTHONPATH=backend backend/venv/bin/python -m pytest backend/tests -q
(cd frontend && npm run lint && npm run typecheck && NODE_ENV=production npm run build)
git diff --check
git status --short
```

Before opening a pull request, include the motivation, threat model, scope of the change, tests run, migration impact, operational limitations, and whether any new endpoint or worker contract was introduced. Never include credentials, live authorization headers, raw secrets, or private target data in commits, tests, screenshots, or issue reports.

## Project governance and license

This repository currently does not include a top-level `LICENSE` or `CONTRIBUTING.md` file. Before distributing the project under an open-source license or accepting external contributions at scale, add an explicit license, contribution policy, code-of-conduct policy, and security-reporting process.

For responsible security reports about the platform itself, do not publish secrets or live target data in a public issue. Contact the maintainers privately through the repository’s configured security channel once one is established.

## References

[1]: docs/extension19-production-review.md "Extension 19 targeted production review"
[2]: docs/extension18-benchmark-production-validation.md "Extension 18 benchmark and production validation"
[3]: docs/API.md "Web Autopsy Network API reference"
[4]: docs/SYSTEM_ARCHITECTURE.md "Web Autopsy Network as-built system architecture"
