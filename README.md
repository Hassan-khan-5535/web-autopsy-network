# Web Autopsy Network

> **"Dissect any website. Understand how it works."**  
> An evidence-backed web intelligence and digital-forensics platform for authorized and publicly analyzable web targets.

Web Autopsy Network captures observable evidence from target web applications, executes multi-tier analysis pipelines, and produces audit-verifiable autopsy reports. It is **not** an LLM wrapper or black-box chatbot — every finding links directly to verifiable, deterministic evidence.

---

## 🏛️ Platform Architecture & Implemented Phases

Web Autopsy Network is built as a microservice monorepo across **13 completed and pushed phases**. The latest implementation is available on the repository `main` branch.

```
                                  +-----------------------+
                                  |   Next.js 15 UI       |
                                  |   (React 19, TS)      |
                                  +-----------+-----------+
                                              | REST API
                                              v
                                  +-----------------------+
                                  |   FastAPI Control     |
                                  |   Plane API Gateway   |
                                  +---+-------+-------+---+
                                      |       |       |
                 +--------------------+       |       +-------------------+
                 | PostgreSQL DB              |                           | HTTP
                 v                            v                           v
     +-----------------------+    +-----------------------+   +-----------------------+
     | SQLAlchemy Models &   |    | Redis Queue &         |   | Playwright Browser    |
     | Alembic Migrations    |    | Cache Store           |   | Microservice Container|
     +-----------------------+    +-----------------------+   +-----------------------+
```

### Completed Phases Breakdown

- 🟢 **Phase 1 — System Architecture Foundation**: Distributed monorepo layout, Docker Compose containerization (PostgreSQL 16, Redis 7, FastAPI 0.115, Next.js 15), baseline settings management, and structured JSON logging.
- 🟢 **Phase 2 — Admission & HTTP Collector**: Strict pre-navigation SSRF protection (IP validation blocking RFC-1918 private subnets, loopback `127.0.0.1`, cloud metadata `169.254.169.254`, and non-HTTP protocols), passive HTTP response header extraction, and raw HTML body persistence.
- 🟢 **Phase 3 — Bounded BFS Crawler**: Same-domain, depth-limited, rate-limited, `robots.txt`-compliant Breadth-First Search (BFS) crawler with deterministic URL normalization and fragment stripping.
- 🟢 **Phase 4 — Technology DNA Engine**: Rule-based signature engine detecting frameworks, CMSs, CDNs, fonts, and analytics with confidence scoring (0.0–1.0) and mandatory linked evidence gating.
- 🟢 **Phase 5 — Structure + Dependency Intelligence**:
  - `StructureAgent`: Site tree reconstruction, internal vs external link statistics, form inventory extraction, and page type classification (`🟡 INFERRED`).
  - `ApiIntelligenceAgent`: Static discovery of candidate API routes (`/api/`, `/v1/`, `fetch()`, `axios`) with HTTP method and content-type inference.
  - `NetworkIntelligenceAgent`: External domain dependency graphing mapped against Phase 4 technology categories.
  - Interactive SVG/Canvas node-link dependency graph UI with zoom, search, category filters, and click-to-inspect evidence panels.
- 🟢 **Phase 6 — Isolated Browser Analysis (Playwright Worker)**:
  - Dedicated Python Playwright microservice (`browser-worker`) running in an isolated Docker container.
  - **Sub-Resource SSRF Protection**: Intercepts *every single outbound request* (scripts, CSS, fetch/XHR, iframes, redirects) via `page.route("**/*")` and aborts forbidden private IP targets before network execution.
  - Captures post-JS fully rendered DOM HTML (`rendered_body`), dynamic runtime network requests (`capture_source="browser_runtime"`), Navigation & Resource Timing API performance metrics (`timing_data`), and browser console warnings/errors (`BROWSER_CONSOLE`).
  - Interactive frontend DOM Inspector allowing side-by-side comparison of Static Raw HTML vs. Rendered DOM HTML.
- 🟢 **Phase 7 — Passive Security Analysis**:
  - Evaluates stored security headers, HTTPS/HSTS observations, cookie attributes, CORS response headers, verbose metadata, source-map references, and sensitive-looking HTML comments without issuing new target requests.
  - Persists `SecurityFinding` records with `OBSERVED` or `INFERRED` classification, confidence bands, severity, rule version, limitations, and non-empty evidence arrays enforced by an Evidence Agent gate.
  - Adds `GET /v1/scans/{id}/security` and a Security section with expandable evidence to the scan results page.
- 🟢 **Phase 8 — Passive Performance Intelligence**: Deterministic performance metrics and diagnoses from persisted HTTP, resource, browser timing, and runtime evidence, including payload composition, render-blocking resources, third-party overhead, and evidence-linked recommendations.
- 🟢 **Phase 9 — Accessibility and Content/SEO Intelligence**: Automated rendered-DOM accessibility checks, metadata and content analysis, duplicate-content signals, page provenance, confidence classifications, and report sections with evidence links.
- 🟢 **Phase 10 — AI Doctor and Evidence-Grounded Synthesis**: Provider-abstracted LLM integration, structured AI Doctor answers, executive synthesis, rate limiting, strict citation validation, and graceful degradation when an AI provider is unavailable. AI output remains `🔵 AI INTERPRETATION` and cannot replace deterministic findings.
- 🟢 **Phase 11 — History / Time Machine**: Persisted scan comparisons with deterministic page, technology, dependency, security, performance, accessibility, and content diffs; stable difference IDs; AI change explanations constrained by the shared evidence gate; comparison APIs; and the interactive History panel.
- 🟢 **Phase 12 — Cause of Death Diagnosis**: Explicit Risk/Impact Engine ranking across impact, confidence, severity, dependency criticality, frequency, and user-facing effect; persisted primary, secondary, and contributing issues; evidence-count confidence; constrained AI narrative; required diagnostic disclaimer; risk and diagnosis APIs; and the branded Cause of Death report card.
- 🟢 **Phase 13 — Distributed Scaling**: Redis/Celery task queues, persisted `AgentTask` and `AgentEvent` state, dependency-aware lifecycle graph, independently scalable crawl/browser/analysis/AI worker pools, retries, idempotency keys, concurrency backpressure, stale-worker recovery, scan timeouts, cancellation propagation, worker health, progress APIs, SSE updates, and the live checklist progress view. **Phase 13 is implemented, locally verified, committed, and pushed to `main`.**

---

## 🏷️ Evidence Claim Taxonomy

Every finding in Web Autopsy Network is strictly classified under a four-level claim taxonomy:

| Classification | Meaning | Example |
|---|---|---|
| 🟢 **OBSERVED** | Directly measured facts captured during HTTP collection or browser rendering. | HTTP status 200, response header `server: nginx`, DOM element `<script src="react.js">`, console error. |
| 🟡 **INFERRED** | Technically supported conclusions derived from one or more observations. | Detected React technology (confidence 0.95), page classified as `contact_or_form`, API route `/v1/scans`. |
| 🔵 **AI INTERPRETATION** | Higher-level architectural summaries or natural language explanations. | AI Doctor answers, change explanations, executive synthesis, and Cause of Death narrative; always grounded in 🟢 and 🟡 evidence. |
| ⚫ **UNKNOWN** | Properties that cannot be observed or confirmed from public evidence. | Server filesystem path, backend database engine, internal environment variables. |

---

## 🛠️ Terminal Commands & Operations Guide

### 1. Stack Startup (Docker Compose)

Start all services (PostgreSQL, Redis, FastAPI Backend, Browser Worker, Next.js Frontend):

```bash
# Copy the local environment configuration template
cp config/local.env.example .env

# Build and launch all services in Docker Compose (runs on ports 8000, 8001, 3001)
docker compose up --build
```

#### Running Service Endpoints
- **Next.js Frontend Application**: [`http://localhost:3000`](http://localhost:3000) (or port `3001` if port 3000 is occupied)
- **FastAPI Interactive Swagger Docs**: [`http://localhost:8000/docs`](http://localhost:8000/docs)
- **Backend API Health Check**: [`http://localhost:8000/health`](http://localhost:8000/health)
- **Playwright Browser Worker Health Check**: [`http://localhost:8001/health`](http://localhost:8001/health)

---

### 2. Database Migrations (Alembic)

Apply schema migrations against the running PostgreSQL container:

```bash
# Apply all schema migrations up to latest (0001 through 0007_phase7_security)
docker compose exec backend alembic upgrade head
```

Roll back or generate new migrations:

```bash
# Downgrade schema by 1 revision step
docker compose exec backend alembic downgrade -1

# Generate a new migration script automatically after updating SQLAlchemy models
docker compose exec backend alembic revision --autogenerate -m "description of changes"
```

---

### 3. Backend Testing Suite (Pytest)

Run the full automated Pytest test suite (44 tests covering SSRF, Crawler, Tech DNA, Structure, API Intelligence, Network Intelligence, Playwright Worker, REST APIs, passive Security Analysis, History, Cause of Death, and distributed task execution):

```bash
# Change directory into backend
cd backend

# Install dependencies (for local test execution outside Docker)
pip install -r requirements.txt -r requirements-dev.txt

# Run the complete test suite with verbose output
pytest -v
```

#### Run Specific Subsystem Test Suites

```bash
# Test Phase 6 Browser Worker SSRF Sub-Resource Request Interception
pytest tests/test_browser_ssrf.py -v

# Test Phase 6 Browser Worker Integration & Rendered Evidence Storage
pytest tests/test_browser_integration.py -v

# Test Phase 6 REST API Endpoint (/scans/{id}/pages/{page_id}/rendered)
pytest tests/test_phase6_endpoints.py -v

# Test Phase 5 REST API Endpoints (/architecture, /dependencies, /api-endpoints)
pytest tests/test_phase5_endpoints.py -v

# Test Structure Agent (Hierarchy, Link Stats, Form Inventory, Page Types)
pytest tests/test_structure.py -v

# Test API Intelligence Agent (Static API Discovery & HTTP Method Inference)
pytest tests/test_api_intelligence.py -v

# Test Network Intelligence Agent (External Domain Graph & Tech Mapping)
pytest tests/test_network_intelligence.py -v

# Test Technology DNA Fingerprinting & Evidence Gating (Phase 4)
pytest tests/test_technology.py -v

# Test Phase 7 passive Security Analysis and Evidence Agent enforcement
pytest tests/test_security.py tests/test_phase7_endpoints.py -v

# Test Crawler & Admission SSRF Safeguards (Phase 2 & 3)
pytest tests/test_crawler.py -v
```

---

### 4. Frontend Development & Static Code Analysis

```bash
# Change directory into frontend
cd frontend

# Install Node.js dependencies
npm install

# Start Next.js development server
npm run dev

# Run TypeScript compiler static typecheck (verifies 0 type errors)
npm run typecheck

# Run Next.js ESLint code quality linter (verifies 0 lint errors/warnings)
npm run lint
```

---

## 🔐 Phase 7 Security Analysis

Phase 7 is strictly passive. `SecurityAnalysisService` reads only persisted `HTTPResponse`, `Header`, `Resource`, `Page`, `Observation`, and browser-capture fields. It does not call the target, probe suspected paths, fetch source maps, submit forms, test credentials, exploit any condition, or perform active CORS/security testing.

Header presence and literal configuration facts are classified as `OBSERVED`. Combined risk framing, such as missing CSP together with stored inline scripts or wildcard CORS together with credentials allowed, is classified as `INFERRED` and cites every contributing evidence item. A missing header is not itself proof of compromise, and a suspected `.git`, `.env`, or source-map reference is recorded as a passive manual follow-up suggestion rather than fetched.

The API endpoint is:

```text
GET /v1/scans/{scan_id}/security
```

Each finding includes its subject, statement, classification, confidence, confidence band, severity, rule ID, ruleset version, limitations, page provenance, and a non-empty evidence array. The existing `/v1/scans/{scan_id}/evidence` feed also includes security findings with category `SECURITY`.

## 📡 REST API Reference & cURL Usage

| Method | Route | Description |
|---|---|---|
| `POST` | `/v1/scans` | Create and execute passive autopsy scan for an authorized URL. |
| `GET` | `/v1/scans/{id}` | Retrieve scan lifecycle state and crawl config. |
| `GET` | `/v1/scans/{id}/pages` | Retrieve site map (URLs, depth, status code, title, discovery source). |
| `GET` | `/v1/scans/{id}/technologies` | Retrieve detected technologies, confidence scores, and linked evidence items. |
| `GET` | `/v1/scans/{id}/architecture` | Retrieve site tree hierarchy, link stats, form inventory, and inferred page types (`🟡 INFERRED`). |
| `GET` | `/v1/scans/{id}/dependencies` | Retrieve external domain dependency graph nodes with reference counts and sample URLs. |
| `GET` | `/v1/scans/{id}/api-endpoints` | Retrieve candidate API endpoints catalog (path, method, content-type, confidence). |
| `GET` | `/v1/scans/{id}/pages/{page_id}/rendered` | **[Phase 6]** Retrieve raw static HTML vs post-JS rendered DOM HTML, browser performance timing, and console logs. |
| `GET` | `/v1/scans/{id}/evidence` | Retrieve raw observation evidence feed (`🟢 OBSERVED`). |

#### cURL Examples with Comments

```bash
# 1. Submit target URL for automated passive autopsy (returns scan payload with scan ID)
curl -X POST http://localhost:8000/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "https://example.com",
    "authorization_acknowledged": true,
    "max_depth": 2,
    "max_pages": 30
  }'

# 2. Query scan status and progress
curl -s http://localhost:8000/v1/scans/{scan_id} | jq .

# 3. Retrieve site map pages
curl -s http://localhost:8000/v1/scans/{scan_id}/pages | jq .

# 4. Retrieve Phase 6 Post-JS Rendered DOM, timing metrics, and console logs for a page
curl -s http://localhost:8000/v1/scans/{scan_id}/pages/{page_id}/rendered | jq .

# 5. Retrieve site architecture, form inventory, and inferred page types
curl -s http://localhost:8000/v1/scans/{scan_id}/architecture | jq .

# 6. Retrieve external dependency graph categorized by service (Analytics, CDN, Fonts)
curl -s http://localhost:8000/v1/scans/{scan_id}/dependencies | jq .

# 7. Retrieve candidate API endpoints catalog
curl -s http://localhost:8000/v1/scans/{scan_id}/api-endpoints | jq .

# 8. Retrieve complete raw observation evidence feed for auditability
curl -s http://localhost:8000/v1/scans/{scan_id}/evidence | jq .
```

---

## 📂 Project Repository Structure

```
web-autopsy-network/
├── backend/
│   ├── alembic/              # Database migration scripts (0001 through 0006_phase6_browser_analysis)
│   ├── app/
│   │   ├── api/              # FastAPI routers, dependencies, and v1 endpoints
│   │   ├── core/             # Settings, logging, database connections
│   │   ├── data/             # Technology signature rules (technology_signatures.json)
│   │   ├── models/           # SQLAlchemy ORM models (scan.py, base.py)
│   │   └── services/         # Admission, Crawler, Tech, Structure, API, Network, Browser Client
│   ├── tests/                # Pytest test suite (20 unit and integration tests)
│   ├── Dockerfile
│   └── requirements.txt
├── browser_worker/           # [Phase 6] Isolated Playwright Browser Microservice
│   ├── app.py                # FastAPI server with sub-resource SSRF request interception
│   ├── Dockerfile            # Playwright Noble Python base image
│   └── requirements.txt
├── frontend/
│   ├── app/                  # Next.js 15 App Router pages (/scans, /scans/[id])
│   ├── components/           # UI components (DependencyGraph.tsx, DOM Inspector Modal)
│   ├── lib/                  # Frontend API client and TypeScript interface definitions
│   └── package.json
├── config/                   # Environment templates (local.env.example)
├── docs/                     # Technical specifications and design documents
└── docker-compose.yml        # Orchestration for PostgreSQL, Redis, Backend, Browser Worker, Frontend
```

---

## 📄 License

Educational and authorized research project. All rights reserved.
