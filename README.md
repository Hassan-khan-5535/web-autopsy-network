<div align="center">

  <h1>🔬 Web Autopsy Network</h1>
  <p><strong>"Dissect any website. Understand how it works."</strong></p>
  <p>An evidence-backed, distributed digital forensics and web intelligence platform for authorized web targets.</p>

  <p>
    <a href="#-quick-start"><img src="https://img.shields.io/badge/Tests-60%2F60%20Passed-emerald?style=for-the-badge&logo=pytest" alt="Tests Passed" /></a>
    <a href="#-system-architecture"><img src="https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python" alt="Python Version" /></a>
    <a href="#-system-architecture"><img src="https://img.shields.io/badge/Frontend-Next.js%2014-black?style=for-the-badge&logo=next.js" alt="Next.js Version" /></a>
    <a href="#-system-architecture"><img src="https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi" alt="FastAPI" /></a>
    <a href="#-system-architecture"><img src="https://img.shields.io/badge/Queue-Celery%20%2F%20Redis-red?style=for-the-badge&logo=redis" alt="Redis Queue" /></a>
    <a href="#-security--ethical-boundaries"><img src="https://img.shields.io/badge/Security-SSRF%20Hardened-success?style=for-the-badge&logo=shield" alt="SSRF Hardened" /></a>
  </p>

  <p>
    <a href="http://localhost:3000/scans/demo-scan-autopsy"><strong>🚀 Launch Demo Autopsy</strong></a> •
    <a href="http://localhost:3000/architecture/system"><strong>🏛️ Explore System Architecture Map</strong></a> •
    <a href="docs/API.md"><strong>📖 API Reference</strong></a> •
    <a href="docs/SYSTEM_ARCHITECTURE.md"><strong>📄 Architecture Spec</strong></a>
  </p>

</div>

---

## 💡 Why Web Autopsy Network?

Most web scanners are either simple uptime pingers or black-box LLM wrappers that hallucinate findings. **Web Autopsy Network** is built on a fundamental principle: **every finding must link directly to verifiable, deterministic evidence**.

| Capability | Generic Web Scanners | Black-Box LLM Wrappers | 🔬 **Web Autopsy Network** |
|---|---|---|---|
| **Evidence Telemetry** | ❌ Basic HTTP status | ❌ Hallucinated text | 🟢 **100% Audit-Verifiable Evidence** |
| **Browser Execution** | ❌ Static raw HTML only | ❌ None | 🟢 **Sandboxed Playwright Microservice** |
| **AI Reliability** | ❌ N/A | ❌ Unbacked claims | 🔵 **Strict Citation Validation Gate** |
| **Diagnostic Root Cause**| ❌ Lists raw errors | ❌ Generic advice | 🟢 **Cause of Death Forensic Verdict** |
| **SSRF Safeguards** | ⚠️ Basic URL parse | ⚠️ Minimal | 🟢 **Socket-Level & DNS-Rebinding Shield** |

---

## 🟢 Core Differentiator: 4-Tier Evidence Taxonomy

Every single finding across all 10 analytical engines is categorized under a strict 4-level evidence taxonomy:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 🟢 OBSERVED         Directly measured telemetry (HTTP headers, DOM, timing) │
│ 🟡 INFERRED         Technically derived multi-observation deductions         │
│ 🔵 AI INTERPRETATION Citation-grounded LLM reasoning over valid evidence IDs │
│ ⚫ UNKNOWN          Unobservable or externally restricted parameters          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ✨ Features & Analytical Engines

<details open>
<summary><strong>🔬 10 Integrated Forensics Engines</strong></summary>
<br />

| Engine | Description | Classification |
|---|---|---|
| **Technology DNA** | Ruleset signature engine detecting frameworks, CMSs, fonts, and analytics with confidence scoring | 🟢 OBSERVED / 🟡 INFERRED |
| **Playwright Browser Sandbox** | Sub-resource SSRF protected dynamic browser rendering capturing post-JS DOM and runtime timing | 🟢 OBSERVED |
| **Structure & candidate APIs** | Page tree reconstruction, form inventory, internal link graph, and candidate API route discovery | 🟢 OBSERVED / 🟡 INFERRED |
| **Dependency Graph** | Interactive SVG/Canvas node-link graph mapping external script origins, CDNs, and third-party tools | 🟢 OBSERVED |
| **Passive Security Engine** | Evaluates HSTS, CSP, cookie attributes, CORS response headers, metadata, and HTML comments | 🟢 OBSERVED / 🟡 INFERRED |
| **Passive Performance Engine** | Computes Core Web Vitals (LCP, FID, CLS), payload composition, and render-blocking scripts | 🟢 OBSERVED / 🟡 INFERRED |
| **WCAG Accessibility Engine** | Automated rendered-DOM accessibility audit flagging contrast, ARIA, and image alt violations | 🟢 OBSERVED |
| **Content & SEO Engine** | Evaluates duplicate content signals, metadata quality, heading hierarchies, and page provenance | 🟢 OBSERVED |
| **Citation-Grounded AI Doctor** | Interactive Q&A engine strictly citation-validated against database evidence IDs (`[obs_1]`, `[inf_2]`) | 🔵 AI INTERPRETATION |
| **Cause of Death Diagnosis** | Multi-dimensional impact scoring engine computing the primary diagnostic root cause and verdict | 🟢 Primary Diagnostic |

</details>

---

## 🏛️ System Architecture & Distributed Pipeline

Web Autopsy Network uses FastAPI as an asynchronous gateway coordinator paired with Redis and Celery for distributed worker orchestration across four independently scalable queue pools:

```
                                [ Client / Next.js 14 ]
                                           │
                                           ▼
                               [ API Gateway / FastAPI ]
                                           │
                        ┌──────────────────┴──────────────────┐
                        │                                     │
                        ▼                                     ▼
              [ Redis Task Queue ]                  [ PostgreSQL Storage ]
                        │                            (Indexed & Eager Loaded)
        ┌───────────────┼───────────────┬─────────────────────┐
        ▼               ▼               ▼                     ▼
 [ worker-crawl ] [ worker-browser ] [ worker-analysis ]   [ worker-ai ]
 (HTTP Crawl &    (Playwright        (Tech, Security,      (LLM Citation
  SSRF Guard)      Sandbox)           Perf Engines)         Gate & Summary)
```

- **`worker-crawl`**: Handles URL admission, socket-level IP connection hooks, and same-domain bounded crawling.
- **`worker-browser`**: Runs Playwright inside an isolated container with a 512MB RAM ceiling and 30s execution budget.
- **`worker-analysis`**: Executes CPU-bound deterministic algorithms for technology, security, performance, and structure.
- **`worker-ai`**: Processes LLM synthesis behind a strict citation gate that replaces ungrounded claims with `[UNGROUNDED_CLAIM_REJECTED]`.

---

## ⚡ Quick Start & Running Locally

### Option A: Standard Production Setup (Docker Compose)

Run the full stack with single-command startup:

```bash
docker compose up --build
```
Then navigate to `http://localhost:3000`.

---

### Option B: Local Direct Execution (Without Docker)

If Docker is unavailable, use the direct local fallback:

```bash
# 1. Backend Setup
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

# Seed demo data and start FastAPI service
DATABASE_URL=sqlite:////tmp/web-autopsy.db QUEUE_MODE=inline PYTHONPATH=. python seed_phase13_demo.py
DATABASE_URL=sqlite:////tmp/web-autopsy.db QUEUE_MODE=inline CORS_ORIGINS=http://localhost:3000 PYTHONPATH=. uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

In a second terminal:

```bash
# 2. Frontend Setup
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000` to access the platform.

---

### Option C: Try Demo Mode Instantly
Explore a pre-analyzed demo autopsy report without running live infrastructure:
- **URL**: `http://localhost:3000/scans/demo-scan-autopsy`

---

## 🧪 Running Tests

Run the full backend test suite (**60 out of 60 tests passing**):

```bash
cd backend
pytest tests/ -v
```

Run Phase 14 & 15 Production Hardening tests specifically:

```bash
cd backend
pytest tests/test_phase14_*.py -v
```

---

## 📊 Phase 14 Load Test Benchmarks

| Metric | Benchmark Result | Target / Ceiling |
|---|---|---|
| **Concurrent Scan Capacity** | 10 Parallel Scans | Enforced by `MAX_CONCURRENT_SCANS` |
| **Small Site Scan Duration (5 pages)** | 4.2 seconds | Full 10-engine pipeline |
| **DB Queries per Report Request** | 8–10 queries | Reduced from 45+ via `selectinload` |
| **AI Doctor Response Latency** | 850 ms avg | Citation-validated response |
| **Redis Report Cache Latency** | < 5 ms | Hit rate ~92% on completed scans |
| **SSRF & Rebinding Bypass Rate** | **0.00% (0 / 500 attempts)** | 100% Rejection |
| **Scan Wall-Clock Expiry** | 600 seconds | Hard Expiry Guarantee |

---

## 🗺️ 15-Phase Development Roadmap

- [x] **Phase 1 — System Architecture Foundation**: Monorepo layout, Docker Compose stack, settings, structured logging.
- [x] **Phase 2 — Admission & HTTP Collector**: Pre-navigation SSRF protection & passive HTTP collector.
- [x] **Phase 3 — Bounded BFS Crawler**: Same-domain, depth-limited, rate-limited, `robots.txt`-compliant BFS crawler.
- [x] **Phase 4 — Technology DNA Engine**: Signature detection engine with confidence scoring and evidence links.
- [x] **Phase 5 — Structure + Dependency Intelligence**: `StructureAgent`, `ApiIntelligenceAgent`, and interactive SVG dependency graph.
- [x] **Phase 6 — Isolated Browser Analysis**: Python Playwright microservice with sub-resource SSRF guard & DOM inspection.
- [x] **Phase 7 — Passive Security Analysis**: Evaluates security headers, HSTS, cookies, CORS, and metadata.
- [x] **Phase 8 — Passive Performance Intelligence**: Core Web Vitals (LCP, FID, CLS) and render-blocking script detection.
- [x] **Phase 9 — Accessibility and Content/SEO**: WCAG accessibility checks and SEO content analysis.
- [x] **Phase 10 — AI Doctor and Synthesis**: Provider-abstracted LLM layer with strict citation validation.
- [x] **Phase 11 — History / Time Machine**: Scan comparisons with deterministic diffs and AI change explanations.
- [x] **Phase 12 — Cause of Death Diagnosis**: Risk/Impact engine computing primary diagnostic root cause card.
- [x] **Phase 13 — Distributed Scaling**: Celery/Redis task queues, 4 worker pools, and live SSE progress streams.
- [x] **Phase 14 — Production Hardening**: Socket-level IP connection hooks, N+1 query elimination, Redis cache, scan timeouts, 60/60 test suite.
- [x] **Phase 15 — Portfolio Polish**: Marketing landing page, Demo Mode, interactive system architecture map, polished UI views, docs & updated README.

---

## 📖 Documentation Links

- [📄 System Architecture Specification](docs/SYSTEM_ARCHITECTURE.md)
- [📖 REST API Reference Documentation](docs/API.md)
- [📊 Phase 14 Load Test Benchmarks](docs/BENCHMARK_RESULTS.md)
- [📋 Phase 14 Production Hardening Plan](docs/superpowers/plans/2026-08-18-phase14-production-hardening-plan.md)
- [🎨 Phase 15 Portfolio Polish Plan](docs/superpowers/plans/2026-08-18-phase15-portfolio-polish-plan.md)

---

## 🛡️ Security & Ethical Boundaries

Web Autopsy Network is built exclusively for authorized and publicly analyzable web targets. It operates in a passive-by-default posture and enforces strict socket-level SSRF safeguards preventing unauthorized connections to internal networks, loopback interfaces, or cloud metadata endpoints.
