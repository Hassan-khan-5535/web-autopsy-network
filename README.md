<div align="center">

  <h1>🔬 Web Autopsy Network</h1>
  <p><strong>Dissect any website. Understand how it works. Zero hallucinations.</strong></p>
  <p>An evidence-backed, distributed digital forensics and web intelligence platform for authorized web targets.</p>

  <p>
    <a href="https://github.com/your-username/web-autopsy-network/actions"><img src="https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge&logo=githubactions" alt="Build Status" /></a>
    <a href="#6-testing"><img src="https://img.shields.io/badge/Tests-60%2F60%20Passed-emerald?style=for-the-badge&logo=pytest" alt="Tests Passed" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License" /></a>
    <a href="#4-tech-stack"><img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python" alt="Python" /></a>
    <a href="#4-tech-stack"><img src="https://img.shields.io/badge/Frontend-Next.js%2015-black?style=for-the-badge&logo=next.js" alt="Next.js" /></a>
    <a href="#4-tech-stack"><img src="https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi" alt="FastAPI" /></a>
    <a href="#4-tech-stack"><img src="https://img.shields.io/badge/AI-Gemini%202.5%20Flash-4285F4?style=for-the-badge&logo=google" alt="Gemini AI" /></a>
  </p>

  <p>
    <a href="http://localhost:3000/scans/demo-scan-autopsy"><strong>🚀 Live Demo</strong></a> •
    <a href="https://github.com/your-username/web-autopsy-network/issues/new?template=bug_report.md"><strong>🐛 Report Bug</strong></a> •
    <a href="https://github.com/your-username/web-autopsy-network/issues/new?template=feature_request.md"><strong>✨ Request Feature</strong></a> •
    <a href="docs/API.md"><strong>📖 API Reference</strong></a>
  </p>

</div>

---

## 📸 Preview

![Web Autopsy Network Dashboard](docs/assets/dashboard-preview.png)
> *Placeholder: Interactive Web Autopsy dashboard displaying Cause of Death verdict, real-time pipeline execution, and citation-grounded AI diagnostic reasoning.*

---

## ✨ Key Features

* 🎯 **Cause of Death Forensic Verdict:** Deterministic prioritization engine that analyzes telemetry to pinpoint the primary root-cause bottleneck (e.g., render-blocking JS bundles, missing CSP headers, or high LCP).
* 🤖 **Citation-Grounded AI Doctor:** Advanced LLM synthesis (powered by Gemini 2.5 Flash or GPT-4o) operating behind a strict evidence validation gate that strips or flags ungrounded claims (`[UNGROUNDED_CLAIM_REJECTED]`).
* 🛡️ **Passive Security & Performance Audits:** Zero-latency evaluation of security headers, HSTS, CORS origins, cookie security flags, and Core Web Vitals (LCP, FID, CLS, TTFB).
* 🌐 **Sandboxed Browser Execution & Dependency Graph:** Sub-resource SSRF-protected Playwright microservice that captures DOM state, console logs, dynamic timing, and renders interactive SVG dependency maps.
* ⏱️ **Time Machine & Historical Diff Engine:** Version-controlled scan history with deterministic category-by-category diffing and automated change summaries.

---

## 🛠️ Tech Stack

### Core Architecture
* **Frontend:** Next.js 15, React 19, TypeScript, Tailwind CSS, Lucide React.
* **Backend:** FastAPI, Python 3.11+, SQLAlchemy 2.0, Alembic, Structlog.
* **Database:** PostgreSQL (Production) / SQLite (Local Fallback) with eager loading (`selectinload`) and composite indexes.
* **AI & LLM Integration:** OpenAI SDK, Google Gemini 2.5 Flash / OpenAI GPT-4o, Custom Citation Verification Gate.

### Infrastructure & DevOps
* **Distributed Task Queue:** Celery, Redis, 4 Parallel Worker Pools (`worker-crawl`, `worker-browser`, `worker-analysis`, `worker-ai`).
* **Browser Container Sandbox:** Python Playwright Microservice with socket-level IP connection hooks & SSRF shields.
* **Orchestration & Containerization:** Docker, Docker Compose.

---

## ⚡ Getting Started

### Prerequisites

Ensure you have the following installed locally:
* **Node.js:** v18.0.0 or higher
* **Python:** v3.11 or higher
* **Docker & Docker Compose:** *(Optional, recommended for full distributed mode)*

---

### Environment Setup (`.env`)

Create a `.env` file in the project root by copying the template:

```bash
cp backend/config.env.example .env
```

Configure your environment variables in `.env`:

```env
COMPOSE_PROJECT_NAME=web-autopsy-network
POSTGRES_DB=web_autopsy
POSTGRES_USER=web_autopsy
POSTGRES_PASSWORD=change-me-for-local-development
POSTGRES_PORT=5432
REDIS_PORT=6380

BACKEND_PORT=8000
FRONTEND_PORT=3000
DATABASE_URL=postgresql+psycopg://web_autopsy:change-me-for-local-development@postgres:5432/web_autopsy
CORS_ORIGINS=http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3001

# LLM Configuration (Gemini 2.5 Flash / OpenAI)
LLM_API_KEY=your_actual_api_key_here
LLM_API_BASE=https://generativelanguage.googleapis.com/v1beta/openai/
LLM_MODEL=gemini-2.5-flash
```

---

### Running the Application

#### Method 1: Docker Compose (Recommended)

To run the complete microservice architecture:

```bash
# Build and start all services
docker compose up --build
```

Access the applications:
* **Frontend Web UI:** `http://localhost:3000`
* **Backend API Docs:** `http://localhost:8000/docs`

---

#### Method 2: Local Direct Service (Without Docker)

To run the application locally without Docker containers:

**1. Start Browser Worker:**

Real-site browser analysis requires the browser worker in manual mode. Start it in a separate terminal. On Linux/macOS, use the installed Chromium executable:

```bash
cd browser_worker
BROWSER_EXECUTABLE_PATH="/usr/bin/chromium" PYTHONPATH="." python3 -m uvicorn app:app --host 127.0.0.1 --port 8001
```

Verify it with `curl http://127.0.0.1:8001/health`. On Windows, set `BROWSER_EXECUTABLE_PATH` to the installed Chromium or Chrome executable.

**2. Start Backend API:**

*PowerShell (Windows):*
```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
$env:DATABASE_URL="sqlite:///web-autopsy-demo.db"
$env:QUEUE_MODE="inline"
$env:CORS_ORIGINS="http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3001"
$env:BROWSER_WORKER_URL="http://127.0.0.1:8001"
$env:PYTHONPATH="."
python -m pip install -r requirements.txt
python seed_phase13_demo.py
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

*Bash (Linux/macOS):*
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
DATABASE_URL="sqlite:///web-autopsy-demo.db" QUEUE_MODE="inline" CORS_ORIGINS="http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3001" PYTHONPATH="." python3 seed_phase13_demo.py
DATABASE_URL="sqlite:///web-autopsy-demo.db" QUEUE_MODE="inline" BROWSER_WORKER_URL="http://127.0.0.1:8001" CORS_ORIGINS="http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3001" PYTHONPATH="." python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

**3. Start Frontend Web UI in development mode:**

Open a second terminal and run:

```bash
cd frontend
npm ci
npm run dev:3001
```

Access the UI at `http://localhost:3001`. The `dev:3001` command compiles the app on demand; do not use `npm start` for development.

**Production-mode alternative:**

The production build uses standalone output. The `postbuild` script copies `.next/static` into the standalone server tree so CSS and JavaScript assets are served correctly.

If you specifically want `next start`, a production build must exist first. Run these commands in the `frontend` directory:

```bash
npm ci
rm -rf .next
npm run build
npm run start:3001
```

The error `Could not find a production build in the '.next' directory` means `npm start` was run before `npm run build`, or the `.next` directory was deleted. It is not fixed by changing the browser URL; build first, then start.

**Public sandbox/link mode:**

The frontend now uses a same-origin `/api` proxy by default. This prevents a public browser from accidentally calling its own `localhost:8000`. Run the backend and frontend on the same machine; no `NEXT_PUBLIC_API_BASE_URL` value is required for the public link:

```bash
# Backend terminal
cd backend
source venv/bin/activate
DATABASE_URL="sqlite:///web-autopsy-demo.db" \
QUEUE_MODE="inline" \
BROWSER_WORKER_URL="http://127.0.0.1:8001" \
PYTHONPATH="." \
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Frontend terminal
cd frontend
npm run build
npm run start:3001
```

The Next.js server forwards `/api/*` to `http://127.0.0.1:8000/*`, so browser requests remain same-origin. Set `NEXT_PUBLIC_API_BASE_URL` only when the backend is deployed on a separate host.

---

## 🧪 Testing

Execute the automated test suites to verify system integrity:

```bash
# 1. Run Backend 60-Test Regression Suite (100% Pass Rate)
cd backend
pytest tests/ -v

# 2. Run Frontend TypeScript Typecheck (0 Errors)
npm --prefix frontend run typecheck

# 3. Run Frontend Code Quality Audit (0 Warnings/Errors)
npm --prefix frontend run lint
```

---

## 🗺️ Roadmap

- [x] **Phase 1 — System Architecture Foundation:** Monorepo setup, settings, structured logging.
- [x] **Phase 2 — Admission & HTTP Collector:** Socket-level SSRF protection & passive HTTP collector.
- [x] **Phase 3 — Bounded BFS Crawler:** Same-domain, rate-limited, robots.txt compliant crawler.
- [x] **Phase 4 — Technology DNA Engine:** Signature detection with confidence scoring.
- [x] **Phase 5 — Structure & Dependency Graph:** Route tree discovery & interactive SVG node graph.
- [x] **Phase 6 — Isolated Browser Analysis:** Playwright container sandbox & DOM timing capture.
- [x] **Phase 7 — Passive Security Analysis:** Evaluation of HSTS, CSP, cookies, CORS, and headers.
- [x] **Phase 8 — Passive Performance Engine:** Core Web Vitals (LCP, FID, CLS) computation.
- [x] **Phase 9 — Accessibility & Content/SEO:** WCAG automated audit & SEO content analysis.
- [x] **Phase 10 — AI Doctor & Citation Synthesis:** Citation-grounded LLM reasoning layer.
- [x] **Phase 11 — History & Time Machine:** Historical comparisons & deterministic diffing.
- [x] **Phase 12 — Cause of Death Diagnosis:** Multi-dimensional risk/impact prioritization verdict.
- [x] **Phase 13 — Distributed Worker Scaling:** Celery/Redis queues with 4 worker pools & SSE streams.
- [x] **Phase 14 — Production Hardening:** DNS rebinding protection, DB N+1 query removal, Redis cache, wall-clock scan expiry.
- [ ] **Phase 15 — Multi-Region Distributed Collectors:** Edge collector nodes for worldwide latency profiling.
- [ ] **Phase 16 — Automated Remediation PRs:** One-click GitHub PR generation for flagged security headers & performance fixes.

---

## 🤝 Contributing & License

Contributions are welcome! Follow this workflow to contribute:

1. **Fork** the repository.
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`).
3. **Commit** your changes (`git commit -m 'feat: add amazing feature'`).
4. **Push** to the branch (`git push origin feature/amazing-feature`).
5. **Open** a Pull Request.

### License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.

---

## 📬 Contact

* **Project Maintainer:** [Your Name / Team Name](https://github.com/your-username)
* **Twitter / X:** [@your_handle](https://twitter.com/your_handle)
* **Discord Community:** [Join Discord Server](https://discord.gg/your-community)
* **Email:** maintainer@webautopsynetwork.io
