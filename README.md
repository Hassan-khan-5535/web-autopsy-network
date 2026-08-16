# Web Autopsy Network

Web Autopsy Network is an evidence-backed web intelligence platform for **authorized public websites**. 

This repository includes **Phase 1 (Project Foundation)**, **Phase 2 (URL Admission & HTTP Collector)**, **Phase 3 (Controlled Crawler)**, and **Phase 4 (Technology DNA)**. It safely admits target URLs, fetches passive evidence, builds a bounded, reproducible same-domain site map from static HTML, and runs deterministic, evidence-backed technology fingerprinting. Phase 4 introduces **INFERRED** findings with transparent confidence scoring; JavaScript rendering and AI interpretation remain deferred to later phases.

## Architecture & Features

| Component | Purpose |
|---|---|
| **Frontend** | Next.js, TypeScript, and Tailwind CSS. Includes the health dashboard, scan submission form, and raw evidence viewer table. |
| **Backend API** | FastAPI control-plane exposing `/v1/scans` routes, structured logs, and CORS configurations. |
| **Services** | `AdmissionService` (DNS resolution & SSRF IP blocking), `CrawlerService` (bounded same-domain BFS, robots, rate limits, redirect validation), `TechnologyDetectionService` (JSON-driven deterministic signatures and Evidence Agent gating), and the compatibility `HTTPCollectorService`. |
| **Database** | PostgreSQL mapping scans, websites, pages, responses, headers, resources, observations, and Phase 3 `page_links` using SQLAlchemy and Alembic. |

*(Note: Redis is provisioned for future task-queue phases but is not yet actively used for asynchronous execution. Phase 3 crawling is synchronous and static-HTML only; JavaScript rendering and AI analysis are slated for later phases.)*

## Local startup

1. Copy the root environment template: `cp config/local.env.example .env`.
2. Start the complete local stack: `docker compose up --build`.
3. Open `http://localhost:3000` for the frontend and `http://localhost:8000/docs` for FastAPI documentation.

The frontend shows the backend health state. **Start a New Scan** accepts a public URL plus optional max-depth and max-page settings. The server always applies hard safety ceilings, robots.txt rules, hostname-only crawling, per-request delay, concurrency limits, and SSRF checks on every discovered URL and redirect hop.

## Database migrations

The backend includes Alembic migrations for the schema. With the Docker services running, use:

```bash
docker compose exec backend alembic upgrade head
```

## Environment configuration

`config/local.env.example` supplies Compose defaults and documents every local setting. Do not commit real `.env` files or secrets. The frontend requires `NEXT_PUBLIC_API_BASE_URL`; the backend requires `DATABASE_URL`, `CORS_ORIGINS`, `LOG_LEVEL`, `APP_ENV`, and `JWT_SECRET`. Backend crawl defaults and hard caps are defined in `backend/app/core/config.py`.

## Verification commands

| Component | Command |
|---|---|
| Frontend types | `cd frontend && pnpm install && pnpm typecheck` |
| Frontend lint | `cd frontend && pnpm lint` |
| Backend lint | `cd backend && pip install -r requirements.txt -r requirements-dev.txt && ruff check app tests alembic` |
| Backend tests | `cd backend && pytest -q` |
| Full stack | `docker compose up --build` |

## Project conventions

The primary development boundary is `frontend/` and `backend/`. The Phase 0 baseline in `docs/phase-0-architecture-baseline.md` governs the evidence model, security boundaries, and later worker architecture.

## Phase 3 API

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/v1/scans` | Admit a URL and run a bounded crawl. Optional JSON fields are `max_depth` and `max_pages`. |
| `GET` | `/v1/scans/{id}` | Return scan state, requested URL, and effective crawl limits. |
| `GET` | `/v1/scans/{id}/evidence` | Return observed evidence accumulated across crawled pages. |
| `GET` | `/v1/scans/{id}/pages` | Return page URL, depth, HTTP status, title, and discovery source for the site map. |
| `GET` | `/v1/scans/{id}/technologies` | Return inferred technologies, confidence bands, ruleset version, and non-empty supporting evidence. |

Example request:

```bash
curl -X POST http://localhost:8000/v1/scans \\
  -H 'Content-Type: application/json' \\
  -d '{"url":"https://example.com","authorization_acknowledged":true,"max_depth":2,"max_pages":30}'
```

The acceptance tests start an isolated local HTTP site and verify same-domain exclusion, robots disallow handling, crawl-time SSRF blocking, URL deduplication, depth and page ceilings, concurrency limits, resource persistence, and page-link persistence. Phase 4 tests use a deterministic known-stack fixture to verify Next.js, React, Bootstrap, WordPress, analytics, CDN, integration, and authentication detections; repeatable confidence; extensible JSON rules; and rejection of findings without evidence. Real public targets must be authorized or publicly analyzable under applicable terms. Apply migrations through `0004_phase4_technology` with `docker compose exec backend alembic upgrade head` before creating scans against a fresh database.

## Phase 4 Technology DNA

Technology signatures are stored in `backend/app/data/technology_signatures.json`. Each rule declares its ID, technology, category, signal type, regular-expression pattern, weight, and evidence field. The engine consumes only stored response bodies, headers, resources, inline scripts, meta values, comments, and cookie names; it never makes new technology-specific requests and never executes JavaScript.

Confidence is transparent: each unique matched rule contributes its declared weight, and each additional independent rule contributes a small five-point corroboration bonus. The result is capped at 100 and mapped to `low`, `medium`, or `high`. Every persisted `Technology` row has classification `inferred`, a ruleset version, and one or more `TechnologyEvidence` rows. The Evidence Agent rejects candidates with missing or incomplete evidence before persistence. Detection observations are also included in the scan evidence feed with classification `INFERRED`.
