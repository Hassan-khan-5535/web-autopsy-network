# Web Autopsy Network

Web Autopsy Network is an evidence-backed web intelligence platform for **authorized public websites**. 

This repository currently includes **Phase 1 (Project Foundation)** and **Phase 2 (URL Admission & HTTP Collector)**. It is capable of safely admitting target URLs (with strict SSRF protections), fetching passive HTTP-level evidence, extracting structural HTML facts, and presenting the raw evidence in a React frontend.

## Architecture & Features

| Component | Purpose |
|---|---|
| **Frontend** | Next.js, TypeScript, and Tailwind CSS. Includes the health dashboard, scan submission form, and raw evidence viewer table. |
| **Backend API** | FastAPI control-plane exposing `/v1/scans` routes, structured logs, and CORS configurations. |
| **Services** | `AdmissionService` (DNS resolution & SSRF IP blocking) and `HTTPCollectorService` (synchronous fetch, redirect loop handling, DOM parsing). |
| **Database** | PostgreSQL mapping the `Scan`, `Website`, `Page`, `HTTPResponse`, `Header`, `Resource`, and `Observation` tables using SQLAlchemy and Alembic. |

*(Note: Redis is provisioned for future task-queue phases but is not yet actively used for asynchronous execution. Crawling, AI analysis, and advanced reporting are slated for future phases.)*

## Local startup

1. Copy the root environment template: `cp config/local.env.example .env`.
2. Start the complete local stack: `docker compose up --build`.
3. Open `http://localhost:3000` for the frontend and `http://localhost:8000/docs` for FastAPI documentation.

The frontend should show the backend health state. You can click **Start a New Scan** to submit a URL for evidence collection.

## Database migrations

The backend includes Alembic migrations for the schema. With the Docker services running, use:

```bash
docker compose exec backend alembic upgrade head
```

## Environment configuration

`config/local.env.example` supplies Compose defaults and documents every local setting. Do not commit real `.env` files or secrets. The frontend requires `NEXT_PUBLIC_API_BASE_URL`; the backend requires `DATABASE_URL`, `CORS_ORIGINS`, `LOG_LEVEL`, `APP_ENV`, and `JWT_SECRET`.

## Verification commands

| Component | Command |
|---|---|
| Frontend types | `cd frontend && pnpm install && pnpm typecheck` |
| Frontend lint | `cd frontend && pnpm lint` |
| Backend lint | `cd backend && pip install -r requirements.txt -r requirements-dev.txt && ruff check app tests` |
| Backend tests | `cd backend && pytest` |
| Full stack | `docker compose up --build` |

## Project conventions

The primary development boundary is `frontend/` and `backend/`. The Phase 0 baseline in `docs/phase-0-architecture-baseline.md` governs the evidence model, security boundaries, and later worker architecture.
