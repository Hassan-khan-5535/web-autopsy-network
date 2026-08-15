# Web Autopsy Network

Web Autopsy Network is an evidence-backed web intelligence platform for **authorized public websites**. This repository contains **Phase 1: Project Foundation** only. It deliberately excludes crawling, scanning, technology detection, browser automation, AI analysis, and reporting logic.

## Foundation architecture

| Directory | Purpose |
|---|---|
| `frontend/` | Next.js, TypeScript, and Tailwind CSS application shell. |
| `backend/` | FastAPI control-plane foundation with settings, structured logs, health checks, migration setup, and auth dependency scaffolding. |
| `docs/` | Phase 0 architecture baseline and project design records. |
| `.github/workflows/` | Clean-clone CI checks for frontend and backend. |

The frontend calls `GET /health` through `NEXT_PUBLIC_API_BASE_URL`. The backend checks PostgreSQL connectivity during that request. Redis is provisioned for future task-queue phases but is not used by Phase 1.

## Local startup

1. Copy the root environment template: `cp config/local.env.example .env`.
2. Start the complete local stack: `docker compose up --build`.
3. Open `http://localhost:3000` for the frontend and `http://localhost:8000/docs` for FastAPI documentation.

The frontend should show the backend health state. The backend health endpoint is available at `http://localhost:8000/health`.

## Database migrations

The backend includes an Alembic baseline migration with no domain tables. With the Docker services running, use:

```bash
docker compose exec backend alembic upgrade head
docker compose exec backend alembic current
```

Future phases will add domain tables through new migrations; no website, scan, evidence, or report tables are introduced at this phase.

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

The primary development boundary is `frontend/` and `backend/`. The existing managed-preview application folders are not the future product architecture and should not be used for Phase 2 onward. The Phase 0 baseline in `docs/phase-0-architecture-baseline.md` governs the evidence model, security boundaries, and later worker architecture.
