# Local Verification — Phase 11–13

No push has been performed. The working tree remains uncommitted so the user can review locally first.

## Runtime status

Docker is not installed in the sandbox, so the local check used the documented direct-service fallback: FastAPI on `http://localhost:8000`, Next.js on `http://localhost:3000`, SQLite at `/tmp/web-autopsy-phase13.db`, and `QUEUE_MODE=inline`. Production Compose remains configured for PostgreSQL, Redis, Celery, the isolated browser worker, and four worker pools.

## Checks completed

| Check | Result |
|---|---:|
| `GET /health` | HTTP 200; database connected |
| `GET /v1/workers/health` | HTTP 200; crawl, browser, analysis, and AI pools reported |
| `GET /v1/scans/{id}/progress` | Returned persisted scan state, percentage, task list, dependencies, attempts, and events |
| `GET /v1/scans/{id}/progress/stream` | Returned `event: progress` SSE snapshots |
| `POST /v1/scans` | Returned HTTP 202 immediately with `state: QUEUED` |
| `POST /v1/scans/{id}/cancel` | Returned cancellation state and stopped pending work; a safe loopback URL was used so no public target was contacted |
| Completed Phase 11–12 overview | Rendered with History/Time Machine and Cause of Death sections |
| Cause of Death API | Selected `diagnosis:large_js_payload` as primary at 87.25 score and 96% overall confidence in the seeded fixture |
| Backend regression suite | 44 passed |
| Frontend typecheck | Passed |
| Frontend lint | Passed |

## Reproduce locally

From the repository root, the production path is:

```bash
docker compose up --build
```

Then open `http://localhost:3000`. A completed scan report is available at `/scans/{id}` after submitting an authorized/publicly analyzable URL. For a Docker-free local demo, use:

```bash
rm -f /tmp/web-autopsy-phase13.db
cd backend
DATABASE_URL=sqlite:////tmp/web-autopsy-phase13.db QUEUE_MODE=inline PYTHONPATH=. python3 seed_phase13_demo.py
DATABASE_URL=sqlite:////tmp/web-autopsy-phase13.db QUEUE_MODE=inline CORS_ORIGINS=http://localhost:3000 PYTHONPATH=. uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In a second terminal, start the frontend with `cd frontend && npm run dev`, then open the seeded scan ID printed by `seed_phase13_demo.py`. The live panel shows task dependencies, queue names, statuses, retries, progress, SSE updates, and cancellation.

## Important safety check

The immediate queue test used `http://127.0.0.1:1`. The request was accepted into the queue, then the worker’s existing SSRF admission layer rejected the non-public address. This confirms that asynchronous execution did not bypass the prior SSRF safeguard.
