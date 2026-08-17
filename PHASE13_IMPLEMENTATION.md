# Phase 13 — Distributed Scaling

## Architecture decision

Phase 13 selects **Celery with Redis as the broker and result transport**. The existing Compose stack already provisions Redis, the workload is a bounded web-crawl pipeline with moderate task fan-out, and Celery provides explicit task routing, late acknowledgements, worker-lost rejection, retry controls, and independently scalable queues without introducing Kafka’s operational overhead. Kafka remains unjustified for this single-application workload because the platform does not currently require long-lived event replay, multi-consumer stream analytics, or very high sustained throughput.

A lighter local alternative remains available through `QUEUE_MODE=inline`. It uses a non-blocking thread dispatcher for development and tests when Redis is unavailable, while retaining the same persisted task graph, idempotency key, progress APIs, cancellation checks, and worker execution code. Compose uses `QUEUE_MODE=celery` and four independently scalable worker pools.

| Queue | Resource profile | Tasks | Compose worker |
|---|---|---|---|
| `crawl` | I/O-bound | Admission and bounded HTTP crawl | `worker-crawl` |
| `browser` | Isolated browser boundary | Per-page browser analysis through the existing `browser-worker` service | `worker-browser` |
| `analysis` | Deterministic CPU/data processing | Technology, structure, API, network, security, performance, accessibility, content, diagnosis | `worker-analysis` |
| `ai` | Rate/cost/latency constrained | AI synthesis and evidence-gated narrative work | `worker-ai` |

## Task dependency graph

```text
admission
   ↓
collection
   ├── browser_analysis:<page_id> ──┐
   ├── technology                    │
   ├── structure                     │
   ├── api_intelligence              │
   ├── network_intelligence          ├── diagnosis ──→ synthesis
   ├── security                      │
   ├── content                       │
   ├── performance ← browser tasks ─┘
   └── accessibility ← browser tasks
```

The coordinator persists dependency keys on every `AgentTask` and dispatches only when all declared dependencies are terminal. A permanently failed upstream task does not block the graph forever; downstream work can proceed against whatever persisted evidence is available, and the scan is finalized as `PARTIAL_FAILED` if any task remains failed.

## Persisted state and operational safeguards

`AgentTask` stores queue, task type, status, attempt count, retry budget, dependency keys, progress, timestamps, heartbeat, error, and result. A unique `(scan_id, task_key)` constraint makes task creation idempotent. `AgentEvent` stores the task lifecycle stream used by progress APIs and diagnostics. Scan-level cancellation state, queue timestamp, and finish timestamp are persisted on `Scan`.

The task runner uses late acknowledgement semantics in Celery, one-task prefetching, explicit retry budgets, exponential-ish bounded backoff, and idempotent terminal short-circuiting. Stale `RUNNING` or `DISPATCHED` tasks are detected through heartbeat age and returned to `RETRYING` or marked failed when the retry budget is exhausted. Scan-level wall-clock expiry marks remaining work with a clear partial-failure state instead of allowing an orphaned scan to hang.

System-wide backpressure is enforced by `MAX_CONCURRENT_SCANS` and queue admission order. New scans are accepted immediately as `QUEUED`; they are not rejected when capacity is full. Progress reports queue position and a transparent wait estimate. Cancellation marks the scan, cancels not-yet-started tasks, and causes in-flight task boundaries and downstream scheduling to stop.

Existing SSRF admission, same-domain crawl, depth/page/concurrency, rate-delay, browser isolation, per-page browser timeout, and evidence-gate safeguards remain inside the same service classes and are now invoked from worker tasks rather than directly from the request handler. The request handler performs only acknowledgement and lightweight URL-shape validation; full admission and SSRF checks remain the first distributed task.

## API additions

| Endpoint | Purpose |
|---|---|
| `POST /v1/scans` | Returns immediately with a `QUEUED` scan and persisted admission/collection tasks. |
| `GET /v1/scans/{id}/progress` | Returns current state, percentage, queue position, task statuses, retries, errors, and recent events. |
| `GET /v1/scans/{id}/progress/stream` | Server-Sent Events stream emitting persisted progress snapshots until terminal state. |
| `POST /v1/scans/{id}/cancel` | Requests cancellation, cancels queued work, and prevents downstream dispatch. |
| `GET /v1/workers/health` | Reports per-pool active task counts and heartbeat freshness. |

## Frontend

Queued and in-flight scan reports now show a live checklist-style panel with task labels, queue names, status badges, progress percentage, retry attempt counts, queue position, estimated wait, persisted state summary, an SSE connection, and a cancel control. Completed scans continue to render the Phase 11 History panel and Phase 12 Cause of Death card unchanged.

## Verification

| Check | Result |
|---|---:|
| Existing Phase 1–12 backend tests | Passed |
| Phase 13 task graph and API acceptance tests | Passed |
| Full backend suite | **44 passed** |
| Backend compilation | Passed |
| Frontend TypeScript typecheck | Passed |
| Frontend ESLint | Passed |
| Celery app import and queue-route smoke test | Passed |
| 6-scan graph isolation test | Passed |
| Idempotent task creation test | Passed |
| Cancellation propagation test | Passed |
| Stale-worker retry recovery test | Passed |
| Live progress and SSE browser verification | Passed |

## Local live demo

Docker is unavailable in the current sandbox, so live verification used the direct FastAPI service with `QUEUE_MODE=inline` against a seeded SQLite database. The seeded scan shows 13 persisted tasks, 3 terminal tasks, a running Technology DNA task, a dispatched Structure task, downstream analysis tasks waiting on dependencies, a 27% progress bar, queue labels, retry counters, and the cancel control. The production Compose path uses Redis and the four Celery worker pools described above.
