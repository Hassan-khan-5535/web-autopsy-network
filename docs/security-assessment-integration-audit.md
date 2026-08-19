# Web Autopsy Network — Security Assessment Layer Integration Audit

## Executive assessment

Web Autopsy Network already contains the core infrastructure required for a separate security-assessment layer: a FastAPI API, SQLAlchemy persistence, a scan/task lifecycle, bounded HTTP crawling, isolated browser rendering, deterministic analysis services, evidence-bearing findings, diagnosis/prioritization, SSE plus polling progress, and a Next.js report UI. The correct extension strategy is to add security-assessment metadata and task types to these existing abstractions rather than introduce a second queue, database, scan engine, or report system.

The public scan path is target-specific. `POST /api/v1/scans` validates and stores the submitted URL, creates a fresh `Scan`, and initializes the existing task graph. The report route loads data using the current persisted scan UUID.

## Existing-system map

| Capability | Existing implementation | Reuse for the Security Assessment Layer | Compatibility note |
|---|---|---|---|
| API bootstrap | `backend/app/main.py`, `backend/app/api/router.py` | Add assessment endpoints to the existing `/api/v1` router | Preserve current route contracts and response codes |
| Scan creation | `backend/app/api/routes/scans.py:create_scan` | Extend `ScanCreate` with optional assessment profile/scope metadata | Existing fields remain valid; default behavior remains the current passive scan |
| Scan lifecycle | `Scan` model plus `TaskGraphCoordinator` | Add optional assessment mode and authorization record linked to the same scan | Do not fork scan lifecycle or create a second scan type |
| Persistence | `backend/app/models/scan.py`, SQLAlchemy, SQLite local/PostgreSQL production | Add nullable tables/columns via a backward-compatible migration | Existing rows must load with safe defaults |
| Task graph | `backend/app/services/tasks.py` with queues `crawl`, `browser`, `analysis`, and `ai` | Add deterministic assessment tasks to the existing `analysis` queue, or bounded sub-tasks under the same scan | No second queue or worker pool without a measured need |
| HTTP collection | `AdmissionService`, `CrawlerService` | Reuse stored responses, headers, HTML, resources, redirects, and page graph as assessment input | Do not duplicate network fetching when persisted evidence is sufficient |
| Browser rendering | `browser_worker/app.py`, `BrowserWorkerClient` | Reuse only for non-destructive DOM/form/cookie/navigation observations | Authenticated workflows require an explicit test-account profile and scope gate |
| Security findings | `SecurityAnalysisService`, `SecurityFinding`, evidence validator | Extend with versioned safe rules and candidate classifications | Keep `OBSERVED`, `INFERRED`, and any future `CONFIRMED_CANARY` distinct |
| Evidence | `Evidence`/observation payloads and finding evidence IDs | Store every assessment result with source URL, request class, timestamp, rule ID, and limitations | No finding without an evidence record |
| Diagnosis | `CauseOfDeathEngine`, `RiskImpactEngine` | Include assessment findings as inputs with provenance | Diagnosis remains prioritization, not a claim of compromise |
| AI helpers | `AISynthesisEngine`, `AIDoctorEngine` | Optional explanation only; deterministic rules remain authoritative | LLM is not required for detection or severity |
| Progress | `AgentTask`, `AgentEvent`, SSE stream, polling fallback | Add assessment task keys/events to existing timeline | Frontend already renders task cards and activity events |
| Frontend API | `frontend/lib/api.ts` | Add typed assessment metadata/findings to current client | Use persisted production scan IDs only |
| Frontend report | `frontend/app/scans/[id]/page.tsx` and report components | Add assessment summary, scope, authorization, rule version, and limitations sections | Existing report sections remain intact |
| Configuration | `backend/app/core/config.py`, env template, Compose | Add explicit safe-policy defaults and caps | Fail closed for active/authenticated modes when policy is absent |
| Logging | Structlog plus `AgentEvent` and request logs | Log authorization decision, scope check, action class, target URL, rate-limit result, and outcome | Never log passwords, tokens, cookies, or raw authorization headers |
| Deployment | Docker Compose services plus documented manual browser worker | Reuse existing backend/frontend/browser worker startup | Manual and Compose modes must share policy semantics |
| Tests | Backend pytest suite by phase and frontend checks | Add policy, evidence, migration, and regression tests | Existing scan tests remain unchanged and must pass |

## Current scan and report lifecycle

1. The frontend calls `createScan` with a URL, authorization acknowledgement, and bounded crawl options.
2. The backend validates the URL and hostname, applies server-side depth/page/concurrency/delay caps, finds or creates a `Website`, creates a `Scan` in `QUEUED`, and initializes the existing task graph.
3. Admission and collection persist pages, HTTP responses, headers, raw HTML, resources, links, redirects, and observations.
4. `after_collection` creates browser tasks per collected page and deterministic analysis tasks for technology, structure, API intelligence, network intelligence, security, content, performance, and accessibility.
5. Diagnosis aggregates evidence-bearing findings, then synthesis optionally creates an AI narrative or deterministic fallback.
6. The frontend polls/SSE-streams the scan progress and, after terminal state, loads all report endpoints using the scan UUID.

The new layer should insert scoped security-assessment tasks after collection and before diagnosis, or as a deterministic extension of the existing `security` task. It must not duplicate collection, browser rendering, evidence, or diagnosis infrastructure.

## Authorization and scope model to add

The existing checkbox is an acknowledgement, not a strong authorization record. The extension should add a nullable `AssessmentAuthorization` record linked to `Scan` with: authorization type, actor/tenant identifier, target allowlist decision, allowed origin/path scope, approved test mode, timestamp, expiration, policy version, and an immutable consent hash. Existing scans can remain valid with a `legacy_passive` default.

Active or authenticated assessment must fail closed unless all of the following are present: an explicit allowlisted target, an approved assessment profile, a bounded request budget, a dedicated test account reference without stored plaintext password, and a policy decision recorded before task dispatch. Python.org currently has no dedicated test account supplied, so authenticated checks must remain `NOT_CONFIGURED` rather than silently running unauthenticated or against real users.

## Safe assessment boundaries

The first production-safe extension can support passive and non-destructive candidates: security-header and cookie policy checks, CORS observations, CSRF-token surface detection without form submission, redirect-parameter candidates without following external destinations, exposed-file references without fetching sensitive paths, TLS metadata, dependency/version correlation when evidence is available, and authenticated workflow readiness checks that report missing configuration.

Injection, XSS, SSRF, command-injection, file-upload, deserialization, RCE, IDOR/BOLA, and authorization checks must use dedicated safe canaries and explicit workflow contracts. They must not use destructive payloads, persistence, credential attacks, evasion, denial of service, arbitrary uploads, or real-user accounts. A result must say `OBSERVED`, `INFERRED`, `CANARY_TRIGGERED`, or `NOT_RUN`, with evidence and limitations.

## Backward compatibility and migrations

All new database columns should be nullable or have server-side defaults. New tables should be additive. Existing `POST /api/v1/scans` requests without an assessment profile must behave exactly as today and select the legacy passive profile. Existing report endpoints must remain unchanged. New assessment endpoints should be additive, for example `GET /api/v1/scans/{scan_id}/assessment` and `GET /api/v1/scans/{scan_id}/assessment/findings`.

The frontend should only render the assessment panel when assessment metadata exists. A normal legacy scan must continue to render the existing progress and report sections without requiring new fields.

## Current implementation status

The repository already contains safe passive security checks and now includes candidate-only CSRF-surface and open-redirect-parameter rules with evidence and limitations. It also avoids missing-header false positives for failed HTTP responses. The next implementation step should be the additive authorization/policy schema and task contract, followed by guarded authenticated workflow support once a dedicated test account and exact login scope are supplied.

## Acceptance checklist

| Acceptance criterion | Audit result / next action |
|---|---|
| Existing scans continue unchanged | Supported by additive defaults; must be regression-tested after migration |
| New security scans separately identifiable | Add nullable assessment profile and authorization record |
| No duplicate infrastructure | Reuse current Scan, AgentTask, AgentEvent, evidence, queues, browser worker, and report UI |
| Deterministic detection | Keep rule engine authoritative; LLM optional |
| Full authorization and scope logging | Add immutable authorization decision and audit events |
| No secret leakage | Store references/hashes only; redact cookies, tokens, and passwords |
| Safe active testing | Canary-only, bounded, opt-in, fail-closed; no destructive exploit modules |
| Authenticated testing | Block until dedicated test account and workflow scope are configured |
| Report provenance | Show target, scope, rule version, evidence IDs, classification, and limitations |
