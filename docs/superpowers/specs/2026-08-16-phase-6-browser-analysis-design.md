# Web Autopsy Network — Phase 6 (Browser Analysis) Design Specification

**Phase:** Phase 6 (Browser Analysis)  
**Status:** Design Approved — Pending Spec Review & Implementation Plan  
**Target Date:** 2026-08-16  

---

## 1. Executive Summary

Phase 6 introduces controlled headless browser automation into the Web Autopsy Network platform using Playwright.

While Phases 2–3 collect static HTML evidence and Phases 4–5 analyze technology fingerprints, site structure, and API dependencies statically, modern web applications rely heavily on client-side JavaScript rendering, dynamic DOM manipulation, dynamic API fetches, and third-party script loading.

Phase 6 adds a new 🟢 **OBSERVED** evidence stream:
1. **Fully Rendered DOM HTML** (`rendered_body` in `HTTPResponse`).
2. **Runtime Network Request Capture** (`Resource` rows tagged `capture_source="browser_runtime"`).
3. **Browser Performance Timing** (`timing_data` in `HTTPResponse` covering Navigation & Resource Timing APIs).
4. **Console Warning & Error Logs** (`Observation` rows under category `BROWSER_CONSOLE`).

---

## 2. Architecture & Service Isolation

```
                   +------------------------+
                   |  Next.js Frontend      |
                   +-----------+------------+
                               | REST API
                               v
                   +------------------------+
                   |  FastAPI Backend       |
                   +----+---------------+---+
                        |               |
         PostgreSQL DB  |               | HTTP (Internal Docker Network)
                        v               v
                   +----+---+      +----+------------------+
                   | DB     |      | browser-worker        |
                   | Tables |      | (Playwright Python)   |
                   +--------+      +-----------------------+
```

### Component Boundaries & Docker Deployment
- **`browser-worker` Service**: Located in `browser_worker/` (root-level monorepo directory). Built using `mcr.microsoft.com/playwright/python:v1.50.0-noble`.
- **FastAPI HTTP Endpoint in Worker**: Listens on internal port `8001`. Exposes `POST /render` for rendering pages and returning captured DOM, network calls, timings, and console logs.
- **Backend Client (`BrowserWorkerClient`)**: Located in `backend/app/services/browser_client.py`. Communicates with `http://browser-worker:8001/render` with fallback for graceful degradation.

---

## 3. Sub-Resource SSRF Protection & Security Boundaries

Playwright executes client-side JavaScript that can trigger sub-resource downloads, redirects, fetch/XHR calls, and iframe navigation. To prevent SSRF attacks against internal services, cloud metadata endpoints (`169.254.169.254`), or private IP ranges:

1. **Request Interception (`page.route("**/*", intercept_request)`)**:
   - Intercepts **every outbound request** issued during navigation and rendering.
   - Parses the target URL and resolves its hostname IP using `socket.getaddrinfo`.
   - Validates the target IP against `AdmissionService` rules:
     - **Blocked**: Private IPv4/IPv6 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.169.254`, `0.0.0.0`, `::1`).
     - **Blocked Protocols**: Anything other than `http` or `https` (e.g. `file://`, `gopher://`, `ftp://`).
   - If a request is blocked, `route.abort("blockedbyclient")` is called immediately, and a `BROWSER_SECURITY` observation is recorded.

2. **Browser Context Isolation**:
   - Ephemeral incognito context (`browser.new_context()`) per page.
   - Permissions: All denied (`permissions=[]`).
   - Downloads: Disabled (`accept_downloads=False`).
   - Dialogs: Auto-dismissed (`page.on("dialog", lambda dialog: dialog.dismiss())`).
   - Hard execution limits: 15s page navigation timeout, 20s hard per-page execution ceiling (`asyncio.wait_for`).

---

## 4. Data Model Extensions & Alembic Migration (`0006_phase6_browser_analysis`)

### `HTTPResponse` Table Extensions
- `rendered_body`: `Text` (nullable) — holds post-JS rendered DOM HTML.
- `timing_data`: `JSON` (nullable) — holds Navigation & Resource Timing API metrics.

### `Resource` Table Extensions
- `capture_source`: `String(50)` (default `"static_http"`, set to `"browser_runtime"` for dynamic requests captured during rendering).

---

## 5. REST API & Frontend Integration

### REST Endpoints
- `GET /scans/{id}/pages/{page_id}/rendered`: Returns rendered DOM HTML, raw HTML, browser timing metrics, and console log observations.
- Updated `GET /scans/{id}/pages` & `GET /scans/{id}/evidence` to include browser-sourced flags and categories.

### Frontend UI Extensions
- **Page Details Inspector**: Added tabs to compare Raw HTML vs. Rendered DOM HTML.
- **Runtime Network Activity Table**: Displays dynamic requests with `static_http` vs `browser_runtime` badges.
- **Console Log Viewer**: Displays browser console errors and warnings.

---

## 6. Verification Plan

1. **Unit & Integration Tests**:
   - Test `BrowserWorkerClient` rendering and JSON payload parsing.
   - Test sub-resource SSRF request interception (verify `127.0.0.1`, `169.254.169.254`, and private IPs are aborted).
   - Test execution timeout and graceful degradation fallback.
   - Test REST endpoint `GET /scans/{id}/pages/{page_id}/rendered`.
2. **End-to-End Verification**:
   - Run `pytest -v` across all backend test suites.
