# Web Autopsy Network — Phase 6 (Browser Analysis) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate a sandboxed Playwright browser worker to capture fully rendered DOM HTML, runtime network requests, browser performance timing, and console logs while enforcing strict sub-resource SSRF request interception and graceful degradation.

**Architecture:** A dedicated `browser-worker` microservice (Python + FastAPI + Playwright) runs in its own Docker container on port `8001`. The backend `CrawlerService` invokes `BrowserWorkerClient.render_page()`, storing post-JS rendered DOM in `HTTPResponse.rendered_body`, timing metrics in `HTTPResponse.timing_data`, and runtime network events in `Resource` (tagged `capture_source="browser_runtime"`). Sub-resource requests to private IPs, localhost, or cloud metadata endpoints are aborted at runtime via Playwright request interception.

**Tech Stack:** Python 3.12, FastAPI, Playwright (Chromium), SQLAlchemy, Alembic, PostgreSQL, Next.js 15, TypeScript, Tailwind CSS, Docker Compose.

**Spec:** [`docs/superpowers/specs/2026-08-16-phase-6-browser-analysis-design.md`](file:///e:/web%20project/web-autopsy-network/docs/superpowers/specs/2026-08-16-phase-6-browser-analysis-design.md)

## Global Constraints

- Every outbound request issued by the browser must be intercepted and validated against `AdmissionService` SSRF rules (blocking private IPs, localhost, `169.254.169.254`, and non-HTTP/HTTPS protocols).
- Hard navigation timeout of 15s and overall per-page execution ceiling of 20s.
- Browser rendering failures must degrade gracefully without failing the overall scan.
- No AI or performance scoring in Phase 6 — only 🟢 **OBSERVED** evidence collection.

---

### Task 1: Database Schema Models & Alembic Migration `0006`

**Files:**
- Modify: `backend/app/models/scan.py:117-155`
- Create: `backend/alembic/versions/0006_phase6_browser_analysis.py`
- Test: `backend/tests/test_models_phase6.py`

**Interfaces:**
- Consumes: SQLAlchemy `Base`, `HTTPResponse`, `Resource` models.
- Produces: `HTTPResponse.rendered_body`, `HTTPResponse.timing_data`, `Resource.capture_source` fields in ORM and PostgreSQL schema.

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/test_models_phase6.py
import pytest
from sqlalchemy.orm import Session
from app.models.scan import Website, Scan, Page, HTTPResponse, Resource

def test_phase6_model_fields(db: Session):
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.commit()

    scan = Scan(website_id=website.id, requested_url="https://example.com", state="COMPLETED")
    db.add(scan)
    db.commit()

    page = Page(scan_id=scan.id, canonical_url="https://example.com/", depth=0)
    db.add(page)
    db.commit()

    response = HTTPResponse(
        page_id=page.id,
        status_code=200,
        final_url="https://example.com/",
        raw_body="<html>Static</html>",
        rendered_body="<html>Rendered DOM</html>",
        timing_data={"navigation": {"domComplete": 450}}
    )
    db.add(response)
    db.commit()

    resource = Resource(
        page_id=page.id,
        url="https://example.com/api/data",
        resource_type="fetch",
        capture_source="browser_runtime"
    )
    db.add(resource)
    db.commit()

    saved_resp = db.query(HTTPResponse).filter(HTTPResponse.id == response.id).first()
    assert saved_resp.rendered_body == "<html>Rendered DOM</html>"
    assert saved_resp.timing_data == {"navigation": {"domComplete": 450}}

    saved_res = db.query(Resource).filter(Resource.id == resource.id).first()
    assert saved_res.capture_source == "browser_runtime"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models_phase6.py -v`  
Expected: FAIL with AttributeError or TypeError for unknown fields `rendered_body`, `timing_data`, `capture_source`.

- [ ] **Step 3: Update SQLAlchemy models and write Alembic migration**

Update `backend/app/models/scan.py`:
```python
class HTTPResponse(Base):
    __tablename__ = "http_responses"
    ...
    rendered_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    timing_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

class Resource(Base):
    __tablename__ = "resources"
    ...
    capture_source: Mapped[str] = mapped_column(String(50), default="static_http", server_default="static_http", index=True)
```

Create `backend/alembic/versions/0006_phase6_browser_analysis.py`:
```python
"""phase 6 browser analysis

Revision ID: 0006_phase6_browser_analysis
Revises: 0005_phase5_structure_deps
Create Date: 2026-08-16 18:00:00
"""
from alembic import op
import sqlalchemy as sa

revision = "0006_phase6_browser_analysis"
down_revision = "0005_phase5_structure_deps"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.add_column("http_responses", sa.Column("rendered_body", sa.Text(), nullable=True))
    op.add_column("http_responses", sa.Column("timing_data", sa.JSON(), nullable=True))
    op.add_column("resources", sa.Column("capture_source", sa.String(length=50), nullable=False, server_default="static_http"))
    op.create_index(op.f("ix_resources_capture_source"), "resources", ["capture_source"], unique=False)

def downgrade() -> None:
    op.drop_index(op.f("ix_resources_capture_source"), table_name="resources")
    op.drop_column("resources", "capture_source")
    op.drop_column("http_responses", "timing_data")
    op.drop_column("http_responses", "rendered_body")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_models_phase6.py -v`  
Expected: PASS.

- [ ] **Step 5: Verify Alembic migration syntax**

Run: `pytest -v`  
Expected: 16 passing tests.

---

### Task 2: Playwright `browser_worker/` Microservice Scaffolding

**Files:**
- Create: `browser_worker/requirements.txt`
- Create: `browser_worker/Dockerfile`
- Create: `browser_worker/app.py`
- Test: `backend/tests/test_browser_worker_api.py`

**Interfaces:**
- Consumes: HTTP `POST /render` request payload `{ "url": str, "timeout_ms": int }`.
- Produces: JSON response with `status`, `final_url`, `status_code`, `rendered_html`, `network_requests`, `timing_data`, `console_logs`, `error`.

- [ ] **Step 1: Create `browser_worker/requirements.txt`**

```txt
fastapi[standard]==0.115.12
playwright==1.50.0
pydantic==2.10.6
uvicorn[standard]==0.34.0
```

- [ ] **Step 2: Create `browser_worker/Dockerfile`**

```dockerfile
FROM mcr.microsoft.com/playwright/python:v1.50.0-noble

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8001

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001"]
```

- [ ] **Step 3: Create `browser_worker/app.py`**

```python
import asyncio
import socket
from typing import Any
from urllib.parse import urlsplit
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="Web Autopsy Browser Worker", version="0.6.0")

class RenderRequest(BaseModel):
    url: str
    timeout_ms: int = Field(default=20000, ge=1000, le=60000)

class NetworkRequestItem(BaseModel):
    url: str
    method: str
    resource_type: str
    status_code: int | None = None
    timing_ms: float | None = None
    capture_source: str = "browser_runtime"

class RenderResponse(BaseModel):
    status: str
    final_url: str | None = None
    status_code: int | None = None
    rendered_html: str | None = None
    network_requests: list[NetworkRequestItem] = []
    timing_data: dict[str, Any] | None = None
    console_logs: list[dict[str, str]] = []
    error: str | None = None

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "browser-worker"}
```

- [ ] **Step 4: Write test verifying `/health` endpoint**

Write `backend/tests/test_browser_worker_api.py`:
```python
import pytest

def test_browser_worker_module_imports():
    from browser_worker.app import app
    assert app.title == "Web Autopsy Browser Worker"
```

- [ ] **Step 5: Verify tests pass**

Run: `pytest tests/test_browser_worker_api.py -v`  
Expected: PASS.

---

### Task 3: Sub-Resource SSRF Request Interceptor in Browser Worker

**Files:**
- Modify: `browser_worker/app.py`
- Test: `backend/tests/test_browser_ssrf.py`

**Interfaces:**
- Consumes: Playwright `page.route("**/*", intercept_request)` callback.
- Produces: Immediate `route.abort("blockedbyclient")` for forbidden private/loopback/metadata IP targets; `route.continue_()` for allowed targets.

- [ ] **Step 1: Write failing test for SSRF request interception**

Write `backend/tests/test_browser_ssrf.py`:
```python
import pytest
from browser_worker.app import is_private_ip, is_url_allowed

def test_ssrf_ip_checks():
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("10.0.1.5") is True
    assert is_private_ip("169.254.169.254") is True
    assert is_private_ip("8.8.8.8") is False

def test_url_ssrf_admission():
    assert is_url_allowed("http://127.0.0.1/admin") is False
    assert is_url_allowed("http://169.254.169.254/latest/meta-data") is False
    assert is_url_allowed("file:///etc/passwd") is False
    assert is_url_allowed("https://example.com/logo.png") is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_browser_ssrf.py -v`  
Expected: FAIL (functions not implemented).

- [ ] **Step 3: Implement SSRF validation functions in `browser_worker/app.py`**

```python
import ipaddress
import socket
from urllib.parse import urlsplit

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return True

def is_url_allowed(url: str) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if is_private_ip(ip_str):
                return False
        return True
    except socket.gaierror:
        return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_browser_ssrf.py -v`  
Expected: PASS.

---

### Task 4: Complete Playwright Render Engine Implementation

**Files:**
- Modify: `browser_worker/app.py`
- Test: `backend/tests/test_browser_render.py`

**Interfaces:**
- Consumes: `POST /render` with target URL and timeout.
- Produces: Rendered DOM HTML, captured network calls, performance timing JSON, and console log list.

- [ ] **Step 1: Write test for rendering engine logic**

Write `backend/tests/test_browser_render.py`:
```python
import pytest
from browser_worker.app import RenderRequest, RenderResponse

def test_render_response_structure():
    res = RenderResponse(
        status="success",
        final_url="https://example.com/",
        status_code=200,
        rendered_html="<html><body><h1>Hello</h1></body></html>"
    )
    assert res.status == "success"
    assert res.rendered_html is not None
```

- [ ] **Step 2: Implement full `/render` route handler in `browser_worker/app.py`**

```python
from playwright.async_api import async_playwright

@app.post("/render", response_model=RenderResponse)
async def render_page(req: RenderRequest):
    if not is_url_allowed(req.url):
        return RenderResponse(
            status="failed",
            error=f"SSRF Check blocked target URL: {req.url}"
        )

    captured_requests = []
    console_logs = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            accept_downloads=False,
            permissions=[],
            ignore_https_errors=False
        )

        page = await context.new_page()
        page.on("dialog", lambda d: asyncio.create_task(d.dismiss()))
        page.on("console", lambda msg: console_logs.append({"type": msg.type, "text": msg.text}))

        async def route_interceptor(route, request):
            if not is_url_allowed(request.url):
                await route.abort("blockedbyclient")
            else:
                captured_requests.append({
                    "url": request.url,
                    "method": request.method,
                    "resource_type": request.resource_type,
                })
                await route.continue_()

        await page.route("**/*", route_interceptor)

        try:
            response = await page.goto(req.url, timeout=15000, wait_until="domcontentloaded")
            await asyncio.sleep(1.5)  # Allow JS execution & dynamic fetch calls to resolve

            rendered_html = await page.content()
            final_url = page.url
            status_code = response.status if response else 200

            timing_json = await page.evaluate("""() => {
                const nav = performance.getEntriesByType('navigation')[0] || {};
                return {
                    domInteractive: nav.domInteractive || 0,
                    domComplete: nav.domComplete || 0,
                    loadEventEnd: nav.loadEventEnd || 0
                };
            }""")

            await browser.close()

            return RenderResponse(
                status="success",
                final_url=final_url,
                status_code=status_code,
                rendered_html=rendered_html,
                network_requests=[
                    NetworkRequestItem(
                        url=item["url"],
                        method=item["method"],
                        resource_type=item["resource_type"],
                        status_code=200
                    ) for item in captured_requests
                ],
                timing_data={"navigation": timing_json},
                console_logs=console_logs
            )
        except Exception as exc:
            await browser.close()
            return RenderResponse(
                status="failed",
                error=f"Browser execution failed: {str(exc)}"
            )
```

- [ ] **Step 3: Run test to verify pass**

Run: `pytest tests/test_browser_render.py -v`  
Expected: PASS.

---

### Task 5: Docker Compose Integration

**Files:**
- Modify: `docker-compose.yml:30-55`
- Modify: `config/local.env.example`
- Modify: `backend/app/core/config.py`

**Interfaces:**
- Consumes: Environment variable `BROWSER_WORKER_URL=http://browser-worker:8001`.
- Produces: Running `browser-worker` container in Docker Compose network.

- [ ] **Step 1: Update `docker-compose.yml` to include `browser-worker`**

```yaml
  browser-worker:
    build:
      context: ./browser_worker
      dockerfile: Dockerfile
    ports:
      - "${BROWSER_WORKER_PORT:-8001}:8001"
    restart: unless-stopped
```

- [ ] **Step 2: Update `backend/app/core/config.py`**

```python
class Settings(BaseSettings):
    ...
    browser_worker_url: str = "http://browser-worker:8001"
```

- [ ] **Step 3: Verify backend config imports `browser_worker_url`**

Run: `pytest -v`  
Expected: PASS.

---

### Task 6: Backend Browser Client & Pipeline Integration

**Files:**
- Create: `backend/app/services/browser_client.py`
- Modify: `backend/app/services/crawler.py`
- Test: `backend/tests/test_browser_integration.py`

**Interfaces:**
- Consumes: `HTTPResponse` static record from crawler.
- Produces: Updated `HTTPResponse.rendered_body`, `HTTPResponse.timing_data`, dynamic `Resource` rows, and `BROWSER_CONSOLE` observations in DB.

- [ ] **Step 1: Write failing integration test**

Write `backend/tests/test_browser_integration.py`:
```python
import pytest
from unittest.mock import MagicMock, patch
from sqlalchemy.orm import Session
from app.models.scan import Website, Scan, Page, HTTPResponse, Resource
from app.services.browser_client import BrowserWorkerClient

def test_browser_client_updates_page_response(db: Session):
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.commit()

    scan = Scan(website_id=website.id, requested_url="https://example.com", state="COLLECTING")
    db.add(scan)
    db.commit()

    page = Page(scan_id=scan.id, canonical_url="https://example.com/", depth=0)
    db.add(page)
    db.commit()

    resp = HTTPResponse(page_id=page.id, status_code=200, final_url="https://example.com/", raw_body="<html>Static</html>")
    db.add(resp)
    db.commit()

    mock_render = {
        "status": "success",
        "final_url": "https://example.com/",
        "status_code": 200,
        "rendered_html": "<html><body><h1>Rendered JS</h1></body></html>",
        "network_requests": [
            {"url": "https://example.com/api/dynamic", "method": "GET", "resource_type": "fetch", "status_code": 200, "capture_source": "browser_runtime"}
        ],
        "timing_data": {"navigation": {"domComplete": 350}},
        "console_logs": [{"type": "warning", "text": "Console log test"}]
    }

    with patch("httpx.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200, json=lambda: mock_render)
        client = BrowserWorkerClient(db)
        client.analyze_page(scan.id, page.id, "https://example.com/")

    db.refresh(resp)
    assert resp.rendered_body == "<html><body><h1>Rendered JS</h1></body></html>"
    assert resp.timing_data == {"navigation": {"domComplete": 350}}

    resources = db.query(Resource).filter(Resource.page_id == page.id).all()
    assert len(resources) == 1
    assert resources[0].capture_source == "browser_runtime"
```

- [ ] **Step 2: Implement `BrowserWorkerClient` in `backend/app/services/browser_client.py`**

```python
import httpx
import logging
from uuid import UUID
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.models.scan import HTTPResponse, Resource, Observation

logger = logging.getLogger("web_autopsy.browser_client")

class BrowserWorkerClient:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.settings = get_settings()

    def analyze_page(self, scan_id: UUID, page_id: UUID, url: str) -> bool:
        try:
            response = httpx.post(
                f"{self.settings.browser_worker_url}/render",
                json={"url": url, "timeout_ms": 20000},
                timeout=25.0
            )
            if response.status_code != 200:
                logger.warning(f"Browser worker HTTP {response.status_code} for {url}")
                return False

            data = response.json()
            if data.get("status") != "success":
                logger.warning(f"Browser rendering failed: {data.get('error')}")
                obs = Observation(
                    scan_id=scan_id,
                    page_id=page_id,
                    category="BROWSER_ANALYSIS",
                    subject=url,
                    observation=f"Browser analysis failed: {data.get('error')}",
                    classification="OBSERVED"
                )
                self.db.add(obs)
                self.db.commit()
                return False

            resp = self.db.query(HTTPResponse).filter(HTTPResponse.page_id == page_id).first()
            if resp:
                resp.rendered_body = data.get("rendered_html")
                resp.timing_data = data.get("timing_data")
                self.db.commit()

            for req in data.get("network_requests", []):
                res = Resource(
                    page_id=page_id,
                    url=req["url"],
                    resource_type=req.get("resource_type", "other"),
                    capture_source="browser_runtime"
                )
                self.db.add(res)

            for log_item in data.get("console_logs", []):
                obs = Observation(
                    scan_id=scan_id,
                    page_id=page_id,
                    category="BROWSER_CONSOLE",
                    subject=log_item.get("type", "log"),
                    observation=log_item.get("text", ""),
                    classification="OBSERVED"
                )
                self.db.add(obs)

            self.db.commit()
            return True
        except Exception as exc:
            logger.warning(f"BrowserWorkerClient exception for {url}: {exc}")
            obs = Observation(
                scan_id=scan_id,
                page_id=page_id,
                category="BROWSER_ANALYSIS",
                subject=url,
                observation=f"Browser analysis degraded: {str(exc)}",
                classification="OBSERVED"
            )
            self.db.add(obs)
            self.db.commit()
            return False
```

- [ ] **Step 3: Integrate `BrowserWorkerClient` into `CrawlerService` (`backend/app/services/crawler.py`)**

After static HTTP page collection in `CrawlerService._process_page()`:
```python
BrowserWorkerClient(self.db).analyze_page(self.scan.id, page.id, fetch_res.final_url)
```

- [ ] **Step 4: Run integration test**

Run: `pytest tests/test_browser_integration.py -v`  
Expected: PASS.

---

### Task 7: REST API Extensions

**Files:**
- Modify: `backend/app/api/routes/scans.py`
- Test: `backend/tests/test_phase6_endpoints.py`

**Interfaces:**
- Consumes: Scan and page IDs.
- Produces: Endpoint `GET /scans/{id}/pages/{page_id}/rendered` returning raw vs rendered HTML, timing metrics, and console observations.

- [ ] **Step 1: Write failing REST endpoint test**

Write `backend/tests/test_phase6_endpoints.py`:
```python
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.main import app
from app.models.scan import Website, Scan, Page, HTTPResponse

client = TestClient(app)

def test_get_page_rendered_endpoint(db: Session):
    app.dependency_overrides[get_db] = lambda: db

    website = Website(canonical_origin="example.com")
    db.add(website)
    db.commit()

    scan = Scan(website_id=website.id, requested_url="https://example.com", state="COMPLETED")
    db.add(scan)
    db.commit()

    page = Page(scan_id=scan.id, canonical_url="https://example.com/", depth=0)
    db.add(page)
    db.commit()

    resp = HTTPResponse(
        page_id=page.id,
        status_code=200,
        final_url="https://example.com/",
        raw_body="<html>Static</html>",
        rendered_body="<html>Rendered</html>",
        timing_data={"navigation": {"domComplete": 250}}
    )
    db.add(resp)
    db.commit()

    res = client.get(f"/v1/scans/{scan.id}/pages/{page.id}/rendered")
    assert res.status_code == 200
    data = res.json()
    assert data["raw_body"] == "<html>Static</html>"
    assert data["rendered_body"] == "<html>Rendered</html>"
    assert data["timing_data"] == {"navigation": {"domComplete": 250}}
```

- [ ] **Step 2: Add route handler in `backend/app/api/routes/scans.py`**

```python
@router.get("/{id}/pages/{page_id}/rendered")
def get_page_rendered(id: UUID, page_id: UUID, db: Session = Depends(get_db)):
    page = db.query(Page).filter(Page.id == page_id, Page.scan_id == id).first()
    if not page:
        raise HTTPException(status_code=404, detail="Page not found for this scan.")

    resp = db.query(HTTPResponse).filter(HTTPResponse.page_id == page.id).first()
    if not resp:
        raise HTTPException(status_code=404, detail="No response recorded for page.")

    resources = db.query(Resource).filter(Resource.page_id == page.id).all()
    observations = db.query(Observation).filter(Observation.page_id == page.id).all()

    return {
        "page_id": page.id,
        "url": page.canonical_url,
        "raw_body": resp.raw_body,
        "rendered_body": resp.rendered_body,
        "timing_data": resp.timing_data,
        "resources": [
            {
                "id": r.id,
                "url": r.url,
                "resource_type": r.resource_type,
                "capture_source": r.capture_source,
            } for r in resources
        ],
        "console_logs": [
            {
                "id": o.id,
                "type": o.subject,
                "text": o.observation,
            } for o in observations if o.category == "BROWSER_CONSOLE"
        ]
    }
```

- [ ] **Step 3: Run test to verify pass**

Run: `pytest tests/test_phase6_endpoints.py -v`  
Expected: PASS.

---

### Task 8: Frontend Data Client & UI Integration

**Files:**
- Modify: `frontend/lib/api.ts`
- Modify: `frontend/app/scans/[id]/page.tsx`

**Interfaces:**
- Consumes: `getScanPageRendered(scanId, pageId)` API method.
- Produces: Rendered vs Raw HTML tab view, runtime network activity table, and browser console log inspector in the scan result view.

- [ ] **Step 1: Update `frontend/lib/api.ts`**

```typescript
export type PageRenderedResponse = {
  page_id: string;
  url: string;
  raw_body: string | null;
  rendered_body: string | null;
  timing_data: Record<string, any> | null;
  resources: Array<{
    id: string;
    url: string;
    resource_type: string;
    capture_source: string;
  }>;
  console_logs: Array<{
    id: string;
    type: string;
    text: string;
  }>;
};

export async function getScanPageRendered(
  scanId: string,
  pageId: string
): Promise<PageRenderedResponse> {
  const response = await fetch(`${apiBaseUrl}/v1/scans/${scanId}/pages/${pageId}/rendered`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch rendered DOM for page ${pageId}`);
  }

  return response.json() as Promise<PageRenderedResponse>;
}
```

- [ ] **Step 2: Update `frontend/app/scans/[id]/page.tsx` to include Rendered DOM Inspector**

Add expandable Page Detail Modal/Drawer showing:
- Tabs for "Rendered DOM HTML" vs "Raw Static HTML".
- Captured runtime network requests table (highlighting `browser_runtime` badges).
- Browser console warnings and errors feed.

- [ ] **Step 3: Verify frontend typecheck**

Run: `npm run typecheck` inside `frontend/`  
Expected: 0 errors.

---

### Task 9: Final Whole-Branch Verification

- [ ] **Step 1: Execute full backend test suite**

Run: `pytest -v` inside `backend/`  
Expected: All 18+ tests passing.

- [ ] **Step 2: Run frontend typecheck & lint**

Run: `npm run typecheck && npm run lint` inside `frontend/`  
Expected: 0 errors.
