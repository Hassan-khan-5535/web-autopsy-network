# Phase 5 — Structure + Dependency Intelligence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the Web Autopsy Network platform with Structure Agent, API Intelligence Agent, Network Intelligence Agent, database models (`Dependency`, `ApiEndpoint`), 3 new REST endpoints, and an interactive frontend dependency graph with zoom/filter/search/inspection features.

**Architecture:** Add `Dependency` and `ApiEndpoint` SQLAlchemy models. Implement `StructureAgent` (site hierarchy tree, link metrics, form inventory, inferred page types), `ApiIntelligenceAgent` (static API path & endpoint inference), and `NetworkIntelligenceAgent` (external domain graph & category mapping using Phase 4 tech detections). Expose `/architecture`, `/dependencies`, and `/api-endpoints` REST routes. Build an interactive SVG/Canvas dependency graph and architecture views in the Next.js frontend.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy, Alembic, pytest, Next.js 15, TypeScript, Tailwind CSS.

**Spec:** `docs/superpowers/specs/2026-08-16-phase-5-structure-and-dependency-intelligence-design.md`

## Global Constraints
- Target findings taxonomy: `🟢 OBSERVED`, `🟡 INFERRED`, `🔵 AI INTERPRETATION`, `⚫ UNKNOWN`.
- No new HTTP requests issued to the target site during Phase 5 analysis (static evidence analysis only).
- Every persisted finding must link to at least one evidence item / observation.
- Frontend graph must support zoom, filter (category), search, and click-to-inspect.

---

### Task 1: Database Models & Alembic Migration for Phase 5

**Files:**
- Modify: `backend/app/models/scan.py`
- Modify: `backend/app/models/__init__.py`
- Create: `backend/alembic/versions/phase5_dependencies_endpoints.py`
- Test: `backend/tests/test_models_phase5.py`

**Interfaces:**
- Produces: `Dependency` model, `ApiEndpoint` model, `Scan.dependencies` & `Scan.api_endpoints` relationships.

- [ ] **Step 1: Write failing model test**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Add `Dependency` and `ApiEndpoint` models to `scan.py` & `__init__.py`**
- [ ] **Step 4: Create Alembic migration file for `dependencies` and `api_endpoints` tables**
- [ ] **Step 5: Run test to verify models pass**

---

### Task 2: Implement Structure Agent

**Files:**
- Create: `backend/app/services/structure.py`
- Test: `backend/tests/test_structure.py`

**Interfaces:**
- Consumes: `Scan`, `Page`, `PageLink`, `HTTPResponse`, `Observation` from database.
- Produces: `StructureAgent.analyze() -> dict` returning tree hierarchy, link metrics, form inventory, inferred page types, and creating `Observation` items.

- [ ] **Step 1: Write failing unit tests for StructureAgent**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement `StructureAgent` with page tree building, link analytics, form parsing, and page type heuristics**
- [ ] **Step 4: Run test to verify it passes**

---

### Task 3: Implement API Intelligence Agent

**Files:**
- Create: `backend/app/services/api_intelligence.py`
- Test: `backend/tests/test_api_intelligence.py`

**Interfaces:**
- Consumes: `Scan`, `Page`, `HTTPResponse`, `Resource` from database.
- Produces: `ApiIntelligenceAgent.analyze() -> list[ApiEndpoint]` saving `ApiEndpoint` & `Observation` rows.

- [ ] **Step 1: Write failing unit tests for ApiIntelligenceAgent**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement static pattern extraction for candidate API paths, HTTP methods, content-types, and confidence scoring**
- [ ] **Step 4: Run test to verify it passes**

---

### Task 4: Implement Network Intelligence Agent

**Files:**
- Create: `backend/app/services/network_intelligence.py`
- Test: `backend/tests/test_network_intelligence.py`

**Interfaces:**
- Consumes: `Scan`, `Resource`, `PageLink`, `Technology` from database.
- Produces: `NetworkIntelligenceAgent.analyze() -> list[Dependency]` saving `Dependency` & `Observation` rows.

- [ ] **Step 1: Write failing unit tests for NetworkIntelligenceAgent**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement external domain graph construction, Phase 4 technology category cross-referencing, and unclassified dependency fallbacks**
- [ ] **Step 4: Run test to verify it passes**

---

### Task 5: Pipeline Integration & REST Endpoints

**Files:**
- Modify: `backend/app/api/routes/scans.py`
- Test: `backend/tests/test_phase5_endpoints.py`

**Interfaces:**
- Produces: Pipeline integration in `create_scan`, `GET /scans/{id}/architecture`, `GET /scans/{id}/dependencies`, `GET /scans/{id}/api-endpoints`.

- [ ] **Step 1: Write failing API endpoint tests**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Wire agents into `create_scan` completion flow & add new route endpoints**
- [ ] **Step 4: Run test to verify it passes**

---

### Task 6: Frontend API Client & Data Types

**Files:**
- Modify: `frontend/lib/api.ts`

**Interfaces:**
- Produces: TypeScript types `SiteArchitecture`, `FormElement`, `PageNode`, `DependencyNode`, `ApiEndpointItem`, and fetch functions `getScanArchitecture`, `getScanDependencies`, `getScanApiEndpoints`.

- [ ] **Step 1: Add Phase 5 types and API fetch methods to `lib/api.ts`**

---

### Task 7: Interactive Dependency Graph Component

**Files:**
- Create: `frontend/components/DependencyGraph.tsx`

**Interfaces:**
- Consumes: `dependencies: DependencyNode[]`, `scanUrl: string`.
- Produces: Interactive SVG/Canvas node-link network with zoom/pan, category filter, search box, and click-to-inspect evidence drawer.

- [ ] **Step 1: Build `DependencyGraph.tsx` interactive component**

---

### Task 8: Scan Result UI Integration

**Files:**
- Modify: `frontend/app/scans/[id]/page.tsx`

**Interfaces:**
- Displays Architecture tab, Interactive Dependency Graph, and API Endpoints catalog.

- [ ] **Step 1: Integrate Architecture, Dependency Graph, and API Endpoints tabs/views into Scan detail page**
- [ ] **Step 2: Verify typecheck and frontend build**
