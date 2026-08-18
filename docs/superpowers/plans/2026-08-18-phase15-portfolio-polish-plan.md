# Phase 15 Portfolio Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a polished, demo-ready, fully documented version of Web Autopsy Network with a marketing landing page, instant canned demo mode, interactive system architecture visualization, UI polish across all forensic views, system architecture documentation, API reference, load test benchmark results, and an updated README.

**Architecture:** Frontend Next.js pages/components for landing page, demo route, system architecture graph, and polished UI views; markdown documentation files for system architecture, API reference, benchmark results, and main README.

**Tech Stack:** Next.js 14, TypeScript, Tailwind CSS, Lucide Icons, FastAPI, Python, Pytest.

**Spec:** `docs/superpowers/specs/2026-08-18-phase15-portfolio-polish-design.md`

## Global Constraints
- No new backend analysis engines or AI features are added.
- Canned demo mode must be prominently labeled as **DEMO / SAMPLE DATA**.
- Core evidence classification system (🟢 OBSERVED / 🟡 INFERRED / 🔵 AI INTERPRETATION / ⚫ UNKNOWN) must be visually legible across all views.
- No git commits or git pushes (user handles commits manually).

---

### Task 1: Demo Mode Dataset Engine

**Files:**
- Create: `frontend/lib/demo-data.ts`
- Modify: `frontend/lib/api.ts`
- Modify: `frontend/app/scans/[id]/page.tsx`

**Interfaces:**
- Consumes: `ScanResponse`, `ObservationResponse`, `SecurityFinding`, `PerformanceResponse`, etc.
- Produces: `isDemoScan(id: str) -> bool`, `getDemoScanData(id: str) -> DemoScanPayload`.

- [ ] **Step 1: Create `frontend/lib/demo-data.ts` with complete canned autopsy dataset**

```typescript
import {
  ScanResponse,
  CrawledPage,
  TechnologyDetection,
  ObservationResponse,
  SiteArchitecture,
  DependencyItem,
  ApiEndpointItem,
  SecurityFinding,
  PerformanceResponse,
  AccessibilityFinding,
  ContentFinding,
  CauseOfDeathDiagnosis,
} from "./api";

export const DEMO_SCAN_ID = "demo-scan-autopsy";

export const DEMO_SCAN: ScanResponse = {
  id: DEMO_SCAN_ID,
  website_id: "demo-website-123",
  requested_url: "https://demo-autopsy.store",
  state: "COMPLETED",
  error_reason: null,
  max_depth: 2,
  max_pages: 15,
  max_concurrency: 2,
  request_delay_ms: 1000,
  same_domain_mode: "hostname",
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
};

export const DEMO_DIAGNOSIS: CauseOfDeathDiagnosis = {
  id: "diag-demo-1",
  scan_id: DEMO_SCAN_ID,
  primary_issue_id: "sec_csp_missing",
  primary_category: "SECURITY",
  statement: "Critical Security Risk: Unprotected origin lacking Content-Security-Policy & excessive uncompressed JavaScript bundles causing render blocking.",
  impact_score: 88.5,
  confidence: 0.94,
  disclaimer: "Non-literal diagnostic summary based on observable HTTP, security headers, and browser performance metrics.",
  evidence: ["sec_csp_missing", "perf_lcp_slow", "tech_jquery_legacy"],
  created_at: new Date().toISOString(),
};
```

- [ ] **Step 2: Connect `api.ts` to intercept `demo-scan-autopsy` and return demo payload**

- [ ] **Step 3: Add `DEMO DATA` banner to `frontend/app/scans/[id]/page.tsx`**

- [ ] **Step 4: Verify demo page loads without server errors**

---

### Task 2: Polished Marketing Landing Page

**Files:**
- Modify: `frontend/app/page.tsx`

- [ ] **Step 1: Update `frontend/app/page.tsx` with hero section, 10-second tagline, 🟢🟡🔵⚫ legend, live scan URL input, and Demo CTA button**

- [ ] **Step 2: Add glassmorphism styling, feature highlight cards, and responsive layout**

- [ ] **Step 3: Verify landing page renders correctly**

---

### Task 3: Interactive System Architecture Visualization Page

**Files:**
- Create: `frontend/app/architecture/system/page.tsx`

- [ ] **Step 1: Create interactive architecture page visualizing Web Autopsy Network's own distributed pipeline**

Nodes: Admission (SSRF Guard) $\rightarrow$ Crawl Pool $\rightarrow$ Playwright Sandbox $\rightarrow$ Analysis Worker Pools $\rightarrow$ LLM Citation Gate $\rightarrow$ Cause of Death Engine $\rightarrow$ PostgreSQL & Redis Storage.

- [ ] **Step 2: Add interactive node click modal showing queue concurrency limits, security boundaries, and isolation flags**

---

### Task 4: UI Component Polish Pass

**Files:**
- Modify: `frontend/app/scans/[id]/page.tsx` (Evidence Explorer search bar & category/classification pills)
- Modify: `frontend/components/ai-doctor.tsx` (Clickable citation chips & starter prompt buttons)
- Modify: `frontend/components/history-panel.tsx` (Side-by-side visual diff comparison)
- Modify: `frontend/components/cause-of-death.tsx` (Forensic diagnosis card visual styling & disclaimer)
- Modify: `frontend/components/scan-progress.tsx` (Real-time scan progress animation & worker badges)

- [ ] **Step 1: Refine Evidence Explorer with instant search input and classification filters (🟢/🟡/🔵/⚫)**
- [ ] **Step 2: Update AI Doctor chat with clickable citation badges and starter prompt pills**
- [ ] **Step 3: Enhance Time Machine view with side-by-side diff highlighting**
- [ ] **Step 4: Style Cause of Death diagnosis widget with confidence meter and disclaimer**

---

### Task 5: System & API Documentation

**Files:**
- Create: `docs/SYSTEM_ARCHITECTURE.md`
- Create: `docs/API.md`
- Create: `docs/BENCHMARK_RESULTS.md`

- [ ] **Step 1: Write `docs/SYSTEM_ARCHITECTURE.md` covering agent architecture, deterministic vs AI reasoning, queue topology, and security model**
- [ ] **Step 2: Write `docs/API.md` providing complete OpenAPI documentation for all REST endpoints**
- [ ] **Step 3: Write `docs/BENCHMARK_RESULTS.md` documenting Phase 14 load-testing metrics**

---

### Task 6: Primary Repository `README.md` Overhaul

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Rewrite `README.md` with badges, project overview, core classification legend, system architecture diagram, setup instructions, and Phase 14 benchmark summary**

---

### Task 7: Final Verification

**Files:**
- `backend/tests/`
- `frontend/`

- [ ] **Step 1: Run `pytest tests/` in backend to verify 60/60 tests pass**
- [ ] **Step 2: Verify `LOCAL_VERIFICATION.md` is fully updated**

---
