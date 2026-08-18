# Web Autopsy Network — Phase 15: Portfolio Polish Specification

**Date:** 2026-08-18  
**Status:** Approved  
**Phase:** 15 (Portfolio Polish)  

---

## 1. Executive Summary

Phase 15 is the final presentation and documentation phase for Web Autopsy Network. It transforms the complete, production-hardened platform built across Phases 1–14 into an outstanding portfolio piece.

Key deliverables include:
- A high-impact Marketing Landing Page (`/`).
- An instant Demo Mode dataset (`/scans/demo-scan-autopsy`).
- An interactive System Architecture page (`/architecture/system`).
- UI polish across all 8 major forensic views (Evidence Explorer, AI Doctor, Time Machine, Cause of Death, Scan Progress).
- Detailed System Architecture (`SYSTEM_ARCHITECTURE.md`), API reference (`API.md`), and Phase 14 Benchmark Results (`BENCHMARK_RESULTS.md`).
- A comprehensive, polished `README.md`.

---

## 2. Component Specifications

### 2.1 Marketing Landing Page (`frontend/app/page.tsx`)
- **Tagline:** "Dissect any website. Understand how it works."
- **10-Second Concept Legend:**
  - 🟢 **OBSERVED**: Directly measured network/HTTP data
  - 🟡 **INFERRED**: Multi-observation technical conclusion
  - 🔵 **AI INTERPRETATION**: Citation-grounded LLM synthesis
  - ⚫ **UNKNOWN**: Unobservable externally
- **CTA Controls:** Live URL scan input + "View Canned Demo Autopsy" button.

### 2.2 Demo Mode (`frontend/lib/demo-data.ts` & `/scans/demo-scan-autopsy`)
- Pre-populated scan report featuring `demo-autopsy.store`.
- Includes 12 pages, 8 detected technologies, 4 security findings, performance metrics, WCAG violations, and a Cause of Death diagnosis card.
- Prominent **🟡 DEMO / SAMPLE DATA** banner at top of page.

### 2.3 Interactive System Architecture Page (`frontend/app/architecture/system/page.tsx`)
- Interactive explorable node graph visualizing:
  `URL Admission (SSRF Guard) → Crawl Worker Pool → Playwright Sandbox → Analysis Engines → LLM Citation Gate → Cause of Death Engine → PostgreSQL / Redis Storage`.
- Node detail modal showing resource ceilings, queue profiles, and security flags.

### 2.4 Component Polish
- **Scan Progress (`scan-progress.tsx`)**: Real-time progress bar, queue badges, worker heartbeat, execution timer.
- **Evidence Explorer (`app/scans/[id]/page.tsx`)**: Search bar, classification pills (🟢/🟡/🔵/⚫), and category filters.
- **AI Doctor (`ai-doctor.tsx`)**: Clickable citation chips linking to evidence items, starter prompt buttons, citation rejection badges.
- **Time Machine (`history-panel.tsx`)**: Visual side-by-side diff comparison highlighting added, removed, and modified evidence.
- **Cause of Death Card (`cause-of-death.tsx`)**: Branded forensic diagnosis card with impact score gauge and mandatory disclaimer.

### 2.5 Documentation Artifacts
- `docs/SYSTEM_ARCHITECTURE.md`: Complete system architecture guide.
- `docs/API.md`: OpenAPI reference for all 18 REST endpoints.
- `docs/BENCHMARK_RESULTS.md`: Phase 14 load test benchmarks (concurrency, query counts, latencies).
- `README.md`: Updated primary project repository homepage.
