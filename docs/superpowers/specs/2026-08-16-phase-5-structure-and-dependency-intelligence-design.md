# Phase 5 — Structure + Dependency Intelligence Design Specification

**Date:** 2026-08-16  
**Status:** Approved Design  
**Scope:** Structure Agent, API Intelligence Agent, Network Intelligence Agent, DB Models (`Dependency`, `ApiEndpoint`), REST Endpoints, Interactive Dependency Graph UI.

---

## 1. Executive Summary

Phase 5 builds three deterministic evidence processing agents on top of existing Phase 1–4 collection artifacts:
1. **Structure Agent**: Builds site tree hierarchy, link stats (internal vs. external), form inventory, and infers page types.
2. **API Intelligence Agent**: Statically detects candidate API endpoints referenced in page text, scripts, form actions, and resources, inferring HTTP methods and content-types safely without making network calls.
3. **Network Intelligence Agent**: Builds an external domain relationship graph, categorizing external domains using Phase 4 technology detections or tagging them as unclassified dependencies.

Every finding is classified per the project taxonomy (`🟢 OBSERVED`, `🟡 INFERRED`, `⚫ UNKNOWN`) and is linked to verifiable evidence.

---

## 2. Component & Architecture Design

```
+-------------------------------------------------------------------------------+
|                             Phase 5 Analysis Pipeline                         |
|                                                                               |
|  [Crawl & Tech Complete]                                                      |
|           |                                                                   |
|           +---> StructureAgent ----------> Page Hierarchy & Form Inventory    |
|           |                                                                   |
|           +---> ApiIntelligenceAgent ----> Candidate API Endpoints            |
|           |                                                                   |
|           +---> NetworkIntelligenceAgent -> External Dependencies & Graph     |
+-------------------------------------------------------------------------------+
```

### 2.1 Database Models (`app/models/scan.py`)

#### `Dependency`
- `id`: UUID (Primary Key)
- `scan_id`: UUID (Foreign Key to `scans.id`, ondelete CASCADE)
- `domain`: String(255), index=True
- `category`: String(100), index=True (e.g., "Analytics", "CDN", "Fonts", "Unclassified")
- `classification`: String(30), default="inferred"
- `confidence`: Float
- `reference_count`: Integer
- `sample_resource_urls`: JSON (nullable)
- `created_at`: DateTime(timezone=True)

#### `ApiEndpoint`
- `id`: UUID (Primary Key)
- `scan_id`: UUID (Foreign Key to `scans.id`, ondelete CASCADE)
- `url_or_path`: String(2048), index=True
- `http_method`: String(20), default="UNKNOWN"
- `content_type`: String(255), nullable=True
- `classification`: String(30), default="inferred"
- `confidence`: Float
- `discovered_from_source`: String(2048)
- `created_at`: DateTime(timezone=True)

---

### 2.2 Agent Implementations (`app/services/`)

1. **`StructureAgent` (`app/services/structure.py`)**:
   - Analyzes `Page` & `PageLink` rows for the scan.
   - Infers `page_type` per page (e.g. `homepage`, `contact_or_form`, `catalog_or_listing`, `article_or_content`, `documentation_or_api`, `generic_page`) with evidence.
   - Summarizes internal vs. external link counts per page & site-wide.
   - Parses `<form>` attributes (`action`, `method`, `inputs`) from HTTP response body artifacts.

2. **`ApiIntelligenceAgent` (`app/services/api_intelligence.py`)**:
   - Parses HTML bodies, script `src` attributes, inline JS snippets, and resource URLs for API path patterns (`/api/`, `/graphql`, `/v1/`, `fetch(...)`, `axios`, `$.ajax`).
   - Infers HTTP method (`GET`, `POST`, etc.) and content-type.
   - Creates `ApiEndpoint` rows and linked `Observation` items. Strictly static (0 network calls).

3. **`NetworkIntelligenceAgent` (`app/services/network_intelligence.py`)**:
   - Extracts all external domains referenced in `Resource` and `PageLink` rows.
   - Reuses Phase 4 `Technology` output to assign categories (e.g. Analytics, CDN). Unmatched domains are categorized as `Unclassified External Dependency`.
   - Creates `Dependency` rows and linked `Observation` items.

---

### 2.3 API Gateway Endpoints (`app/api/routes/scans.py`)

- `GET /scans/{id}/architecture`: Returns site hierarchy, page types, link summary, and form inventory.
- `GET /scans/{id}/dependencies`: Returns external dependency graph, domain reference counts, categories, confidence, and sample URLs.
- `GET /scans/{id}/api-endpoints`: Returns candidate API endpoints with inferred method, content-type, confidence, and source.
- `GET /scans/{id}/evidence`: Updated to include Phase 5 observations.

---

### 2.4 Frontend Visualization (`frontend/`)

- **Dependency Graph Component (`frontend/components/DependencyGraph.tsx`)**:
  - Node-link graph with SVG/Canvas rendering.
  - Nodes: Target Website $\to$ Categories $\to$ External Domains.
  - Features: Pan/Zoom controls, Category filter multi-select, Real-time search filter, Node inspection drawer displaying linked evidence & confidence.
- **Architecture Tab**: Page tree, link stats, and form inventory.
- **API Endpoints Tab**: Endpoint inventory table with evidence drill-down.

---

## 3. Verification & Testing Strategy

1. **Database Migration**: Run `alembic upgrade head` to verify schema changes.
2. **Backend Unit/Integration Tests**:
   - `tests/test_structure.py`: Verify tree building, form parsing, page type inference, link counts.
   - `tests/test_api_intelligence.py`: Verify endpoint discovery from static bodies/scripts without network requests.
   - `tests/test_network_intelligence.py`: Verify domain extraction, technology category matching, and unclassified dependency fallbacks.
   - `tests/test_phase5_endpoints.py`: Test `/scans/{id}/architecture`, `/scans/{id}/dependencies`, and `/scans/{id}/api-endpoints`.
3. **Frontend Verification**: Build & typecheck frontend (`pnpm build`, `pnpm typecheck`).
