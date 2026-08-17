# Phase 11 — History / Time Machine

## Delivered

Phase 11 adds a persisted, deterministic History / Difference Engine that compares two completed scans belonging to the same website without issuing new requests to the target site. The comparison is available through `POST /v1/scans/compare` with `{ "scan_a": "...", "scan_b": "..." }`, and historical scans are listed through `GET /v1/websites/{website_id}/scans`.

The backend adds the `ScanDifference` model and Alembic migration, plus `DiffEngine`, which compares structure, technology, dependencies, security, performance, and content findings. Every diff item receives a stable ID, a classification, before/after values, and evidence IDs. Technology and dependency absence is classified as `INFERRED` with explicit language that non-detection is not proof of removal. Performance regression framing is only applied when the documented 20% increase threshold is exceeded.

The AI change-summary service reuses the existing provider abstraction and evidence gate. It supplies only structured diff items to the LLM and validates every returned citation against persisted `ScanDifference` item IDs. If no LLM key is configured, the endpoint still returns a deterministic, cited fallback summary without blocking the structured result.

The Phase 10 `POST /v1/scans/{id}/ask` endpoint now recognizes history questions such as “what changed since the previous scan?” and compares the latest earlier completed scan for the same website.

The frontend now includes a History / Time Machine panel on completed scan reports. Users can select a prior completed scan, compare it with the current scan, review category-by-category before/after values and classifications, and follow AI summary citations to the corresponding diff item.

## Verification

| Check | Result |
|---|---:|
| Backend tests, including new Phase 11 tests | 36 passed |
| Backend syntax compilation | Passed |
| Frontend TypeScript typecheck | Passed |
| Frontend ESLint | Passed |
| Deterministic repeated comparison | Passed |
| Fabricated diff citation rejection | Passed |
| Local FastAPI health check | HTTP 200 |
| Browser verification | History panel populated with 4 demo diff items |

## Local demonstration

Docker is not installed in the sandbox, so the screenshot was verified with the repository’s Next.js frontend and FastAPI backend started directly against a seeded SQLite demo database. The normal Compose workflow remains unchanged for environments with Docker.

Before pushing, review the working tree and confirm that the changes should be committed and pushed to the repository’s `main` branch.
