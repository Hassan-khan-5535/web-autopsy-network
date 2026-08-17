# Phase 12 — Cause of Death

## What was added

Phase 12 adds a deterministic **Risk / Impact Engine** and an evidence-linked **Cause of Death** diagnosis for each completed scan. The engine reads only persisted findings and does not issue new requests to a target website. It ranks Technology, Dependency, Security, Performance, Accessibility, and Content findings, then selects a single primary issue, up to three distinct secondary issues, and up to two relation-traceable contributing factors.

The diagnosis is persisted in the new `cause_of_death_diagnoses` table and exposed through both `GET /v1/scans/{id}` and the dedicated `GET /v1/scans/{id}/diagnosis` endpoint. The reusable ranked finding list is available from `GET /v1/scans/{id}/risk`.

## Deterministic rubric

Each normalized dimension is scored from 0 to 1 and combined using the following documented weights:

| Dimension | Weight | Implementation basis |
|---|---:|---|
| Impact | 30% | Category-aware impact level; performance diagnostics receive the highest impact. |
| Confidence | 25% | Existing finding confidence, normalized to 0–1, or classification fallback. |
| Severity | 15% | Explicit severity bands for security and documented category defaults elsewhere. |
| Dependency criticality | 10% | Reference count relative to the most referenced dependency in the scan. |
| Frequency | 10% | Occurrence count for the same category and subject relative to the scan maximum. |
| User-facing effect | 10% | Documented category defaults, with performance and security weighted higher than technology detection. |

The final priority score is not a category average. It is computed per actual finding, and the diagnosis is selected from the ranked findings. Confidence is an evidence-count-weighted mean of the selected findings’ normalized confidence dimensions. Evidence count is the number of distinct evidence IDs backing the selected primary, secondary, and contributing findings.

## AI narrative safeguards

The optional AI narrative receives the already-computed diagnosis only. It cannot change, add, remove, or re-rank the deterministic selection. The narrative citations are validated by the shared `EvidenceAgent` against the diagnosis evidence set. When no LLM key is configured or the provider fails, a deterministic fallback narrative is returned and cited without blocking the diagnosis.

Every diagnosis response includes the structural disclaimer: **“Cause of Death is a diagnostic label for prioritizing observable web findings. It is not a claim that the website is compromised, hacked, or offline.”**

## Frontend

Completed scan reports now show the branded Cause of Death card above the AI Doctor. It displays the primary issue, secondary issues, contributing factors, priority scores, overall confidence, evidence count, AI narrative, required disclaimer, and links back to the relevant evidence anchors in the report.

## Verification

| Check | Result |
|---|---:|
| Backend tests, including Phase 11 and Phase 12 acceptance tests | 39 passed |
| Backend syntax compilation | Passed |
| Frontend TypeScript typecheck | Passed |
| Frontend ESLint | Passed |
| Dominant large-JavaScript-payload diagnosis | Verified as primary issue |
| Confidence/evidence traceability | Verified |
| Fabricated AI narrative citation fallback | Verified |
| Diagnosis disclaimer presence | Verified in API and UI |
| Live FastAPI health check | HTTP 200 |
| Live browser report | Cause of Death card rendered with 96% confidence and 4 evidence items |

## Local demo

Docker is unavailable in the sandbox, so the live verification used the Next.js frontend and FastAPI backend started directly against a seeded SQLite database. The demo scan contains a 9 MB JavaScript payload, a missing Content-Security-Policy observation, a missing meta description, and a Next.js technology detection. The diagnosis correctly selects `diagnosis:large_js_payload` as the primary issue.

The normal Docker Compose workflow remains unchanged for environments with Docker. Before pushing, review the working tree and confirm that the Phase 12 changes should be committed and pushed to the repository’s `main` branch.
