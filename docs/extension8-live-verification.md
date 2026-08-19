# Extension 8 — CVE & Technology Intelligence Live Verification

Date: 2026-08-19

## Definitive real-target scan

A fresh authorized bounded scan targeted `https://www.python.org/` with safe profile, explicit domains `python.org` and `www.python.org`, root-path scope, `/downloads/` exclusion, maximum depth 1, maximum 5 pages, maximum 10 requests, one worker, 500 ms host delay, robots respected, passive-only recon, and actor `authorized-extension8-verification`.

Scan ID: `1b48eba9-cd29-42aa-8ef4-e693659d3e52`.

The scan completed with `COMPLETED` state, `completed` status, 100% progress, 24/24 terminal tasks, 20 task types, `requests_used: 7`, and no terminal error. The new `cve_intelligence` task reached `SUCCEEDED` with dependency `technology`. One worker heartbeat expired during execution; the task returned to the retry queue and then succeeded on attempt 1. This is a recoverable runtime retry, not a CVE-analysis failure.

The live report returned ruleset `phase8-cve-v1`, one detected technology (`fastly`), zero matched CVEs, one `version_insufficient` state, zero KEV matches, and two successful CISA KEV feed runs. The report explicitly displayed separate detection, version-evidence, and CVE-applicability confidence and stated that family-only detection cannot produce a matched CVE.

This is the correct result for the Python.org evidence: the detected technology had no explicit version evidence, so the agent withheld CVE applicability rather than guessing. No NVD product query was issued for that family-only technology.

## Official feed smoke verification

A separate isolated in-memory database used real public feed responses with explicit `WordPress 6.0` evidence. The NVD CVE API returned 100 records for the bounded product query, and the CISA KEV JSON catalog returned 1,670 records. The agent normalized both sources, deduplicated the NVD CVE record, enriched KEV status, and produced a conservative matched state for `CVE-2007-2627` against the explicit WordPress 6.0 evidence. This smoke test did not modify the project’s live scan database.

Feed provenance recorded the official URLs, retrieval timestamps, source timestamps where available, record counts, status, stale thresholds, and error fields. The NVD source was verified through `https://services.nvd.nist.gov/rest/json/cves/2.0`, and the CISA source through `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.

## Validation

Full validation passed with Python compilation, 102 backend tests, frontend lint, TypeScript checking, production build, and Alembic head `20260819_extension8`. The live backend, browser worker, frontend, and `/v1/scans/{scan_id}/cve-intelligence` route returned successfully.
