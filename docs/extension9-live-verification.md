# Extension 9 — Evidence Agent Live Verification

Date: 2026-08-19

## Definitive real-target scan

A fresh authorized bounded scan targeted `https://www.python.org/` with safe profile, explicit domains `python.org` and `www.python.org`, root-path scope, `/downloads/` exclusion, maximum depth 1, maximum 5 pages, maximum 10 requests, one worker, 500 ms configured host delay, robots respected, passive-only recon, and actor `authorized-extension9-verification`.

Scan ID: `1924fbfb-3513-430e-b5bb-29d39d30b460`.

The final scan reached `COMPLETED` with 100% progress, 25/25 terminal tasks, 21 task types, 7 requests used, and `evidence: SUCCEEDED`. The report page rendered the Evidence Agent navigation entry, task card, and report section.

The Evidence Agent returned ruleset `phase9-evidence-v1`, 52 independent reviews, 52 validated states, zero inconclusive states, zero rejected states, and zero unredacted secret values. The API contract reported required provenance fields for target, endpoint/asset, source agent, timestamp, rule ID, and observation; secret values redacted; safe request metadata available when relevant; and `signature_alone_is_proof: false`.

The final report showed redacted provenance records, persisted-response reproducibility metadata with `network_request_issued: false`, observation counts, evidence quality, confidence, target, and endpoint/asset fields. The UI explicitly states that a scanner signature alone is not proof.

## Corrective finding

The first live attempt exposed a route collision: the existing raw observation endpoint already used `/evidence`, so the new review endpoint initially returned the raw observation list. The review endpoint was corrected to:

```text
GET /v1/scans/{scan_id}/evidence-agent
```

The raw compatibility endpoint remains unchanged:

```text
GET /v1/scans/{scan_id}/evidence
```

Both returned HTTP 200 after the correction.

The live runtime also experienced transient SQLite lock and worker-heartbeat events while multiple inline tasks updated task state. The affected tasks retried and ultimately reached `SUCCEEDED`; the final scan completed normally. This is recorded as a runtime retry condition, not an Evidence Agent logic failure.

## Validation

The final release validation passed compilation, 106 backend tests, frontend lint, TypeScript checking, production build, Alembic migration `20260819_extension9`, backend/browser/frontend health checks, raw-evidence route compatibility, and the corrected Evidence Agent route.
