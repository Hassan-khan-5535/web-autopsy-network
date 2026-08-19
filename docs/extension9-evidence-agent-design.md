# Extension 9 — Evidence Agent Design

## Purpose

The Evidence Agent is an independent false-positive reduction layer that runs after candidate-producing agents. It does not replace the source agents and does not treat their signatures as proof. It collects persisted candidate findings, linked HTTP observations, shared observations, and source metadata, then produces a separately persisted evidence review.

## Review contract

Every review preserves the target, endpoint or asset, source agent, timestamp, rule ID, observation identifier, evidence quality, confidence, prerequisite result, reproducibility state, and redacted provenance. The read-only endpoint is:

```text
GET /v1/scans/{scan_id}/evidence-agent
```

The legacy raw observation endpoint remains:

```text
GET /v1/scans/{scan_id}/evidence
```

The Evidence Agent report returns `candidate`, `validated`, `rejected`, and `inconclusive` states. It also returns `strong`, `moderate`, `weak`, and `none` evidence-quality values. State and quality are not interchangeable: a high source confidence does not become validated without prerequisites and corroboration.

## Evidence collection

For each persisted `SecurityFinding`, the agent collects its bounded evidence list, linked HTTP observations for the associated page, and relevant shared observations from the same scan. Each collected item has a stable observation identifier and source-agent label. The aggregated set is capped to prevent unbounded report growth.

Prerequisites require a rule ID, statement, classification, and at least one non-empty persisted observation after redaction. Missing or empty evidence yields a rejected or inconclusive review rather than a positive validation.

## Safe reproducibility

The current reproducibility check is deliberately non-invasive. When a linked persisted HTTP response exists, the agent performs a consistency review over stored response metadata and marks `reproduced_from_persisted_response`. It issues no network request, sends no payload, submits no form, authenticates, mutates state, or replays a target request. If no stored response exists, the report records `not_run` or `not_reproducible` with a reason.

A `validated` state requires strong evidence quality and persisted-response reproduction. Otherwise the review remains a candidate, inconclusive, or rejected state. This prevents a scanner signature or a single weak observation from becoming proof.

## Redaction

Evidence review output redacts URL query values, authorization/cookie/token/password/secret-like fields, provider-style credentials, and private-key blocks. Values are not intended to be persisted, logged, or returned. Safe request metadata includes only method-independent facts such as `network_request_issued: false`, response-availability flags, and bounded status metadata where relevant.

The model stores a `redacted` invariant, and validation rejects reviews that lack required provenance or contain known unredacted provider/private-key patterns.

## Persistence and task graph

Extension 9 adds the `evidence_reviews` table through Alembic revision `20260819_extension9`. Existing `SecurityFinding` records remain unchanged. Each scan/candidate review is idempotent through a unique `(scan_id, candidate_key)` constraint.

The persisted task graph runs `evidence` after technology, structure, API, network, HTTP, configuration, security, vulnerability, secrets, CVE intelligence, performance, accessibility, content, and optional recon tasks. Diagnosis waits for Evidence Agent completion.

## Safety boundary

The Evidence Agent is a reporting and quality layer, not an exploit verifier. It does not claim exploitability, access control failure, secret validity, or impact. Any future active reproducibility check must remain explicitly authorized, scope-checked, rate-limited, non-destructive, and fully audited.
