# Extension 7 — Secrets & Sensitive Data Agent Integration Design

## Purpose

The Secrets & Sensitive Data Agent is a redaction-first leakage detector for authorized web assessments. It inspects only bounded evidence already persisted by collection and the HTTP Agent: response bodies, inline and JavaScript resources, source-map/configuration-shaped bodies, and response headers. It does not create a new fetcher, request pass, artifact downloader, credential validator, or authentication workflow.

> Secret values are never persisted, logged, returned by the report API, displayed in the frontend, or used for authentication. Findings contain only the minimum metadata required to establish a likely leakage class.

## Integration

The persisted task graph runs `secrets` after `collection` and `http_agent`. Diagnosis waits for the Secrets Agent alongside the other assessment agents. Existing scans remain compatible because findings use the existing `SecurityFinding` table with `category="secrets"`; no migration is required.

The read-only report endpoint is:

```text
GET /v1/scans/{scan_id}/secrets
```

The response contains six rule templates, redacted findings, confidence-tier counts, and an explicit redaction contract stating whether values were persisted, logged, or returned. The frontend renders the rule catalog, suppression logic, severity counters, redacted evidence, limitations, remediation guidance, and references.

## Detection sources

The agent builds in-memory `SecretSource` records from the latest persisted HTTP response for each page. The source types are `http_response`, `javascript`, `source_map`, `public_config`, and `header`. Source locations are sanitized to remove query strings. Inline script bodies are analyzed in memory but never stored as raw script evidence. Header analysis includes only the header name plus the in-memory value context; findings retain only redacted metadata.

Referenced source maps and configuration resources are not fetched. A source-map or public-configuration finding requires a captured body that itself contains a detected candidate; a URL reference alone is not treated as a secret leakage finding.

## Rule catalog

| Rule | Detection scope | False-positive suppression |
|---|---|---|
| `SECRET-SIG-001` | Provider-specific API keys, tokens, JWTs, and signature families | Suppresses placeholders, examples, test values, short values, URLs, and low-diversity strings. |
| `SECRET-SIG-002` | PEM-style private-key material | Stores only the delimiter family and never the key body. |
| `SECRET-CONTEXT-001` | Context-bound assignments such as `api_key`, `access_token`, `client_secret`, password, or private-key values | Requires sufficient length and entropy; suppresses placeholders, URLs, hashes, and common public constants. |
| `SECRET-ENTROPY-001` | High-entropy contextual assignments without provider prefixes | Requires a contextual key, length threshold, character diversity, and entropy threshold. |
| `SECRET-ID-001` | SSN-like and checksum-valid payment-card identifiers in relevant contexts | Requires nearby identifier context; suppresses random numbers, dates, order IDs, phone numbers, and test markers. |
| `SECRET-ARTIFACT-001` | Correlation between a captured source-map/configuration artifact body and a separate secret candidate | Requires both artifact classification and an independently detected candidate; never fetches an artifact. |

Confidence tiers are `high`, `medium`, and `low`, with high-confidence provider/private-key/identifier findings separated from medium-confidence entropy candidates. Severity is independent from confidence and is chosen according to likely impact, with private-key material treated as critical.

## Minimum evidence and redaction

A finding stores the rule ID, redacted subject and statement, classification, confidence, severity, source type, sanitized source path, secret class, length bucket, entropy tier, confidence tier, occurrence-offset bucket, and `[REDACTED]` marker. It does not store the matched value, surrounding source text, full header value, script body, response body, or a reversible hash of the secret.

The implementation validates every candidate before persistence. A candidate is rejected if it lacks evidence, limitations, or the redaction marker, or if provider token material appears in its serialized evidence. The API and frontend expose the same redaction contract and do not offer an unlock or reveal action.

## Safety and operations

The agent performs no target requests, sends no payloads, submits no forms, attempts no authentication, fetches no referenced artifacts, and does not validate whether a credential works. Confirmed exposure requires separate authorized incident handling: remove the value from public assets, revoke or rotate it, review access logs, and apply least-privilege remediation. The report uses indicator language and explicit limitations rather than claiming compromise.
