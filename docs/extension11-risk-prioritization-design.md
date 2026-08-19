# Extension 11 — Risk & Heuristic Prioritization Agent

## Purpose and non-negotiable boundary

The Risk Agent prioritizes already persisted findings for engineering review. It does not issue target requests, validate exploitability through active testing, submit data, attempt authentication, or modify the target. Every score is derived from stored evidence and displayed as named components. A risk score is a prioritization aid, not a claim that a vulnerability is exploitable or that business impact has been proven.

Machine-learning-assisted prioritization is intentionally disabled by default. It can be introduced only after a documented training and evaluation dataset demonstrates sufficient coverage, calibration, validation, and governance. A learned model must be additive and must never override a validated evidence state, its provenance, or the deterministic score components.

## Deterministic score model

The agent computes a 0–100 priority score using seven visible components. The weighted total is the sum of the component scores multiplied by their weights.

| Component | Weight | Deterministic source | Constraint |
|---|---:|---|---|
| Severity | 25% | Stored finding severity | Uses a fixed critical/high/medium/low/info map. |
| Confidence | 15% | Stored finding confidence and evidence-review state | Candidate or inconclusive evidence cannot be presented as validated. |
| Exposure | 15% | In-scope affected endpoint, API, host, or application edges in the attack-surface graph | Missing exposure data is neutral, not an assumed public exposure. |
| Exploitability indicators | 10% | Observed category, rule metadata, and evidence-review reproducibility | No exploit attempt is performed or implied. |
| Asset criticality | 15% | Affected graph asset type and stored association | Application/API/authentication-boundary assets receive explicit, explainable weight; unknown assets remain neutral. |
| Business impact | 10% | Finding category and severity only | No unobserved revenue, customer, or regulatory impact is inferred. |
| Evidence quality | 10% | Persisted EvidenceReview quality, state, prerequisites, and reproducibility | Rejected evidence is suppressed; weak or inconclusive evidence receives a visible confidence cap. |

The deterministic risk band is `critical` at 85 or above, `high` at 70–84.99, `medium` at 45–69.99, `low` at 20–44.99, and `info` below 20. A rejected review is ineligible for prioritization. Candidate and inconclusive reviews retain their label but are capped at lower priority bands; the component explanation names the applied cap.

## Persistence and provenance

`risk_assessments` stores one idempotent record per `(scan_id, security_finding_id)`. It stores the score, band, eligibility, named component values and weights, a redacted evidence snapshot, and the deterministic decision notes.

`scan_risk_summaries` stores one idempotent scan-level summary. Its `overall_score` is the weighted blend of the highest eligible finding and the mean of the highest five eligible findings. The calculation and inputs are returned to clients.

## Same-target trends

Trend calculations compare persisted risk summaries from completed scans that share the same `website_id`. A score movement of at least five points is presented as increased or decreased; smaller changes are stable. Finding-level comparison uses a stable `(rule_id, normalized_subject)` key. An absent current finding is always described as `not_currently_observed`, not resolved.

## API and user interface

`GET /v1/scans/{scan_id}/risk-prioritization` returns ordered assessments, transparent components, scan summary, prior-scan comparison, same-target trend series, and the ML safety contract. The report section renders the highest-priority items, a component breakdown, evidence state, and trend comparisons. It contains no control that initiates testing or exploitation.
