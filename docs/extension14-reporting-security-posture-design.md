# Extension 14 — Reporting and Security Posture

## Scope

Extension 14 creates one evidence-backed report representation for the persisted scan report, JSON export, SARIF export, and PDF export. It does not perform target requests, collect new evidence, generate screenshots, or broaden authorization.

## Report Contract

| Section | Source of truth | Safety boundary |
| --- | --- | --- |
| Executive summary | Persisted deterministic risk summary and eligible evidence-backed findings | States limitations; does not claim exploitability. |
| Technical findings | Security findings, risk assessments, evidence reviews, and existing page/URL context | Preserves redaction and only names parameters already present in a URL. |
| Remediation and references | Deterministic rule-family mapping and persisted CVE intelligence | Provides defensive remediation only; links map to CWE, OWASP, and source CVE records. |
| Security posture and trend | Security posture snapshot and same-target difference data | Reports comparisons as observations; absence is not treated as resolution. |
| Attack-surface summary | Persisted recon, API endpoint, and graph records | Descriptive inventory only. |
| Screenshots | Persisted screenshot artifacts, if the deployment supports them | Current deployment has no screenshot artifact store, so exports state that none are available rather than creating new captures. |

## Exploitation Breakpoints

The report identifies at most five already-prioritized entry points. Each breakpoint contains the affected subject, risk and evidence context, and a high-level explanation of why remediation should be prioritized.

> Breakpoints deliberately omit payloads, commands, attack chains, authentication bypasses, exploit code, and procedural instructions. They are triage context, not exploitation guidance.

## Export Guarantees

JSON is the full unified report representation. SARIF 2.1.0 maps each persisted technical finding to a rule and result with a severity-derived level. PDF is a portable text-only rendering of the same redacted report, generated in memory without target access or file persistence. All outputs preserve redaction for values or field names that indicate credentials or secrets.
