# Agent and UI Verification

Date: 2026-08-19

Verified against real completed scan `00184207-b235-473a-8d5c-4b2cffe430e4` for `https://www.python.org/`.

All audited report endpoints returned HTTP 200: scan, progress, evidence, pages, technologies, architecture, dependencies, API endpoints, recon, HTTP observations, configuration, security, performance, accessibility, content, diagnosis, risk, authorization, and audit.

Persisted data counts were: 20/20 terminal tasks and 16 task types at 100% completion; 711 evidence records; 5 pages; 1 technology detection; 64 dependencies; 0 API endpoint records; 323 recon assets, 11 recon endpoints, and 32 parameters; 153 HTTP observations; 11 Configuration Agent rules with 0 findings; 52 security findings; 139 performance metrics; 22 accessibility findings; 11 content findings; 234 risk findings; and one authorization audit record.

The live UI rendered navigation and report sections for Cause of Death, AI Doctor, History, Dependencies, Architecture, HTTP Agent, Recon Agent, API Intelligence, Technology DNA, Performance, Configuration, Security, Accessibility, Content & SEO, and Raw Evidence. The Configuration Agent section displayed ruleset `phase4-config-v1`, 11 rules, zero matched findings, severity counters, a rule catalog, and the limitation that zero findings are not a guarantee of security.

The progress panel displayed all task types and `COMPLETED` at 100%. One worker heartbeat-expiry/retry event was visible in the execution activity, but the affected task recovered and ultimately reached `SUCCEEDED`; there were no terminal task failures.

Empty API Intelligence data is an honest result for this bounded Python.org scan, not a UI failure. Likewise, zero Configuration findings means no rule prerequisites were met by the stored evidence, not that the target is secure.


A live DOM inspection confirmed all expected section IDs exist and contain rendered text. The browser’s direct `fetch('/api/v1/scans/{scan_id}/configuration', {cache: 'no-store'})` returned HTTP 200 and `phase4-config-v1` with 11 rules and zero findings. One DOM text snapshot unexpectedly showed `phase4-config-v10` while the current public API and the Configuration section screenshot showed `phase4-config-v1`; this appears to be a stale/hydration/cache artifact and must be cleared and rechecked before treating UI verification as fully consistent.


After refreshing the live report, the visible Configuration Agent card displayed the current `phase4-config-v1` ruleset, 11 rules, and 0 findings. The public API also consistently returned `phase4-config-v1`. The earlier `phase4-config-v10` DOM snapshot was transient and was not reproduced in the refreshed visible report.
