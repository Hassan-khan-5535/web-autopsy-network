# Extension 4 Live Verification

Date: 2026-08-19

The rebuilt public frontend loaded successfully at the live project URL. The authorized verification scan targeted `https://www.python.org/` with the safe profile, explicit domains `python.org` and `www.python.org`, root-path scope, `/downloads/` exclusion, maximum depth 1, maximum 5 pages, maximum 10 requests, one worker, 500 ms per-host delay, robots respected, passive-only recon, and actor `authorized-research-verification`.

Scan ID: `00184207-b235-473a-8d5c-4b2cffe430e4`.

The scan completed at 100% with state `COMPLETED`, status `completed`, `requests_used` 7, and no error. Every task reached `SUCCEEDED`, including `http_agent`, `configuration`, `security`, `recon`, `diagnosis`, and `synthesis`. The Configuration Agent endpoint returned 11 rule metadata records under ruleset `phase4-config-v1`, with zero findings and zero high/medium/low findings. The report correctly states that no rules met prerequisites and that this is not a guarantee the target is secure.

The public report page exposed the Configuration navigation entry, the Configuration Agent section, the 11-rule catalog, severity summary cards, and the passive-evidence disclaimer. Direct public API access to `/api/v1/scans/{scan_id}/configuration` returned HTTP 200 with the same ruleset and summary.
