
## Live verification

The public scan form at `https://3001-iuz98nix5x3egg8bbruc3-2761d934.us2.manus.computer/scans` rendered successfully after the HTTP Agent deployment. Existing target, profile, scope, rate-limit, robots, authentication, and Recon Agent controls remained available.

A real authorized Python.org scan completed as `d028a1ac-2849-4b0a-a8a5-b3a028b11466`. The scan reached `COMPLETED` with 100% progress, `requests_used=5` of `max_requests=8`, and the `http_agent` task succeeded on attempt 1. The API returned `rule_version=phase3-http-v1`, 91 HTTP observations, 9 observation types, 0 redacted flags in this unauthenticated target, and 0 truncation flags. The observed types included status code, headers, cache, content type, TLS, CORS, compression, security policy, and redirects.

The live report displayed the HTTP Agent section, observation counts, behavior-type chips, bounded table values, transport-only TLS limitation, response-header-only CORS limitation, and the statement that no additional target requests were issued.
