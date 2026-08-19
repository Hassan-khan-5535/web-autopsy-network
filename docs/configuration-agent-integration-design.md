# Extension 4 — Configuration Agent integration design

## Scope

The Configuration Agent is a deterministic, read-only rule engine over persisted `HTTPObservation`, `HTTPResponse`, `Header`, `Page`, and existing resource/evidence records. It does not issue additional requests, submit forms, authenticate, exploit, or probe paths outside the existing scan scope. Findings are stored in the existing `SecurityFinding` table under the additive `configuration` category so the existing report and diagnosis pipelines remain reusable.

## False-positive policy

Rules execute only when their prerequisites are satisfied. A generic missing header is not reported as a high-impact compromise. Stronger findings require explicit combinations such as wildcard CORS plus credentials, a confirmed directory-index marker, a successful response at a sensitive artifact path, a session-like cookie with explicitly public caching, or a verbose error signature in a server-error response. Transport-only TLS data is never used to claim certificate, cipher, or protocol weaknesses that were not captured.

## Rule catalog

| Rule ID | Prerequisites and detection logic | Evidence requirement | Severity / confidence | Remediation and references |
| --- | --- | --- | --- | --- |
| `CFG-HEADERS-001` | Successful HTML response with at least two missing baseline headers among CSP, HSTS on HTTPS, X-Content-Type-Options, and X-Frame-Options. | HTTP security-policy observations and status/content-type observation. | Medium / 0.98 observed. | Deploy a context-appropriate baseline policy; avoid unsafe framing and MIME sniffing. CWE-693; OWASP Secure Headers. |
| `CFG-CORS-001` | Response explicitly contains `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true`. No origin-reflection claim is made. | CORS observation containing both values. | High / 0.99 observed. | Replace wildcard origin with an explicit allowlist and review credentialed cross-origin design. CWE-942; OWASP CORS. |
| `CFG-TLS-001` | A successful response for a sensitive-looking path is served over `http://`. | Status and TLS transport observations plus the scoped page URL. | High / 0.99 observed. | Redirect sensitive workflows to HTTPS and enforce HSTS after validation. CWE-319; OWASP A02. |
| `CFG-TLS-002` | HTTPS response on a sensitive-looking path has missing HSTS or a max-age below one year. | TLS and security-policy observations. | Medium / 0.96 observed. | Configure HSTS with an appropriate lifetime after confirming HTTPS coverage. CWE-319; OWASP A02. |
| `CFG-DIR-001` | Successful HTML response contains a strong directory-index marker such as `Index of /` or `Directory listing for`, plus listing-style links. | Stored response body excerpt and status/content-type evidence. | High / 0.99 observed. | Disable autoindexing or restrict directory access. CWE-548; OWASP A05. |
| `CFG-EXPOSED-ARTIFACT-001` | In-scope successful response path matches `.git/config`, `.env`, known config files, or backup/archive suffixes, and the response is not a generic HTML fallback. | URL, status, content-type, and bounded body marker when available. | High for `.git/.env`, medium for backup/config artifacts / 0.96–0.99. | Remove artifacts from web roots, deny access, rotate exposed secrets, and verify deployment packaging. CWE-530/CWE-538; OWASP A05. |
| `CFG-ERROR-001` | 5xx response contains a bounded strong verbose-error signature such as traceback, stack trace, exception class, SQLSTATE, or framework debug marker. | Error status and redacted body excerpt. | High / 0.98 observed. | Disable production debug output and return generic error pages while logging server-side. CWE-209; OWASP A05. |
| `CFG-CACHE-001` | Session-like cookie is set while cache metadata explicitly allows public/shared caching or `s-maxage`. | Redacted cookie attributes plus cache observation. | High / 0.98 observed. | Mark personalized responses private/no-store and review CDN cache keys. CWE-525; OWASP A05. |
| `CFG-DISCLOSURE-001` | Response explicitly discloses a versioned `Server` or `X-Powered-By` header. | Header observation with the safe, bounded value. | Low / 0.98 observed. | Remove unnecessary product/version disclosure at the edge. CWE-200; OWASP A05. |
| `CFG-COOKIE-001` | Session-like cookie lacks HttpOnly, lacks Secure on HTTPS, or uses SameSite=None without Secure. | Redacted cookie observation with attributes and transport scheme. | Medium / 0.99 observed. | Set HttpOnly, Secure, and an appropriate SameSite policy. CWE-614/CWE-1004; OWASP A05. |
| `CFG-HTTP-001` | Stored response explicitly advertises unsafe `TRACE`, `CONNECT`, or `DEBUG` in an `Allow`/method capability header. | Header observation containing the method token. | Medium / 0.98 observed. | Disable unsafe methods at the server, proxy, and application layers. CWE-749; OWASP A05. |

Every rule has a stable metadata record with prerequisites, detection description, evidence requirements, severity, confidence, remediation guidance, and references. Findings preserve the rule ID/version and structured evidence IDs so the Evidence, Correlation, Risk, and diagnosis layers can consume them without scraping prose.
