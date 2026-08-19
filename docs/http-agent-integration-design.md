# Extension 3 — HTTP Agent integration design

## Purpose

The HTTP Agent is a deterministic, read-only analysis worker over the HTTP artifacts already collected by the bounded crawler and browser worker. It does not create a second crawler or issue new target requests. Its output is a reusable normalized observation stream for configuration, API, vulnerability, evidence, correlation, and risk processing.

## Reusable inputs

The agent consumes `Page`, `HTTPResponse`, `Header`, `Resource`, `PageLink`, and existing `Observation` records. Static collection already stores status code, final URL, content type, elapsed time, bounded HTML body, response headers, redirects, and browser timing data. A small additive `redirect_chain` field on `HTTPResponse` makes redirect analysis structured instead of dependent on human-readable observations.

## Normalized observation contract

Each `HTTPObservation` belongs to a scan and may reference a page. It contains an observation type, subject, source, classification, confidence, bounded JSON value, redaction/truncation flags, a deduplication key, and creation time.

| Observation type | Stored analysis |
| --- | --- |
| `status_code` | HTTP status, final URL, requested URL, elapsed time, and availability band |
| `header` | Header name, normalized safe value or presence-only redaction, and duplicate count |
| `cookie` | Cookie name and security attributes only; cookie values are never persisted |
| `redirect` | Ordered source/target chain with query values redacted and same-scope status |
| `cache` | Cache-Control directives and validators such as ETag, Last-Modified, Age, Vary, and CDN cache signals |
| `content_type` | Media type, charset, body capture size, and truncation state |
| `tls` | HTTPS transport observation and explicit limitation that certificate/cipher details were not captured |
| `cors` | Observed Access-Control-* response policy, without claiming origin validation because no origin matrix was sent |
| `compression` | Content-Encoding, Transfer-Encoding, Content-Length, and captured-body size |
| `security_policy` | CSP, HSTS, framing, MIME-sniffing, referrer, permissions, and legacy XSS policy headers |
| `response_anomaly` | Bounded anomaly statements such as error responses, missing content type, body truncation, redirect scope mismatch, or contradictory metadata |

## Redaction and limits

Header names matching authorization, cookie, token, API-key, CSRF, proxy-authorization, or secret patterns are represented by `present`, length, and a stable non-reversible category marker; their values are not stored. `Set-Cookie` values are parsed into names and attributes without values. URL query and fragment values are replaced with `[REDACTED]` while retaining parameter names. Safe header excerpts are limited to 512 characters. Observation JSON is capped at 8 KiB and evidence excerpts at 512 characters. The agent analyzes the stored bounded response body but never persists arbitrary body content.

## Downstream compatibility

The existing security analyzer continues to produce its established findings. HTTP observations are additive and can be consumed by later agents without changing existing finding contracts. Existing scans continue to run because the HTTP task only reads already persisted artifacts and legacy rows receive an empty-but-successful HTTP observation result when no response exists.

## TLS boundary

The static HTTP collector records whether the observed URL used HTTPS. It does not perform a second TLS handshake or store certificate/cipher material, because doing so would duplicate network collection and bypass the scan-wide admission and request budget. Certificate-chain and cipher auditing remain an explicit future extension.

## Safety boundary

No form is submitted, no method other than the existing bounded crawler requests is issued, no credentials are exposed, and no finding claims exploitability. All observations retain whether they are `OBSERVED` or `INFERRED`, the source artifact, and any relevant limitation.
