# Extension 17 — Scanner Security and Isolation

Extension 17 treats every target response, redirect, browser result, and worker boundary as hostile. The scanner revalidates DNS and public-network eligibility immediately before each crawler request and each redirect target. It allows only configured HTTP(S) egress ports, checks redirect scope, and bounds headers, decompressed HTML bytes, HTML elements, requests, redirects, and timeouts.

Browser analysis is an explicit service boundary. Requests include a scan and page identity, current scope policy, egress constraints, and render/network/console budgets. Browser results are accepted only when the page belongs to the requesting scan and captured network URLs pass current admission and scope checks. Authentication is not forwarded to browser workers by default.

| Threat boundary | Control |
| --- | --- |
| SSRF, DNS rebinding, redirects | Public-IP admission and repeat resolution before every outbound attempt or redirect; configured port allowlist and current scope validation. |
| Decompression bombs and oversized HTML | Streamed decompressed byte ceiling, declared content-length rejection, allowed encoding list, header budget, and DOM element cap. |
| Hostile HTML and browser activity | Bounded parsing, browser render/event budgets, scan/page binding, and browser network-event scope filtering. |
| Credential leakage | Credential headers remain in the direct crawler path; browser forwarding is disabled by default; observations and failures redact secret-like values. |
| Cross-scan leakage | Browser page ownership is verified against the scan, and captured resources are attached only to that page. |
| Process and filesystem boundaries | The application does not execute target-controlled commands or persist target files; production browser workers must remain an internal service with per-job process/container, network namespace, read-only filesystem, and cgroup CPU/memory limits. |

The in-process code enforces request, time, content, and data boundaries. Operating-system isolation for browser workers is a deployment obligation and is documented as an internal-worker requirement rather than being simulated by application code.
