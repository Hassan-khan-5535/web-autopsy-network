# Extension 19 — Targeted Production Review

**Review status:** Complete for the codebase at the Extension 19 release boundary.  
**Review approach:** Targeted, evidence-backed engineering review; not a penetration test, a guarantee of absence of defects, or authorization to assess any third-party target.  
**Assessment constraints:** All scanner activity remains authorization-gated, scope-limited, deterministic where scoring is involved, and limited to non-exploitative evidence collection.

> This review intentionally avoids a broad rewrite. Its code changes address verified production defects and hardening gaps: a graph-write race, permissive browser-worker admission, wildcard CORS configuration, production defaults for signing keys, root container execution, and public browser-worker exposure in the development composition.

## Scope and Review Method

The review examined compatibility from the foundation through Extensions 10–18, with particular attention to the safety contracts introduced by continuous assessment, orchestration, reporting, update packages, scanner isolation, and benchmark validation. It combined source inspection of contracts and persistence paths with targeted regression tests, the complete backend suite, and a clean production frontend build. This work did not run a new remote scan; the project’s standing authorized test target remains the user-specified `https://www.w3schools.com/` and persisted real scan identifiers only.

| Review area | Evidence reviewed | Result |
|---|---|---|
| Scope, authorization, profiles | Assessment policy, scope gates, recurring-scan conditions, orchestrator task contracts | Retained as fail-closed boundaries; no scope expansion was added. |
| SSRF, redirects, hostile browser content | Transport revalidation, browser request routing, final-URL check, output budgets | Browser-worker admission was strengthened and direct regressions added. |
| Isolation and credentials | Per-scan identifiers, redaction, worker inputs, container runtime users | Application-level isolation improved; infrastructure controls remain a deployment responsibility. |
| Queue and database reliability | Task graph coordination, graph uniqueness constraints, correlation persistence | A verified duplicate-key race now recovers through a savepoint and canonical-row reread. |
| API and reports | FastAPI router, CORS middleware, typed frontend API client, reporting/export services | CORS now follows explicit configuration; existing evidence and redaction contracts remain in place. |
| Update lifecycle | Signed package validation, activation, rollback, local fallback | Existing signed, schema-validated, rollback-capable lifecycle retained. |
| Performance and reproducibility | Extension 18 benchmark record, bounded settings, Compose and Dockerfiles | Limits are documented; the tracked Compose file is explicitly development-only. |

## Findings and Targeted Remediation

### 1. Correlation graph duplicate-key race — remediated

Two concurrently scheduled correlation tasks could observe the same graph entity or relationship as absent, then race to create the same unique row. The resulting `IntegrityError` could propagate and mark otherwise usable scans as partially failed. `CorrelationAgent` now performs node and edge creation inside `Session.begin_nested()` savepoints. If a unique constraint wins elsewhere, it rereads the canonical row, merges refreshed metadata, and continues the enclosing scan transaction. The dedicated regression test reproduces a stale second writer for both a node and a self-edge and verifies that each resolves to exactly one stored row. [1]

### 2. Browser-worker scope and output boundary — remediated

The worker now accepts strict request models that reject undeclared fields. A render request carries domain, path allowlist, excluded-path, page and scan identity fields, and bounded resource/output settings. It blocks credential-bearing URLs and non-HTTP(S) schemes, rejects private, loopback, link-local, multicast, reserved, and documentation-test networks, resolves the hostname before navigation, intercepts every subrequest, and revalidates the final URL after redirects. Rendered HTML, network-event records, and console records are bounded; console text and errors pass through sensitive-value redaction. [2]

The browser contract is deliberately restrictive: a caller must supply the approved scope from the persisted scan flow. These controls remain investigatory safeguards and do not create an authorization boundary for an Internet-exposed worker; the worker must be kept private to trusted application services.

### 3. Production secrets and CORS configuration — remediated

`Settings.validate_production_security()` prevents an application configured as `production` or `prod` from starting with default or short JWT/update-package HMAC keys or a wildcard CORS origin. FastAPI CORS middleware now consumes the explicit comma-separated setting rather than using an unconditional wildcard. Dedicated tests cover both failure of unsafe production defaults and acceptance of strong keys plus a concrete allowed origin. [3] [4]

### 4. Container privilege and service exposure — remediated

The backend and browser-worker images now install dependencies as root only during image construction, create an application account, copy application files with that ownership, and run the service as that unprivileged account. The checked-in Compose stack no longer publishes the browser-worker port to the host; the backend accesses it through the internal Compose network. [5] [6] This reduces accidental local exposure but does not replace a production network policy.

## Control Review Record

| Control | Review conclusion | Operational interpretation |
|---|---|---|
| Scope enforcement | Pass with documented boundary | Assessment, agent, recurring-scan, and browser controls must receive persisted allowed domains/paths; callers may not widen them ad hoc. |
| Authorization auditability | Pass by design review | Stored authorization and task/event records remain the authoritative audit trail. Authorization expiry is intended to fail closed for recurring work. |
| SSRF and DNS/redirect handling | Pass for application controls | URL and redirect revalidation blocks private and disallowed destinations. Production must additionally enforce network egress at the platform boundary. |
| Scan isolation | Pass with infrastructure dependency | Per-scan state, page identity, bounded outputs, and non-forwarding credentials mitigate cross-scan leakage; containers and networks still need external isolation. |
| Secret handling | Pass with limits | Secret-like text is redacted from worker errors and logs; raw secrets must never be introduced into scope, evidence, reports, or environment files. |
| Authentication and API authorization | Retained | Existing authentication dependencies and scan ownership enforcement remain unchanged. CORS no longer bypasses configured origin policy. |
| Queue reliability | Pass for reviewed code | Orchestration uses events, idempotency keys, budgets, timeout/retry controls, and cancellation states. Delivery semantics depend on the selected Redis/Celery deployment. |
| Observability | Pass for reviewed code | Structured request completion logging, task event records, reports, graph updates, and benchmark artifacts provide diagnostic evidence; an external log sink and alerting are still required in production. |
| Database integrity | Improved | Unique graph records now recover from concurrent creation races. Production must use PostgreSQL and apply the repository’s Alembic migrations before application startup. |
| API contracts | Pass by build/test review | The API router and typed frontend client retain their existing contracts; strict worker Pydantic contracts reject unexpected request fields. |
| Report correctness | Pass by compatibility review | Reporting preserves evidence classification, redaction, uncertainty, and high-level non-exploitative breakpoint language. |
| Update-package security | Pass by existing design review | Packages require signature/schema/compatibility validation, retain provenance and timestamps, support staged checks and rollback, and fall back locally if feeds are unavailable. |
| Performance/resource control | Pass with enforced-limit caveat | Application limits bound requests and artifacts. CPU/memory values are propagated in the worker contract, but hard CPU/memory limits require container-orchestrator enforcement. |
| Deployment reproducibility | Documented gap | The current Compose file is a development stack, not a production manifest; source mounts and development commands intentionally override the images. |

## Agent, Rule, and Data-Model Reference Map

The platform’s agent and rule boundaries are deliberately documented in focused design records rather than duplicated here. The following documents remain the normative component references, while this review records only production implications.

| Component family | Normative design / implementation reference | Production-review note |
|---|---|---|
| Recon, HTTP, configuration, API, vulnerability, secret, CVE, evidence agents | Integration design records under `docs/` and the agent services | Their outputs must remain classified, scope-bound, bounded, and persisted before correlation/risk/report use. |
| Correlation and attack-surface graph | Extension 10 design and `CorrelationAgent` | Graph relationships are prioritization aids, never exploit paths or proof of exploitability. [1] [7] |
| Risk prioritization | Extension 11 design and risk service | Components remain deterministic and transparent; opaque models may not override validated evidence. [8] |
| Differential and continuous assessment | Extension 12 design and continuous service | Recurring work is limited to the safe profile and must revalidate stored authorization and current scope. [9] |
| Event-driven orchestrator | Extension 13 design and task services | Dependencies, retries, cancellation, idempotency, timeout and resource budgets remain scan-scoped. [10] |
| Reports and exports | Extension 14 design and reporting service | PDF, JSON, and SARIF outputs must preserve evidence classification/redaction and omit exploit steps. [11] |
| API, CLI, dashboard | Extension 15 design, API router, frontend client | User flows use persisted scan UUIDs; no demo-route or static report shortcut is permitted. [12] |
| Update packages | Extension 16 design and update service | Offline built-ins remain a safe fallback when a verified package cannot be activated. [13] |
| Scanner isolation | Extension 17 design, scanner-security service, browser worker | Application checks complement—not replace—network policy, sandboxing, and resource quotas outside the process. [2] [14] |
| Benchmarks | Extension 18 protocol and controlled baseline | Benchmarks are reproducible controlled measurements, not a claim of state-of-the-art performance. [15] [16] |

The principal persistence model remains the scan-centered SQLAlchemy schema: scan records own pages, observations, assets, findings, evidence/reviews, graph updates, risk and posture records, and report artifacts. Graph node and edge natural keys provide the canonical association model; update records provide a history of incremental correlation runs. The new regression test specifically verifies the unique-key recovery behavior of that model. [1] [17]

## API and Configuration Guidance

The public API is versioned under the configured prefix and its capability catalog, scan lifecycle, graph, comparison, and export routes are documented in `docs/API.md` and the Extension 15 design. Browser-worker `/render` is an internal service interface, not a public API; it should be reachable only from the backend/authorized queue workers. [12] [18]

| Setting group | Required production handling |
|---|---|
| `APP_ENV` | Set to `production` only when the full production secret and network configuration is present. Production startup intentionally fails on unsafe defaults. |
| `JWT_SECRET` | Supply a unique value of at least 32 characters through the secret manager; never commit it. |
| `UPDATE_PACKAGE_HMAC_KEY` | Supply a unique value of at least 32 characters through the secret manager; rotate according to the update-package trust policy. |
| `CORS_ORIGINS` | Provide concrete trusted origins as a comma-separated list. Wildcards are rejected in production. |
| `DATABASE_URL`, `QUEUE_BACKEND_URL` | Use production PostgreSQL and Redis endpoints secured through the deployment’s private network and credentials manager. |
| `BROWSER_WORKER_URL`, `BROWSER_WORKER_ALLOWED_HOSTS` | Point only to the internal worker service. Do not expose the worker through a public load balancer. |
| Scanner/browser limits | Tune only downwards without benchmark and regression evidence; maintain bounded depth, requests, redirects, bytes, events, timeouts, CPU, and memory. |
| Update-package settings | Keep signature verification enabled; retain a local cache and built-in offline fallback. |

## Deployment and Reproducibility Guidance

The tracked `docker-compose.yml` is now explicitly labeled **development-only**. Its `./backend:/app` and `./frontend:/app` mounts intentionally replace image contents, and its `--reload` and `npm run dev` commands intentionally favor iteration. It is not a reproducible production launch file and must not be promoted unchanged. [6]

A production deployment should build immutable backend, worker, and frontend images from the reviewed commit; run the database migration before admitting traffic; inject all secrets through a secret manager; use private PostgreSQL, Redis, and browser-worker networks; disable source mounts and reload commands; set resource quotas; configure outbound egress filtering; collect structured logs; and health-check all services. The service images execute as an unprivileged application account, but the surrounding platform should additionally use a read-only root filesystem where compatible, a writable temporary volume for the browser, dropped capabilities, `no-new-privileges`, a seccomp profile, non-root orchestration settings, and restrictive network policies. [5]

## Remaining Operational Limitations and Required Follow-Up

| Limitation | Risk if ignored | Required operational control |
|---|---|---|
| No checked-in production Compose/Kubernetes manifest | An operator could accidentally deploy development mounts or hot reload. | Maintain a separate immutable production manifest and review it alongside infrastructure changes. |
| Browser-worker CPU/memory fields are contract values, not OS enforcement | Hostile pages may consume more than expected if the runtime provides no cgroup quota. | Enforce CPU, memory, PID, timeout, and temporary-storage quotas at the container/orchestrator layer. |
| App-level SSRF controls cannot constrain the host network alone | A future code path or browser/runtime defect could reach an unintended network. | Use allowlisted egress/firewall/DNS policy and private service networks. |
| Browser worker has no user-facing authentication | Public exposure would permit untrusted render requests. | Keep it internal; authenticate service-to-service calls if it must cross trust boundaries. |
| External telemetry and alert routing are deployment-specific | Failures may be recorded locally but not acted upon. | Forward structured logs, metrics, traces, and health alerts to operated monitoring. |
| Benchmark evidence is controlled and synthetic | Results can be misread as real-world effectiveness claims. | Publish only measured protocols/results and repeat them after meaningful engine or rule changes. |

## Verification Record

| Check | Result |
|---|---|
| Extension 19 focused graph race, worker security, and graph correlation regressions | **12 passed**. |
| Full backend regression suite | **143 passed** in 33.28 seconds with `APP_ENV=test`; this explicit test environment avoids the intentional production startup fail-closed guard. |
| Production frontend build | **Passed**; Next.js compiled, linted, type-checked, generated static pages, and finalized build traces. |
| Browser-worker direct coverage | Scope enforcement, strict request contracts, SSRF blocking, and sensitive-error redaction covered by dedicated tests. |
| Integrity regression | Stale second writer resolves duplicate graph node and edge creation to the pre-existing canonical rows. |

## Review Conclusion

The reviewed code is suitable to advance from the Extension 18 baseline with the targeted remediations in this release. The release does **not** claim universal production readiness independent of deployment practice. A production operator must provide immutable deployment definitions, secret management, egress/network policy, container resource isolation, monitoring, migrations, and a private browser-worker path. Within those boundaries, this review confirms the targeted fixes and the existing safety contracts through the recorded regression and build results.

## References

[1]: https://github.com/atifkhani397/web-autopsy-network/blob/main/backend/app/services/correlation.py "Correlation agent graph persistence"
[2]: https://github.com/atifkhani397/web-autopsy-network/blob/main/browser_worker/app.py "Browser-worker scope and resource contract"
[3]: https://github.com/atifkhani397/web-autopsy-network/blob/main/backend/app/core/config.py "Runtime configuration and production security validation"
[4]: https://github.com/atifkhani397/web-autopsy-network/blob/main/backend/app/main.py "FastAPI application and configured CORS middleware"
[5]: https://github.com/atifkhani397/web-autopsy-network/blob/main/backend/Dockerfile "Backend non-root container runtime"
[6]: https://github.com/atifkhani397/web-autopsy-network/blob/main/docker-compose.yml "Development-only Compose composition"
[7]: https://github.com/atifkhani397/web-autopsy-network/blob/main/docs/extension10-correlation-graph-design.md "Extension 10 Correlation & Attack-Surface Graph design"
[8]: https://github.com/atifkhani397/web-autopsy-network/blob/main/docs/extension11-risk-prioritization-design.md "Extension 11 Risk & Heuristic Prioritization design"
[9]: https://github.com/atifkhani397/web-autopsy-network/blob/main/docs/extension12-differential-continuous-assessment-design.md "Extension 12 Differential & Continuous Assessment design"
[10]: https://github.com/atifkhani397/web-autopsy-network/blob/main/docs/extension13-multi-agent-orchestrator-design.md "Extension 13 Multi-Agent Orchestrator design"
[11]: https://github.com/atifkhani397/web-autopsy-network/blob/main/docs/extension14-reporting-security-posture-design.md "Extension 14 Reporting & Security Posture design"
[12]: https://github.com/atifkhani397/web-autopsy-network/blob/main/docs/extension15-api-cli-dashboard-design.md "Extension 15 API, CLI & Dashboard design"
[13]: https://github.com/atifkhani397/web-autopsy-network/blob/main/docs/extension16-template-signature-updates-design.md "Extension 16 Template / Signature Update System design"
[14]: https://github.com/atifkhani397/web-autopsy-network/blob/main/docs/extension17-scanner-security-isolation-design.md "Extension 17 Scanner Security & Isolation design"
[15]: https://github.com/atifkhani397/web-autopsy-network/blob/main/docs/extension18-benchmark-production-validation.md "Extension 18 benchmark and validation protocol"
[16]: https://github.com/atifkhani397/web-autopsy-network/blob/main/docs/benchmarks/extension18-controlled-baseline.json "Extension 18 controlled baseline"
[17]: https://github.com/atifkhani397/web-autopsy-network/blob/main/backend/app/models/scan.py "Scan-centered persistence model"
[18]: https://github.com/atifkhani397/web-autopsy-network/blob/main/docs/API.md "API contract reference"
