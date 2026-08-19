# Extension 6 — Vulnerability Agent Live Verification

Date: 2026-08-19

A fresh authorized bounded scan targeted `https://www.python.org/` with safe profile, explicit domains `python.org` and `www.python.org`, root-path scope, `/downloads/` exclusion, maximum depth 1, maximum 5 pages, maximum 10 requests, one worker, robots respected, passive-only recon, and actor `authorized-extension6-verification`.

## Definitive verification

Scan ID: `7bf7efeb-6824-4b01-bbba-95f50a230f6b`.

The scan completed with `COMPLETED` state, `completed` status, 100% progress, 22/22 terminal tasks, 18 task types, `requests_used: 7`, and no error. The `vulnerability` task reached `SUCCEEDED` with declared dependencies `collection`, `security`, `configuration`, `api_agent`, and `http_agent`.

The Vulnerability Agent API returned ruleset `phase6-vuln-v1`, 12 rule metadata records, 10 detector plugins, zero findings, and safe-validation counters of zero network requests, zero payloads, zero form submissions, zero mutating requests, and zero authentication attempts. The empty result is valid for this bounded Python.org evidence and is not a security guarantee.

The live frontend displayed the Vulnerability Agent navigation entry and report section. It showed the current ruleset, zero severity counters, the explicit safe-validation contract, the honest empty-state limitation, and all 12 independently testable detector templates. The live progress report displayed `Vulnerability analysis — SUCCEEDED` and `22/22 terminal tasks`.

## False-positive correction

An earlier verification run exposed an overbroad stored-XSS heuristic that treated ordinary `<script>` tags and generic `javascript:` accessibility links as stored-XSS indicators. The detector was corrected to require high-signal explicit markers such as dangerous inline handlers containing `alert`, `document.cookie`, or `eval`, dangerous `javascript:` calls, or explicit dangerous script markers. Controlled fixtures still cover high-signal stored-XSS detection, and the definitive Python.org scan now produces zero stored-XSS findings.

## Safety and validation

The implementation is detection-only. It does not send exploit payloads, probe routes, authenticate, submit forms, replay requests, perform identifier substitution, mutate target state, or provide exploit chains. Full validation passed after the correction: Python compilation, 92 backend tests, frontend lint, TypeScript checking, production build, and Alembic head `20260819_extension3`.
