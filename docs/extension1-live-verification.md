# Extension 1 live verification

The restarted standalone frontend was opened at the public port-3001 URL on 2026-08-19.

The new scan form rendered the target URL/domain input, Safe/Normal/Aggressive profile selector, profile-specific bounds, maximum depth/pages/requests, concurrency, per-host rate limit, allowed domains, allowed paths, excluded paths, robots override warning, optional Cookie/Header/Basic authentication controls, test-account reference, and explicit authorization acknowledgement.

A real non-destructive scan of `https://www.python.org/` completed successfully with scan ID `97eeaf24-654a-46e5-aca0-2d65e1a27a0d`.

The live progress endpoint reported `COMPLETED`, lowercase status `completed`, 100 percent, 17 terminal tasks, and a 29-second total duration. The recorded authorization endpoint showed the Safe profile, actor `extension1-verification`, target `https://www.python.org/`, allowed domain `python.org`, allowed path `/`, excluded paths `/admin` and `/logout`, 8 requests, concurrency 1, 1000ms per-host rate limit, robots respected, authentication not configured, policy `assessment-v1`, and consent-hash prefix `f862d0c7`. The audit endpoint returned an `AUTHORIZATION_RECORDED` event with a chained hash and no credential material.

The completed report page visibly rendered the `Scope & consent record` panel above the existing report and live-progress sections. Existing report sections, phase timeline, 100 percent progress, cause-of-death navigation, and evidence sections remained present.
