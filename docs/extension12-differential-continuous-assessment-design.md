# Extension 12 — Differential & Continuous Assessment Design

## Purpose

Extension 12 compares completed scans of the same persisted website and records an evidence-backed security-posture timeline. It also supports weekly recurring scans through the existing scan queue. The feature is designed for investigation and prioritization only; it does not add active exploitation, new unapproved scope, or autonomous authentication changes.

## Differential posture contract

The comparison engine will preserve the existing same-target and completed-scan preconditions. It will extend the persisted comparison with the following categories: asset additions and non-observation, technology changes, endpoint changes, selected security-header changes, security-finding changes, configuration regressions, newly exposed secret findings, vulnerability changes, severity changes, and deterministic risk-score changes.

Every comparison item will retain the source records from both scans. A missing observation in the newer scan is classified as `INFERRED` and explicitly does not prove an asset, technology, vulnerability, secret, or finding has been resolved.

## Historical security posture timeline

Each completed scan will receive a compact posture snapshot. A snapshot contains the deterministic overall risk score and band, observed counts for relevant posture categories, the current comparison baseline where available, and a timestamp. The report timeline shows the ordered same-target snapshots, score movement, and comparison summaries.

## Approved recurring-scan model

The implementation uses the approved **Option A** model: persisted schedules plus a lightweight schedule checker. The checker is intentionally separate from scan analysis; when invoked by a periodic trigger, it finds due schedules and submits ordinary scans through the existing `TaskGraphCoordinator` and dispatcher.

The default cadence is **weekly**. A deployment can invoke the schedule-checker command or API on a bounded periodic trigger. The service remains stateless between invocations; scan execution continues through the existing queue.

## Mandatory gates before every scheduled run

Before it creates a scan, the schedule checker must confirm all of the following from the stored source authorization and current configured policy:

1. The schedule is enabled and due.
2. The source authorization exists and has not expired.
3. The target URL is normalized and still belongs to the stored allowed domains and paths.
4. The stored assessment profile and limits still pass the current policy.
5. The recurring run uses the stored scope only. It cannot expand domains, paths, authentication, request limits, or assessment intensity.

If any gate fails, the schedule is blocked, the reason is persisted, no scan is created, and an audit event is recorded. A newly created recurring scan gets a copied authorization record and its own audit trail.

## Safety boundary

Recurring assessment is limited to the existing authorized scan modes. The schedule checker makes no direct target request and cannot change scope. It will not use an opaque model to decide whether a target is safe to scan. The configured real test target is `https://www.w3schools.com/`, subject to the stored authorization and passive scope at the time of each run.
