# Extension 13 — Multi-Agent Investigation Orchestrator

## Purpose

Extension 13 evolves the persisted task graph into an **event-driven, dependency-aware orchestration layer**. It coordinates Recon, HTTP, Configuration, API, Vulnerability, Secrets, CVE Intelligence, Evidence, Correlation, Risk, and Report work without introducing active exploitation or widening a scan’s approved target scope.

## Execution Contract

| Concern | Contract |
| --- | --- |
| Triggering | A task is released only when its persisted task dependencies are terminal **and** its persisted output events are present. Events are idempotent by scan/task/event key. |
| Parallelism | Independent work is dispatched by queue and is bounded per scan and per queue. Dependent work is released by durable output events rather than a forced sequential pipeline. |
| Example flow | Recon and API Intelligence can run after collection. Their `AGENT_OUTPUT_READY` events release the API Agent only after the required HTTP/recon signals are available. Candidate-producing agents then release Evidence; Evidence releases Correlation; Correlation and Evidence release Risk; Diagnosis and Synthesis update the Report. |
| Safety | Before every task action, the orchestrator revalidates stored authorization expiry, profile, current profile policy, hostname, and path scope. A scope or policy violation fails closed without retrying the action. |
| Resource budgets | Each scan persists a task-dispatch budget, a per-queue active-task limit, task timeout, and current usage. A budget exhaustion is terminal for the affected task and is recorded as a budget event. |
| Reliability | Task keys remain unique per scan. Worker deadlines and heartbeats feed stale recovery. Cancellation prevents queued tasks from dispatching, while retries use the stored retry budget. |
| Isolation | Dependencies, events, budgets, and task lookups are all scoped to one scan ID. No event emitted by one target can release work for another target. |

## Event Semantics

The task graph stores requirements using `event:<task-key>:AGENT_OUTPUT_READY`. A successful task emits this event with an idempotency key. Events describe persisted-agent output, not a claim about target security. A task can only consume events emitted by dependencies in the same scan.

The following output sequence is the normal investigation path, while unrelated work remains eligible for parallel execution:

1. Collection emits `COLLECTION_READY` through its normal task completion and unlocks Recon, HTTP, Technology, Structure, API Intelligence, Network Intelligence, Content, and browser-derived work.
2. HTTP, Recon, and API Intelligence emit durable agent-output events. The API Agent waits for its required inputs; Configuration, Security, and Secrets wait for HTTP output.
3. Candidate agents emit output events. Vulnerability waits for HTTP, Security, Configuration, and API output. Evidence waits for all evidence-producing input events.
4. Evidence emits a validation event; Correlation refreshes the persisted graph; Risk recalculates transparent priorities; Diagnosis and Synthesis update the report.

> The graph is an investigation and prioritization artifact only. Events do not authorize any new network action, exploitation, authentication attempt, or scope expansion.

## Visibility

The existing progress endpoint reports each task’s event requirements, deadline, retry state, dependency state, event history, current budget, and selected orchestration state. The UI can render these values as a live investigation timeline without relying on transient worker memory.

## Operational Boundaries

The deployed service should use its durable queue worker configuration for production execution. The local inline dispatcher is a development fallback, and stale-task recovery remains available through the worker health endpoint. Extension 13 does not add a separate always-on worker or a polling service.
