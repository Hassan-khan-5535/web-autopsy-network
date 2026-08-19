# Extension 15 — API, CLI, and Premium Dashboard

## Platform Contract

Extension 15 makes the existing persisted assessment system easier to operate without changing its authorization model. The capability catalog is machine-readable and describes the existing scan creation, scope, status, progress stream, assets, evidence, findings, graph, comparison, report, and export paths.

| Surface | Design |
| --- | --- |
| API | `GET /v1/capabilities` documents available operations and safety boundaries. The platform dashboard and filtered findings routes aggregate persisted data only. |
| CLI | The CLI only calls the platform API; it never contacts targets. Scan creation requires `--authorized`, preserves existing profile/scope limits, and accepts authentication only from an owner-readable JSON file. |
| Dashboard | The product home becomes a portfolio pulse for recent scans, active work, deterministic risk, posture availability, and direct report access. Detailed reports retain live agent activity, graph, evidence, trend, regression, and export controls. |
| Findings | The API and report workbench support severity and minimum-confidence filtering. Drill-down remains evidence-first and redaction-preserving. |

## Safety

No Extension 15 route or CLI command authorizes a new target action outside the existing admission, authorization, profile, scope, or rate-limit controls. The CLI does not print authentication material. Dashboard views and exports only read persisted scan data.
