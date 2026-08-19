# Extension 18 — End-to-End Benchmark and Production Validation

## Controlled Benchmark Protocol

Extension 18 uses versioned, local JSON suites whose expected labels are explicit ground truth. The runner does not perform network activity. A benchmark case is valid only when the target is synthetic and local or when its authorization and captured raw output are recorded separately.

| Evaluation category | Measurement method | Current baseline status |
| --- | --- | --- |
| Asset and endpoint discovery | Exact identifier precision/recall against fixture ground truth | Metric-engine contract fixture published; target-level execution remains a separate authorized run. |
| Vulnerability, secret, CVE, and differential results | Exact rule/change identifiers against known truth and explicit negative universe | Metric-engine contract fixture published; no general scanner-accuracy claim. |
| False-positive and false-negative rates | Explicit negative universe only; otherwise reported as unavailable | Available only where the fixture enumerates negatives. |
| Validation accuracy | Compare validated versus ground-truth state | Requires a scenario-specific evidence validation oracle. |
| Duration, requests, resource use, concurrency, reliability | Recorded from a specific authorized run and its persisted scan/task metrics | Not applicable to the metric-contract fixture; must not be extrapolated. |

## Reproducibility

Run from repository root:

```bash
PYTHONPATH=backend backend/venv/bin/python backend/scripts/run_benchmark.py --exercise-local-target
PYTHONPATH=backend backend/venv/bin/python -m pytest backend/tests/test_extension18_benchmark.py -q
```

The runner writes `docs/benchmarks/extension18-controlled-baseline.json`. With `--exercise-local-target`, it starts a short-lived in-process synthetic target containing a known page and asset graph, then records measured asset/endpoint coverage, request count, duration, observed concurrency, and completion reliability. It does not contact external hosts. Its output identifies the suite and ground-truth revision, calculation method, and limitations. It intentionally does not label results state-of-the-art or representative of all websites.

## Production Validation Boundary

The existing W3Schools record is an authorized persisted integration artifact, but it ended `PARTIAL_FAILED` before later orchestration fixes. It is therefore unsuitable for publishing as a clean production accuracy baseline. A future production benchmark must use a newly authorized completed scan and preserve its authorization, scope, scanner version, update-package state, raw evidence IDs, and runtime environment alongside the result.
