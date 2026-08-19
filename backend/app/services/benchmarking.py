"""Ground-truth metric calculations for controlled Web Autopsy benchmarks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ConfusionMetrics:
    true_positive: int
    false_positive: int
    false_negative: int
    precision: float | None
    recall: float | None
    false_positive_rate: float | None
    false_negative_rate: float | None

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def set_metrics(expected: set[str], observed: set[str], universe: set[str] | None = None) -> ConfusionMetrics:
    """Evaluate exact identifiers against explicit ground truth, never inferred labels."""
    true_positive = len(expected & observed)
    false_positive = len(observed - expected)
    false_negative = len(expected - observed)
    precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) else None
    recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) else None
    negatives = (universe or set()) - expected
    false_positive_rate = false_positive / len(negatives) if negatives else None
    false_negative_rate = false_negative / len(expected) if expected else None
    return ConfusionMetrics(true_positive, false_positive, false_negative, precision, recall, false_positive_rate, false_negative_rate)


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    truth = case.get("ground_truth")
    observed = case.get("observed")
    if not isinstance(truth, dict) or not isinstance(observed, dict):
        raise ValueError("Benchmark case requires ground_truth and observed objects.")
    metrics: dict[str, Any] = {}
    for category in ("assets", "endpoints", "findings", "cve_matches", "secrets", "differential_changes"):
        expected_values = truth.get(category)
        observed_values = observed.get(category)
        if expected_values is None or observed_values is None:
            metrics[category] = {"status": "not_measured", "reason": "No controlled ground truth and observed output supplied."}
            continue
        if not expected_values and not observed_values and not truth.get(f"{category}_universe"):
            metrics[category] = {"status": "not_measured", "reason": "No positive or negative ground-truth cases were supplied for this category."}
            continue
        result = set_metrics(set(expected_values), set(observed_values), set(truth.get(f"{category}_universe", [])))
        metrics[category] = {"status": "measured", **result.as_dict()}
    resources = observed.get("resources", {})
    has_execution_measurement = any(resources.get(key) is not None for key in ("scan_duration_ms", "requests_used", "max_concurrency_observed"))
    metrics["execution"] = {
        "status": "measured" if has_execution_measurement else "not_measured",
        "scan_duration_ms": resources.get("scan_duration_ms"),
        "requests_used": resources.get("requests_used"),
        "max_concurrency_observed": resources.get("max_concurrency_observed"),
        "reliability": resources.get("reliability") if has_execution_measurement else None,
    }
    return {"case_id": case.get("id"), "ground_truth_revision": case.get("ground_truth_revision"), "metrics": metrics, "limitations": case.get("limitations", [])}


def evaluate_suite(suite: dict[str, Any]) -> dict[str, Any]:
    if suite.get("schema_version") != "web-autopsy-benchmark-v1":
        raise ValueError("Unsupported benchmark schema version.")
    cases = suite.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("Benchmark suite must contain at least one case.")
    return {"schema_version": "web-autopsy-benchmark-result-v1", "suite_id": suite.get("suite_id"), "suite_revision": suite.get("suite_revision"), "claims_boundary": "Controlled-case measurements only; not a state-of-the-art or general-production claim.", "cases": [evaluate_case(case) for case in cases]}
