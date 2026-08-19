import json
from pathlib import Path

from app.services.benchmarking import evaluate_suite, set_metrics
from benchmarks.local_target import run_local_target_benchmark


def test_confusion_metrics_measure_precision_recall_and_rates_only_against_explicit_truth():
    result = set_metrics({"a", "b"}, {"a", "x"}, {"a", "b", "x", "y"})
    assert result.true_positive == 1
    assert result.false_positive == 1
    assert result.false_negative == 1
    assert result.precision == 0.5
    assert result.recall == 0.5
    assert result.false_positive_rate == 0.5
    assert result.false_negative_rate == 0.5


def test_controlled_suite_is_versioned_reproducible_and_does_not_make_general_claims():
    suite_path = Path(__file__).resolve().parents[1] / "benchmarks" / "controlled-suite-v1.json"
    result = evaluate_suite(json.loads(suite_path.read_text(encoding="utf-8")))
    case = result["cases"][0]
    assert result["schema_version"] == "web-autopsy-benchmark-result-v1"
    assert "general-production claim" in result["claims_boundary"].lower()
    assert case["metrics"]["assets"]["recall"] == 1.0
    assert case["metrics"]["findings"]["precision"] == 0.5
    assert case["metrics"]["findings"]["recall"] == 0.5
    assert case["metrics"]["cve_matches"]["status"] == "not_measured"


def test_local_intentionally_vulnerable_target_measures_discovery_and_execution_without_external_egress():
    result = run_local_target_benchmark()
    assert result["metrics"]["assets"]["recall"] == 1.0
    assert result["metrics"]["endpoints"]["recall"] == 1.0
    assert result["metrics"]["execution"]["reliability"] == "completed"
    assert result["metrics"]["execution"]["requests_used"] <= 8
