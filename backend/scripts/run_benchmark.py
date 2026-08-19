#!/usr/bin/env python3
"""Evaluate a versioned controlled benchmark suite; never issues network requests."""

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path

os.environ["DATABASE_URL"] = os.environ.get("BENCHMARK_DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.services.benchmarking import evaluate_suite
from benchmarks.local_target import run_local_target_benchmark


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a local Web Autopsy controlled benchmark suite.")
    parser.add_argument("--suite", default="backend/benchmarks/controlled-suite-v1.json")
    parser.add_argument("--output", default="docs/benchmarks/extension18-controlled-baseline.json")
    parser.add_argument("--exercise-local-target", action="store_true", help="Run the in-process synthetic discovery target; never contacts external hosts.")
    args = parser.parse_args()
    suite = json.loads(Path(args.suite).read_text(encoding="utf-8"))
    result = evaluate_suite(suite)
    result["generated_at"] = datetime.now(UTC).isoformat()
    result["runner"] = "backend/scripts/run_benchmark.py"
    if args.exercise_local_target:
        result["cases"].append(run_local_target_benchmark())
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "case_count": len(result["cases"])}, sort_keys=True))


if __name__ == "__main__":
    main()
