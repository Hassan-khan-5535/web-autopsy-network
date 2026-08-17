"""Deterministic risk and impact ranking for persisted scan findings.

The rubric is intentionally explicit and inspectable. Every score is normalized to
0..1 and the final priority is:

    impact              30%
    confidence          25%
    severity            15%
    dependency criticality 10%
    frequency           10%
    user-facing effect  10%

This is prioritization, not a claim that a target is compromised or defective.
"""

from __future__ import annotations

from collections import Counter
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.scan import (
    AccessibilityFinding,
    ContentFinding,
    Dependency,
    PerformanceMetric,
    Scan,
    SecurityFinding,
    Technology,
)

RUBRIC_WEIGHTS = {
    "impact": 0.30,
    "confidence": 0.25,
    "severity": 0.15,
    "dependency_criticality": 0.10,
    "frequency": 0.10,
    "user_facing_effect": 0.10,
}
SEVERITY_SCORES = {"critical": 1.0, "high": 0.9, "medium": 0.7, "low": 0.5, "info": 0.3}
CLASSIFICATION_CONFIDENCE = {"OBSERVED": 0.90, "INFERRED": 0.75, "UNKNOWN": 0.25}
USER_FACING_EFFECT = {
    "SECURITY": 0.90,
    "PERFORMANCE": 0.95,
    "ACCESSIBILITY": 0.85,
    "CONTENT": 0.65,
    "DEPENDENCY": 0.55,
    "TECHNOLOGY": 0.35,
}


class RiskImpactEngine:
    """Return a stable, evidence-linked priority list for one completed scan."""

    def __init__(self, db: Session, scan_id: UUID):
        self.db = db
        self.scan_id = scan_id

    def rank(self) -> list[dict[str, Any]]:
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            raise ValueError("Scan not found.")
        records = self._collect(scan)
        frequencies = Counter((item["category"], item["subject"]) for item in records)
        max_frequency = max(frequencies.values(), default=1)
        max_dependency_refs = max(
            (item["raw"].reference_count for item in records if item["category"] == "DEPENDENCY"),
            default=1,
        )
        ranked = []
        for item in records:
            key = (item["category"], item["subject"])
            dimensions = item["dimensions"]
            dimensions["frequency"] = frequencies[key] / max_frequency
            if item["category"] == "DEPENDENCY":
                dimensions["dependency_criticality"] = item["raw"].reference_count / max_dependency_refs
            score = round(
                sum(dimensions[name] * weight for name, weight in RUBRIC_WEIGHTS.items()) * 100,
                2,
            )
            evidence = item["evidence"]
            ranked.append(
                {
                    "finding_id": item["finding_id"],
                    "category": item["category"],
                    "subject": item["subject"],
                    "statement": item["statement"],
                    "classification": item["classification"],
                    "score": score,
                    "dimensions": {name: round(value, 4) for name, value in dimensions.items()},
                    "evidence": evidence,
                    "evidence_count": len({entry["id"] for entry in evidence}),
                    "dependency_context": item.get("dependency_context"),
                }
            )
        return sorted(ranked, key=lambda item: (-item["score"], item["category"], item["subject"], item["finding_id"]))

    @staticmethod
    def _confidence(raw: Any) -> float:
        value = getattr(raw, "confidence", None)
        if value is not None:
            return max(0.0, min(1.0, float(value) / 100 if float(value) > 1 else float(value)))
        return CLASSIFICATION_CONFIDENCE.get(getattr(raw, "classification", "UNKNOWN"), 0.25)

    @staticmethod
    def _evidence(raw: Any, category: str, statement: str) -> list[dict[str, str]]:
        result: list[dict[str, str]] = []
        raw_evidence = getattr(raw, "evidence", None)
        if isinstance(raw_evidence, list):
            for index, entry in enumerate(raw_evidence):
                if isinstance(entry, dict) and entry.get("id"):
                    result.append({
                        "id": str(entry["id"]),
                        "type": str(entry.get("type", category)),
                        "observation": str(entry.get("observation", statement)),
                        "source": str(entry.get("source", "persisted finding evidence")),
                    })
        if not result and category == "TECHNOLOGY":
            for entry in getattr(raw, "evidence", []):
                result.append({"id": str(entry.id), "type": entry.signal_type, "observation": entry.observation, "source": entry.source})
        if not result:
            result.append({"id": str(raw.id), "type": category, "observation": statement, "source": "persisted finding"})
        return result

    def _collect(self, scan: Scan) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []

        def add(raw: Any, category: str, subject: str, statement: str, classification: str, impact: float, severity: float, dependency_context: str | None = None):
            records.append({
                "raw": raw,
                "finding_id": str(raw.id),
                "category": category,
                "subject": subject,
                "statement": statement,
                "classification": classification,
                "evidence": self._evidence(raw, category, statement),
                "dependency_context": dependency_context,
                "dimensions": {
                    "impact": impact,
                    "confidence": self._confidence(raw),
                    "severity": severity,
                    "dependency_criticality": 0.0,
                    "frequency": 0.0,
                    "user_facing_effect": USER_FACING_EFFECT[category],
                },
            })

        for finding in scan.security_findings:
            add(finding, "SECURITY", finding.subject, finding.statement, finding.classification, 0.95, SEVERITY_SCORES.get(finding.severity, 0.4))
        for metric in scan.performance_metrics:
            if metric.value is None and not metric.metric_name.startswith("diagnosis:"):
                continue
            impact = 1.0 if metric.metric_name.startswith("diagnosis:") else 0.75
            add(metric, "PERFORMANCE", metric.metric_name, metric.statement, metric.classification, impact, 0.85 if impact == 1.0 else 0.65)
        for finding in scan.accessibility_findings:
            add(finding, "ACCESSIBILITY", finding.subject, finding.statement, finding.classification, 0.80, 0.65)
        for finding in scan.content_findings:
            add(finding, "CONTENT", finding.subject, finding.statement, finding.classification, 0.60, 0.50)
        for dependency in scan.dependencies:
            add(dependency, "DEPENDENCY", dependency.domain, f"External dependency observed: {dependency.domain} ({dependency.category}).", dependency.classification.upper(), 0.55, 0.45)
        for technology in scan.technologies:
            add(technology, "TECHNOLOGY", technology.canonical_name, f"Technology detected: {technology.canonical_name}.", technology.classification.upper(), 0.35, 0.30)
        return records


__all__ = ["RiskImpactEngine", "RUBRIC_WEIGHTS"]
