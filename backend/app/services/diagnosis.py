from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.scan import CauseOfDeathDiagnosis, Scan
from app.services.evidence import EvidenceAgent, EvidenceValidationError
from app.services.llm import LLMClient, LLMError
from app.services.risk import RiskImpactEngine

CAUSE_OF_DEATH_DISCLAIMER = (
    "Cause of Death is a diagnostic label for prioritizing observable web findings. "
    "It is not a claim that the website is compromised, hacked, or offline."
)


class CauseOfDeathEngine:
    """Select an auditable diagnosis from risk-ranked persisted findings."""

    def __init__(self, db: Session, scan_id: UUID):
        self.db = db
        self.scan_id = scan_id

    def compute(self, *, allow_in_progress: bool = False) -> dict[str, Any]:
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            raise ValueError("Scan not found.")
        if scan.state != "COMPLETED" and not (allow_in_progress and scan.state in {"ANALYZING", "SYNTHESIZING", "PARTIAL_FAILED"}):
            raise ValueError("Cause of Death requires a completed scan when requested through the public workflow.")
        ranked = RiskImpactEngine(self.db, self.scan_id).rank()
        primary = ranked[0] if ranked else self._unknown_issue()
        secondary = self._select_secondary(ranked[1:])
        contributing = self._select_contributing(primary, ranked[1:], {item["finding_id"] for item in secondary})
        selected = [primary, *secondary, *contributing]
        evidence = self._distinct_evidence(selected)
        confidence = self._confidence(selected)
        diagnosis = {
            "scan_id": str(self.scan_id),
            "primary_issue": primary,
            "secondary_issues": secondary,
            "contributing_factors": contributing,
            "confidence": confidence,
            "evidence_count": len(evidence),
            "evidence": evidence,
            "disclaimer": CAUSE_OF_DEATH_DISCLAIMER,
            "rubric": {
                "selection": "RiskImpactEngine descending priority; secondary issues are distinct subjects/categories; contributing factors must satisfy a documented relation to the primary category.",
                "confidence": "Evidence-count-weighted mean of selected finding confidence dimensions, rounded to 4 decimals.",
            },
        }
        return diagnosis

    def persist(self, *, narrative: dict[str, Any] | None = None, allow_in_progress: bool = False) -> dict[str, Any]:
        diagnosis = self.compute(allow_in_progress=allow_in_progress)
        row = self.db.query(CauseOfDeathDiagnosis).filter(CauseOfDeathDiagnosis.scan_id == self.scan_id).first()
        if not row:
            row = CauseOfDeathDiagnosis(scan_id=self.scan_id)
            self.db.add(row)
        row.primary_issue = diagnosis["primary_issue"]
        row.secondary_issues = diagnosis["secondary_issues"]
        row.contributing_factors = diagnosis["contributing_factors"]
        row.confidence = diagnosis["confidence"]
        row.evidence_count = diagnosis["evidence_count"]
        row.evidence = diagnosis["evidence"]
        row.disclaimer = diagnosis["disclaimer"]
        row.ai_narrative = narrative.get("narrative") if narrative else None
        row.ai_evidence = narrative.get("evidence", []) if narrative else []
        self.db.commit()
        self.db.refresh(row)
        return self.to_response(row, diagnosis.get("rubric"))

    @staticmethod
    def _unknown_issue() -> dict[str, Any]:
        return {
            "finding_id": None,
            "category": "UNKNOWN",
            "subject": "No ranked finding",
            "statement": "No persisted finding was available to select as a primary issue.",
            "classification": "UNKNOWN",
            "score": 0.0,
            "dimensions": {"impact": 0.0, "confidence": 0.0, "severity": 0.0, "dependency_criticality": 0.0, "frequency": 0.0, "user_facing_effect": 0.0},
            "evidence": [],
            "evidence_count": 0,
            "dependency_context": None,
        }

    @staticmethod
    def _select_secondary(ranked: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for item in ranked:
            key = (item["category"], item["subject"])
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
            if len(result) == 3:
                break
        return result

    @staticmethod
    def _select_contributing(primary: dict[str, Any], ranked: list[dict[str, Any]], excluded_ids: set[str | None]) -> list[dict[str, Any]]:
        if primary["category"] == "UNKNOWN":
            return []
        related_categories = {
            "PERFORMANCE": {"PERFORMANCE", "DEPENDENCY", "TECHNOLOGY"},
            "SECURITY": {"SECURITY", "DEPENDENCY"},
            "ACCESSIBILITY": {"ACCESSIBILITY", "CONTENT"},
            "CONTENT": {"CONTENT", "ACCESSIBILITY"},
            "DEPENDENCY": {"DEPENDENCY", "TECHNOLOGY", "PERFORMANCE"},
            "TECHNOLOGY": {"TECHNOLOGY", "DEPENDENCY"},
        }.get(primary["category"], {primary["category"]})
        result = []
        for item in ranked:
            if item["category"] in related_categories and item["finding_id"] != primary["finding_id"] and item["finding_id"] not in excluded_ids:
                result.append(item)
            if len(result) == 2:
                break
        return result

    @staticmethod
    def _distinct_evidence(selected: list[dict[str, Any]]) -> list[dict[str, str]]:
        evidence: list[dict[str, str]] = []
        seen: set[str] = set()
        for item in selected:
            for entry in item.get("evidence", []):
                if entry["id"] not in seen:
                    seen.add(entry["id"])
                    evidence.append(entry)
        return evidence

    @staticmethod
    def _confidence(selected: list[dict[str, Any]]) -> float:
        weighted = [(item["dimensions"]["confidence"], max(1, item["evidence_count"])) for item in selected if item["finding_id"]]
        if not weighted:
            return 0.0
        return round(sum(value * weight for value, weight in weighted) / sum(weight for _, weight in weighted), 4)

    @staticmethod
    def to_response(row: CauseOfDeathDiagnosis, rubric: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "id": str(row.id),
            "scan_id": str(row.scan_id),
            "primary_issue": row.primary_issue,
            "secondary_issues": row.secondary_issues,
            "contributing_factors": row.contributing_factors,
            "confidence": row.confidence,
            "evidence_count": row.evidence_count,
            "evidence": row.evidence,
            "ai_narrative": row.ai_narrative,
            "ai_evidence": row.ai_evidence,
            "disclaimer": row.disclaimer,
            "rubric": rubric or {},
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }


class CauseOfDeathNarrative:
    """Optional narrative framing; it cannot modify deterministic selections."""

    def __init__(self, db: Session):
        self.db = db
        try:
            self.llm: LLMClient | None = LLMClient()
        except LLMError:
            self.llm = None

    def generate(self, diagnosis: dict[str, Any]) -> dict[str, Any]:
        allowed_ids = [entry["id"] for entry in diagnosis["evidence"]]
        context = {
            "primary_issue": diagnosis["primary_issue"],
            "secondary_issues": diagnosis["secondary_issues"],
            "contributing_factors": diagnosis["contributing_factors"],
            "confidence": diagnosis["confidence"],
            "evidence_count": diagnosis["evidence_count"],
            "evidence_ids": allowed_ids,
        }
        system_prompt = """
You narrate an already-computed Web Autopsy Network Cause of Death diagnosis.
Return JSON exactly {"narrative": "short paragraph", "evidence": ["exact evidence IDs"]}.
You may rephrase only the supplied primary_issue, secondary_issues, contributing_factors, confidence, and evidence count. You must not alter, add, remove, or re-rank issues. Cite only exact evidence IDs from the supplied diagnosis. Preserve this disclaimer concept: the label is not a claim of compromise, hacking, or outage.
"""
        try:
            if self.llm is None:
                raise LLMError("LLM_API_KEY is not configured; using deterministic narrative fallback.")
            response = self.llm.generate_json(system_prompt, f"Computed diagnosis:\n{context}")
            cited = [str(value) for value in response.get("evidence", [])]
            EvidenceAgent(self.db, UUID(diagnosis["scan_id"])).validate_diagnosis_citations(cited, allowed_ids)
            return {"narrative": str(response.get("narrative", "")), "evidence": cited, "status": "generated"}
        except (LLMError, EvidenceValidationError, TypeError, ValueError):
            primary = diagnosis["primary_issue"]["subject"]
            secondary = ", ".join(item["subject"] for item in diagnosis["secondary_issues"]) or "none"
            return {
                "narrative": f"The highest-priority observed issue is {primary}; secondary priorities include {secondary}. This diagnostic label is based on {diagnosis['evidence_count']} evidence item(s) at {diagnosis['confidence']:.0%} confidence and does not claim compromise, hacking, or outage.",
                "evidence": allowed_ids,
                "status": "graceful_degradation",
            }
