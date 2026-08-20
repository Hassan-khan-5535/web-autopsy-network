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
from datetime import UTC, datetime
import re
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.scan import (
    AccessibilityFinding,
    AttackSurfaceGraphEdge,
    AttackSurfaceGraphNode,
    ContentFinding,
    Dependency,
    EvidenceReview,
    PerformanceMetric,
    RiskAssessment,
    Scan,
    ScanRiskSummary,
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


RISK_VERSION = "extension11-v1"
RISK_COMPONENT_WEIGHTS = {
    "severity": 25,
    "confidence": 15,
    "exposure": 15,
    "exploitability_indicators": 10,
    "asset_criticality": 15,
    "business_impact": 10,
    "evidence_quality": 10,
}
RISK_SEVERITIES = {"critical": 100.0, "high": 80.0, "medium": 55.0, "low": 30.0, "info": 10.0}
RISK_QUALITY = {"strong": 100.0, "moderate": 75.0, "weak": 45.0, "none": 10.0}
RISK_REVIEW_STATE = {"validated": 100.0, "candidate": 65.0, "inconclusive": 40.0, "rejected": 0.0, "not_reviewed": 45.0}
RISK_ASSETS = {"Authentication Boundary": 95.0, "API": 90.0, "Application": 85.0, "Endpoint": 70.0, "Cloud Asset": 65.0, "Host": 60.0, "Service": 55.0, "Domain": 45.0, "Technology": 40.0, "Parameter": 50.0}


class RiskAgent:
    """Evidence-backed deterministic risk prioritization; no target action is performed."""

    def __init__(self, db: Session, scan_id: UUID):
        self.db = db
        self.scan_id = scan_id

    def analyze(self) -> list[RiskAssessment]:
        scan = self._scan()
        self.db.query(RiskAssessment).filter(RiskAssessment.scan_id == scan.id).delete(synchronize_session=False)
        self.db.flush()
        reviews = {item.security_finding_id: item for item in self.db.query(EvidenceReview).filter(EvidenceReview.scan_id == scan.id, EvidenceReview.security_finding_id.is_not(None)).all()}
        coverage_limited = self._analysis_unavailable(scan)
        graph_assets = self._graph_assets()
        assessments: list[RiskAssessment] = []
        for finding in self.db.query(SecurityFinding).filter(SecurityFinding.scan_id == scan.id).order_by(SecurityFinding.created_at, SecurityFinding.id).all():
            review = reviews.get(finding.id)
            components, notes, eligible, evidence_state = self._score_components(finding, review, graph_assets.get(self._finding_key(finding), []))
            if coverage_limited:
                eligible = False
                evidence_state = "not_analyzed"
                notes.append("Risk prioritization was suppressed because security analysis was unavailable; this scan does not establish a vulnerability conclusion.")
            raw_score = round(sum(component["weighted_contribution"] for component in components.values()), 2)
            score, cap_note = self._apply_evidence_cap(raw_score, review, eligible)
            if cap_note:
                notes.append(cap_note)
            item = RiskAssessment(
                scan_id=scan.id,
                security_finding_id=finding.id,
                deterministic_version=RISK_VERSION,
                risk_score=score,
                risk_band=self._band(score),
                eligible_for_prioritization=eligible,
                evidence_state=evidence_state,
                score_components=components,
                decision_notes=notes,
                evidence_snapshot=self._evidence_snapshot(finding, review),
            )
            self.db.add(item)
            self.db.flush()
            assessments.append(item)
        self._save_summary(scan, assessments)
        self.db.commit()
        return assessments

    def report(self) -> dict[str, Any]:
        scan = self._scan()
        summary = self.db.query(ScanRiskSummary).filter(ScanRiskSummary.scan_id == scan.id).first()
        assessments = self.db.query(RiskAssessment).filter(RiskAssessment.scan_id == scan.id).order_by(RiskAssessment.eligible_for_prioritization.desc(), RiskAssessment.risk_score.desc(), RiskAssessment.created_at).all()
        return {
            "scan_id": str(scan.id),
            "deterministic_version": RISK_VERSION,
            "summary": self._summary_dict(summary),
            "assessments": [self._assessment_dict(item) for item in assessments],
            "trend": self._trend(scan, assessments, summary),
            "scoring_contract": {
                "model": "deterministic_heuristic",
                "component_weights": RISK_COMPONENT_WEIGHTS,
                "components_are_transparent": True,
                "ml_assistance_enabled": False,
                "ml_requirement": "Additive ML assistance requires sufficient documented training and evaluation data, calibration, and governance.",
                "validated_evidence_can_be_overridden_by_ml": False,
                "opaque_override_allowed": False,
                "active_exploitation_supported": False,
                "network_requests_performed": False,
            },
        }

    def _scan(self) -> Scan:
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            raise ValueError(f"Scan {self.scan_id} not found")
        return scan

    def _score_components(self, finding: SecurityFinding, review: EvidenceReview | None, assets: list[AttackSurfaceGraphNode]) -> tuple[dict[str, dict[str, Any]], list[str], bool, str]:
        severity = str(finding.severity or "info").lower()
        evidence_state = review.finding_state if review else "not_reviewed"
        best_asset = max(assets, key=lambda item: RISK_ASSETS.get(item.entity_type, 50.0), default=None)
        asset_score = RISK_ASSETS.get(best_asset.entity_type, 50.0) if best_asset else 50.0
        category = str(finding.category or "").lower()
        exploitability = 75.0 if any(value in category for value in ("vulnerability", "secrets", "cve")) else 65.0 if any(value in category for value in ("api", "security", "configuration")) else 45.0
        if review and review.reproducibility_state == "reproduced_from_persisted_response":
            exploitability = min(100.0, exploitability + 10.0)
        evidence_score = min(RISK_QUALITY.get(review.evidence_quality, 10.0) if review else 45.0, RISK_REVIEW_STATE.get(evidence_state, 40.0))
        if review and not review.prerequisites_valid:
            evidence_score = min(evidence_score, 25.0)
        confidence = self._percentage(finding.confidence)
        business = min(100.0, RISK_SEVERITIES.get(severity, 10.0) + (10.0 if category in {"secrets", "vulnerability", "cve"} else 0.0))
        asset_name = best_asset.label if best_asset else "No persisted affected graph asset; neutral score used."
        components = {
            "severity": self._component("severity", RISK_SEVERITIES.get(severity, 10.0), f"Stored finding severity: {severity}."),
            "confidence": self._component("confidence", confidence, f"Stored finding confidence: {confidence:.0f}%"),
            "exposure": self._component("exposure", asset_score, f"Affected persisted graph asset: {asset_name}"),
            "exploitability_indicators": self._component("exploitability_indicators", exploitability, "Passive indicator only; no exploit attempt or proof of exploitability was performed."),
            "asset_criticality": self._component("asset_criticality", asset_score, f"Highest affected graph asset type: {best_asset.entity_type if best_asset else 'unknown'}"),
            "business_impact": self._component("business_impact", business, "Heuristic uses stored severity and category only; it does not infer unobserved business harm."),
            "evidence_quality": self._component("evidence_quality", evidence_score, f"Evidence state: {evidence_state}; quality: {review.evidence_quality if review else 'not reviewed'}."),
        }
        eligible = evidence_state != "rejected"
        notes = ["All score components are deterministic and derive from persisted records.", "The score prioritizes review and does not prove exploitability or business impact."]
        if review and review.redacted:
            notes.append("Evidence inputs use redacted persisted EvidenceReview records.")
        if not eligible:
            notes.append("Rejected evidence is retained for audit but excluded from prioritization.")
        return components, notes, eligible, evidence_state

    def _graph_assets(self) -> dict[str, list[AttackSurfaceGraphNode]]:
        nodes = {item.id: item for item in self.db.query(AttackSurfaceGraphNode).filter(AttackSurfaceGraphNode.scan_id == self.scan_id).all()}
        result: dict[str, list[AttackSurfaceGraphNode]] = {}
        edges = self.db.query(AttackSurfaceGraphEdge).filter(AttackSurfaceGraphEdge.scan_id == self.scan_id, AttackSurfaceGraphEdge.relationship_type.in_(["AFFECTS", "POTENTIAL_ESCALATION_PRIORITY"])).all()
        for edge in edges:
            source, target = nodes.get(edge.source_node_id), nodes.get(edge.target_node_id)
            if not source or not target or source.entity_type != "Finding":
                continue
            attributes = source.attributes if isinstance(source.attributes, dict) else {}
            key = self._key(str(attributes.get("rule_id") or ""), source.label)
            result.setdefault(key, []).append(target)
        return result

    def _save_summary(self, scan: Scan, assessments: list[RiskAssessment]) -> None:
        unique_eligible: dict[tuple[str, str], RiskAssessment] = {}
        for item in assessments:
            if not item.eligible_for_prioritization or not item.security_finding:
                continue
            key = self._semantic_key(item.security_finding)
            prior = unique_eligible.get(key)
            if prior is None or item.risk_score > prior.risk_score:
                unique_eligible[key] = item
        eligible = sorted(unique_eligible.values(), key=lambda item: item.risk_score, reverse=True)
        top_scores = [item.risk_score for item in eligible[:5]]
        overall = round(0.6 * top_scores[0] + 0.4 * sum(top_scores) / len(top_scores), 2) if top_scores else 0.0
        coverage_limited = self._analysis_unavailable(scan)
        data = {
            "website_id": scan.website_id,
            "deterministic_version": RISK_VERSION,
            "overall_score": 0.0 if coverage_limited else overall,
            "risk_band": "not_analyzed" if coverage_limited else self._band(overall),
            "eligible_assessment_count": len(eligible),
            "assessment_count": len(assessments),
            "summary": {"band_counts": dict(Counter(item.risk_band for item in assessments)), "top_assessment_ids": [str(item.id) for item in eligible[:5]], "overall_formula": "0.6 × highest eligible score + 0.4 × mean of highest five eligible scores", "coverage_state": "analysis_unavailable" if coverage_limited else "analyzed"},
        }
        summary = self.db.query(ScanRiskSummary).filter(ScanRiskSummary.scan_id == scan.id).first()
        if summary:
            for key, value in data.items():
                setattr(summary, key, value)
        else:
            self.db.add(ScanRiskSummary(scan_id=scan.id, **data))
        self.db.flush()

    def _trend(self, scan: Scan, assessments: list[RiskAssessment], summary: ScanRiskSummary | None) -> dict[str, Any]:
        summaries = self.db.query(ScanRiskSummary).join(Scan, ScanRiskSummary.scan_id == Scan.id).filter(ScanRiskSummary.website_id == scan.website_id, Scan.state == "COMPLETED").order_by(Scan.created_at, Scan.id).all()
        series = [{"scan_id": str(item.scan_id), "overall_score": item.overall_score, "risk_band": item.risk_band, "updated_at": item.updated_at.isoformat()} for item in summaries]
        previous = next((item for item in reversed(summaries) if item.scan_id != scan.id), None)
        if not previous or not summary:
            return {"prior_scan": None, "score_delta": None, "movement": "baseline", "series": series, "finding_changes": [], "limitation": "No prior completed same-target risk summary is available."}
        delta = round(summary.overall_score - previous.overall_score, 2)
        movement = "increased" if delta >= 5 else "decreased" if delta <= -5 else "stable"
        previous_items = self.db.query(RiskAssessment).join(SecurityFinding, RiskAssessment.security_finding_id == SecurityFinding.id).filter(RiskAssessment.scan_id == previous.scan_id).all()
        current_by_key = {self._finding_key(item.security_finding): item for item in assessments if item.security_finding}
        previous_by_key = {self._finding_key(item.security_finding): item for item in previous_items if item.security_finding}
        changes: list[dict[str, Any]] = []
        for key in sorted(current_by_key.keys() - previous_by_key.keys()):
            changes.append({"key": key, "change": "newly_prioritized", "current_score": current_by_key[key].risk_score, "previous_score": None, "classification": "OBSERVED"})
        for key in sorted(previous_by_key.keys() - current_by_key.keys()):
            changes.append({"key": key, "change": "not_currently_observed", "current_score": None, "previous_score": previous_by_key[key].risk_score, "classification": "INFERRED", "note": "Absence from this scan is not proof that the finding is resolved."})
        for key in sorted(current_by_key.keys() & previous_by_key.keys()):
            current, prior = current_by_key[key], previous_by_key[key]
            if abs(current.risk_score - prior.risk_score) >= 1:
                changes.append({"key": key, "change": "risk_score_changed", "current_score": current.risk_score, "previous_score": prior.risk_score, "delta": round(current.risk_score - prior.risk_score, 2), "classification": "OBSERVED"})
        return {"prior_scan": {"scan_id": str(previous.scan_id), "overall_score": previous.overall_score, "risk_band": previous.risk_band, "updated_at": previous.updated_at.isoformat()}, "score_delta": delta, "movement": movement, "series": series, "finding_changes": changes, "limitation": "Comparisons use completed scans of the same stored target only; non-observation is not resolution."}

    @staticmethod
    def _component(name: str, score: float, explanation: str) -> dict[str, Any]:
        value = round(max(0.0, min(100.0, score)), 2)
        return {"weight": RISK_COMPONENT_WEIGHTS[name], "score": value, "weighted_contribution": round(RISK_COMPONENT_WEIGHTS[name] * value / 100.0, 2), "explanation": explanation}

    @staticmethod
    def _semantic_key(finding: SecurityFinding) -> tuple[str, str]:
        canonical_rule = "cors_wildcard_credentials" if finding.rule_id in {"cors_wildcard_credentials", "CFG-CORS-001"} else finding.rule_id
        location = finding.page.canonical_url if finding.page else finding.subject
        return canonical_rule, location

    @staticmethod
    def _analysis_unavailable(scan: Scan) -> bool:
        return any(finding.rule_id == "security_analysis_unavailable" for finding in scan.security_findings)

    @staticmethod
    def _apply_evidence_cap(raw_score: float, review: EvidenceReview | None, eligible: bool) -> tuple[float, str | None]:
        if not eligible:
            return 0.0, "Risk score set to 0 because its evidence review is rejected."
        if review and review.finding_state in {"candidate", "inconclusive"}:
            cap = 69.99 if review.finding_state == "candidate" else 44.99
            return min(raw_score, cap), f"Score capped at {cap:.2f} because the evidence state is {review.finding_state}, not validated."
        return raw_score, None

    @staticmethod
    def _evidence_snapshot(finding: SecurityFinding, review: EvidenceReview | None) -> dict[str, Any]:
        return {"finding_evidence_count": len(finding.evidence or []), "finding_classification": finding.classification, "review_present": review is not None, "review_state": review.finding_state if review else "not_reviewed", "review_quality": review.evidence_quality if review else "not_reviewed", "review_reproducibility": review.reproducibility_state if review else "not_run", "secret_values_included": False}

    @staticmethod
    def _percentage(value: float | None) -> float:
        value = float(value or 0.0)
        return round(value * 100 if value <= 1 else value, 2)

    @staticmethod
    def _band(score: float) -> str:
        if score >= 85:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 45:
            return "medium"
        if score >= 20:
            return "low"
        return "info"

    @staticmethod
    def _key(rule_id: str, subject: str) -> str:
        normalized_subject = re.sub(r'\s+', ' ', subject.strip().lower())
        return f"{rule_id.strip().lower()}|{normalized_subject}"

    def _finding_key(self, finding: SecurityFinding) -> str:
        return self._key(finding.rule_id, finding.subject)

    @staticmethod
    def _assessment_dict(item: RiskAssessment) -> dict[str, Any]:
        finding = item.security_finding
        return {"id": str(item.id), "security_finding_id": str(item.security_finding_id), "subject": finding.subject if finding else "Unknown finding", "category": finding.category if finding else "unknown", "severity": finding.severity if finding else "info", "rule_id": finding.rule_id if finding else "unknown", "risk_score": item.risk_score, "risk_band": item.risk_band, "eligible_for_prioritization": item.eligible_for_prioritization, "evidence_state": item.evidence_state, "score_components": item.score_components, "decision_notes": item.decision_notes, "evidence_snapshot": item.evidence_snapshot, "updated_at": item.updated_at.isoformat()}

    @staticmethod
    def _summary_dict(summary: ScanRiskSummary | None) -> dict[str, Any]:
        if not summary:
            return {"available": False, "overall_score": 0.0, "risk_band": "info", "eligible_assessment_count": 0, "assessment_count": 0, "summary": {}}
        return {"available": True, "overall_score": summary.overall_score, "risk_band": summary.risk_band, "eligible_assessment_count": summary.eligible_assessment_count, "assessment_count": summary.assessment_count, "summary": summary.summary, "updated_at": summary.updated_at.isoformat()}


__all__ = ["RiskAgent", "RiskImpactEngine", "RISK_COMPONENT_WEIGHTS", "RISK_VERSION", "RUBRIC_WEIGHTS"]
