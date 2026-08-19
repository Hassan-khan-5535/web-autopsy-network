from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections import Counter
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy.orm import Session

from app.models.scan import EvidenceReview, HTTPObservation, HTTPResponse, Observation, Scan, ScanDifference, SecurityFinding

RULE_VERSION = "phase9-evidence-v1"
REDACTED = "[REDACTED]"
SECRET_KEY_RE = re.compile(r"(?:authorization|cookie|token|secret|password|passwd|api[-_]?key|private[-_]?key|client[-_]?secret)", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{30,}|sk_(?:live|test)_[A-Za-z0-9]{16,})\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE)
VALID_STATES = {"candidate", "validated", "rejected", "inconclusive"}


def _redact_url(value: str) -> str:
    try:
        parsed = urlsplit(str(value))
        query = [(key, REDACTED) for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))
    except Exception:
        return str(value).split("?", 1)[0][:2048]


def _redact_text(value: str) -> str:
    value = PRIVATE_KEY_RE.sub("[PRIVATE_KEY_REDACTED]", str(value))
    value = SECRET_VALUE_RE.sub(REDACTED, value)
    return value[:4096]


def redact_value(value: Any, key: str | None = None) -> Any:
    if key and SECRET_KEY_RE.search(key):
        if isinstance(value, (str, list, dict)):
            return {"present": bool(value), "value_redacted": True}
        return REDACTED
    if isinstance(value, str):
        return _redact_url(value) if "://" in value else _redact_text(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value[:50]]
    if isinstance(value, dict):
        return {str(item_key): redact_value(item, str(item_key)) for item_key, item in list(value.items())[:80]}
    return value


class EvidenceValidationError(Exception):
    pass


class EvidenceAgent:
    """Legacy citation validation plus independent false-positive reduction over persisted evidence."""

    def __init__(self, db: Session, scan_id: uuid.UUID):
        self.db = db
        self.scan_id = scan_id
        self.scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not self.scan:
            raise ValueError(f"Scan {scan_id} not found")

    def validate_finding(self, evidence: list | None) -> None:
        if not evidence or len(evidence) == 0:
            raise EvidenceValidationError("A finding cannot be persisted without evidence.")

    def validate_difference_citations(self, difference_id: uuid.UUID, cited_ids: list[str]) -> None:
        if not cited_ids:
            raise EvidenceValidationError("AI change explanations must cite at least one diff item.")
        try:
            difference_uuid = uuid.UUID(str(difference_id))
        except (TypeError, ValueError) as exc:
            raise EvidenceValidationError(f"Invalid scan difference ID: {difference_id}") from exc
        difference = self.db.query(ScanDifference).filter(ScanDifference.id == difference_uuid).first()
        if not difference:
            raise EvidenceValidationError(f"Scan difference {difference_id} not found.")
        valid_ids = {str(item.get("id")) for item in (difference.diff_data or {}).get("items", []) if item.get("id")}
        invalid = [citation for citation in cited_ids if citation not in valid_ids]
        if invalid:
            raise EvidenceValidationError(f"LLM hallucinated citation: diff item IDs {invalid} do not exist in this comparison.")

    def validate_diagnosis_citations(self, cited_ids: list[str], allowed_ids: list[str]) -> None:
        if not cited_ids:
            raise EvidenceValidationError("Diagnosis narrative must cite at least one diagnosis evidence item.")
        invalid = sorted(set(cited_ids) - set(allowed_ids))
        if invalid:
            raise EvidenceValidationError(f"AI narrative cited evidence outside the deterministic diagnosis: {invalid}")

    def validate_ai_citations(self, cited_evidence_ids: list[str]) -> None:
        if not cited_evidence_ids:
            raise EvidenceValidationError("AI Interpretation must cite at least one evidence ID.")
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            raise EvidenceValidationError(f"Scan {self.scan_id} not found.")
        valid_ids = set()
        for obs in scan.observations:
            valid_ids.add(str(obs.id))
        for sf in scan.security_findings:
            valid_ids.add(str(sf.id))
        for pm in scan.performance_metrics:
            valid_ids.add(str(pm.id))
        for af in scan.accessibility_findings:
            valid_ids.add(str(af.id))
        for cf in scan.content_findings:
            valid_ids.add(str(cf.id))
        for tech in scan.technologies:
            for ev in tech.evidence:
                valid_ids.add(str(ev.id))
        for cited_id in cited_evidence_ids:
            if cited_id not in valid_ids:
                raise EvidenceValidationError(f"LLM hallucinated citation: Evidence ID {cited_id} does not exist in this scan.")

    def analyze(self) -> list[EvidenceReview]:
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            raise ValueError(f"Scan {self.scan_id} not found")
        self.db.query(EvidenceReview).filter(EvidenceReview.scan_id == self.scan_id).delete(synchronize_session=False)
        self.db.flush()
        findings = self.db.query(SecurityFinding).filter(SecurityFinding.scan_id == self.scan_id).order_by(SecurityFinding.created_at, SecurityFinding.id).all()
        reviews: list[EvidenceReview] = []
        seen: set[str] = set()
        for finding in findings:
            candidate_key = self._candidate_key(finding)
            if candidate_key in seen:
                continue
            seen.add(candidate_key)
            review = self._review_finding(finding, candidate_key)
            self._validate_review(review)
            self.db.add(review)
            self.db.flush()
            reviews.append(review)
        self.db.commit()
        return reviews

    def report(self) -> dict[str, Any]:
        reviews = self.db.query(EvidenceReview).filter(EvidenceReview.scan_id == self.scan_id).order_by(EvidenceReview.finding_state, EvidenceReview.rule_id, EvidenceReview.created_at).all()
        state_counts = Counter(item.finding_state for item in reviews)
        quality_counts = Counter(item.evidence_quality for item in reviews)
        reproducibility_counts = Counter(item.reproducibility_state for item in reviews)
        return {"scan_id": str(self.scan_id), "rule_version": RULE_VERSION, "reviews": [self._review_dict(item) for item in reviews], "summary": {"candidate_count": len(reviews), "state_counts": dict(state_counts), "quality_counts": dict(quality_counts), "reproducibility_counts": dict(reproducibility_counts), "validated_count": state_counts.get("validated", 0), "inconclusive_count": state_counts.get("inconclusive", 0), "rejected_count": state_counts.get("rejected", 0)}, "provenance_contract": {"required_fields": ["target", "endpoint_or_asset", "source_agent", "timestamp", "rule_id", "observation"], "safe_request_metadata_included_when_available": True, "secret_values_redacted": True, "signature_alone_is_proof": False}}

    def _review_finding(self, finding: SecurityFinding, candidate_key: str) -> EvidenceReview:
        page_url = finding.page.canonical_url if finding.page else None
        observations = self._collect_observations(finding, page_url)
        provenance = self._collect_provenance(finding, observations, page_url)
        prerequisites_valid, prerequisite_reason = self._validate_prerequisites(finding, observations)
        reproducibility_state, safe_request_metadata = self._safe_reproducibility(finding, observations)
        distinct_agents = {item.get("source_agent") for item in observations if item.get("source_agent")}
        corroboration_count = len(distinct_agents)
        evidence_quality = self._quality(prerequisites_valid, len(observations), corroboration_count, reproducibility_state)
        state = self._state(prerequisites_valid, evidence_quality, reproducibility_state, len(observations))
        confidence = self._confidence(finding, evidence_quality, corroboration_count, reproducibility_state, state)
        target = _redact_url(self.scan.requested_url)
        endpoint = _redact_url(page_url or self._evidence_endpoint(finding) or self.scan.requested_url)
        redacted_observations = [redact_value(item) for item in observations]
        redacted_observations.append({"type": "evidence_agent_decision", "observation": prerequisite_reason, "evidence_quality": evidence_quality, "corroboration_count": corroboration_count, "redacted": True})
        return EvidenceReview(scan_id=self.scan_id, security_finding_id=finding.id, candidate_key=candidate_key, target=target, endpoint_or_asset=endpoint, source_agent=finding.category, rule_id=finding.rule_id, finding_state=state, evidence_quality=evidence_quality, confidence=confidence, prerequisites_valid=prerequisites_valid, reproducibility_state=reproducibility_state, observations=redacted_observations, safe_request_metadata=safe_request_metadata, provenance=provenance, redacted=True)

    def _collect_observations(self, finding: SecurityFinding, page_url: str | None) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        evidence = finding.evidence if isinstance(finding.evidence, list) else []
        for index, item in enumerate(evidence[:40]):
            if isinstance(item, dict):
                records.append({"observation_id": f"finding:{finding.id}:{index}", "source_agent": finding.category, "timestamp": finding.created_at.isoformat(), "rule_id": finding.rule_id, "observation": redact_value(item), "endpoint_or_asset": _redact_url(page_url or str(item.get("source") or self.scan.requested_url))})
            else:
                records.append({"observation_id": f"finding:{finding.id}:{index}", "source_agent": finding.category, "timestamp": finding.created_at.isoformat(), "rule_id": finding.rule_id, "observation": _redact_text(str(item)), "endpoint_or_asset": _redact_url(page_url or self.scan.requested_url)})
        http_rows = self.db.query(HTTPObservation).filter(HTTPObservation.scan_id == self.scan_id, HTTPObservation.page_id == finding.page_id).order_by(HTTPObservation.created_at).limit(40).all() if finding.page_id else []
        for item in http_rows:
            records.append({"observation_id": f"http:{item.id}", "source_agent": "http_agent", "timestamp": item.created_at.isoformat(), "rule_id": finding.rule_id, "observation": {"observation_type": item.observation_type, "subject": _redact_url(item.subject), "value": redact_value(item.value), "classification": item.classification, "confidence": item.confidence, "redacted": item.redacted}, "endpoint_or_asset": _redact_url(item.subject)})
        broad = self.db.query(Observation).filter(Observation.scan_id == self.scan_id, Observation.category.in_([finding.category.upper(), "SECURITY", "TECHNOLOGY"])).order_by(Observation.created_at).limit(20).all()
        for item in broad:
            records.append({"observation_id": f"observation:{item.id}", "source_agent": item.category.lower(), "timestamp": item.created_at.isoformat(), "rule_id": finding.rule_id, "observation": _redact_text(item.observation), "endpoint_or_asset": _redact_url(item.subject)})
        return records[:100]

    def _collect_provenance(self, finding: SecurityFinding, observations: list[dict[str, Any]], page_url: str | None) -> list[dict[str, Any]]:
        provenance = []
        for item in observations:
            provenance.append({"target": _redact_url(self.scan.requested_url), "endpoint_or_asset": item.get("endpoint_or_asset") or _redact_url(page_url or self.scan.requested_url), "source_agent": item.get("source_agent"), "timestamp": item.get("timestamp"), "rule_id": finding.rule_id, "observation_id": item.get("observation_id"), "redacted": True})
        if not provenance:
            provenance.append({"target": _redact_url(self.scan.requested_url), "endpoint_or_asset": _redact_url(page_url or self.scan.requested_url), "source_agent": finding.category, "timestamp": finding.created_at.isoformat(), "rule_id": finding.rule_id, "observation_id": f"finding:{finding.id}", "redacted": True})
        return provenance[:100]

    @staticmethod
    def _validate_prerequisites(finding: SecurityFinding, observations: list[dict[str, Any]]) -> tuple[bool, str]:
        if not finding.rule_id or not finding.statement or not finding.classification:
            return False, "Required finding metadata is missing."
        if not observations:
            return False, "No relevant persisted observations were available for this candidate."
        if not any(item.get("observation") for item in observations):
            return False, "Relevant observations were empty after redaction."
        return True, f"Prerequisites satisfied with {len(observations)} relevant persisted observation(s)."

    def _safe_reproducibility(self, finding: SecurityFinding, observations: list[dict[str, Any]]) -> tuple[str, dict[str, Any] | None]:
        response_ids = [item.get("observation_id") for item in observations if str(item.get("observation_id", "")).startswith("http:")]
        if not response_ids:
            return "not_run", None
        response_available = bool(finding.page_id and self.db.query(HTTPResponse).filter(HTTPResponse.page_id == finding.page_id).first())
        if response_available:
            return "reproduced_from_persisted_response", {"method": "persisted_response_consistency", "network_request_issued": False, "response_metadata": {"status_available": True, "body_reused": False, "secret_values_returned": False}}
        return "not_reproducible", {"method": "persisted_response_consistency", "network_request_issued": False, "reason": "No persisted response was available."}

    @staticmethod
    def _quality(prerequisites: bool, observation_count: int, corroboration_count: int, reproducibility: str) -> str:
        if not prerequisites:
            return "none"
        if reproducibility == "reproduced_from_persisted_response" and corroboration_count >= 2:
            return "strong"
        if observation_count >= 2 or corroboration_count >= 2:
            return "moderate"
        return "weak"

    @staticmethod
    def _state(prerequisites: bool, quality: str, reproducibility: str, observation_count: int) -> str:
        if not prerequisites:
            return "rejected" if observation_count == 0 else "inconclusive"
        if quality == "strong" and reproducibility == "reproduced_from_persisted_response":
            return "validated"
        if quality in {"moderate", "weak"}:
            return "candidate"
        return "inconclusive"

    @staticmethod
    def _confidence(finding: SecurityFinding, quality: str, corroboration_count: int, reproducibility: str, state: str) -> float:
        base = float(finding.confidence or 0)
        quality_bonus = {"strong": 15, "moderate": 8, "weak": 0, "none": -20}.get(quality, 0)
        corroboration_bonus = min(15, max(0, corroboration_count - 1) * 5)
        reproducibility_bonus = 10 if reproducibility == "reproduced_from_persisted_response" else 0
        state_penalty = -20 if state in {"rejected", "inconclusive"} else 0
        return max(0.0, min(100.0, round(base + quality_bonus + corroboration_bonus + reproducibility_bonus + state_penalty, 2)))

    @staticmethod
    def _candidate_key(finding: SecurityFinding) -> str:
        raw = "|".join([str(finding.id), finding.category, finding.rule_id, finding.subject])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _evidence_endpoint(finding: SecurityFinding) -> str | None:
        for item in finding.evidence or []:
            if isinstance(item, dict) and item.get("source"):
                return str(item["source"])
        return None

    @staticmethod
    def _validate_review(review: EvidenceReview) -> None:
        if review.finding_state not in VALID_STATES:
            raise ValueError("Evidence review has an invalid finding state")
        required = {"target", "endpoint_or_asset", "source_agent", "timestamp", "rule_id", "observation_id"}
        if not review.provenance or not required.issubset(review.provenance[0]):
            raise ValueError("Evidence review provenance is incomplete")
        if not review.redacted:
            raise ValueError("Evidence reviews must be redacted")
        if SECRET_VALUE_RE.search(json.dumps(review.observations)):
            raise ValueError("Evidence review contains an unredacted secret")

    @staticmethod
    def _review_dict(review: EvidenceReview) -> dict[str, Any]:
        return {"id": str(review.id), "security_finding_id": str(review.security_finding_id) if review.security_finding_id else None, "candidate_key": review.candidate_key, "target": review.target, "endpoint_or_asset": review.endpoint_or_asset, "source_agent": review.source_agent, "rule_id": review.rule_id, "finding_state": review.finding_state, "evidence_quality": review.evidence_quality, "confidence": review.confidence, "prerequisites_valid": review.prerequisites_valid, "reproducibility_state": review.reproducibility_state, "observations": review.observations, "safe_request_metadata": review.safe_request_metadata, "provenance": review.provenance, "redacted": review.redacted, "created_at": review.created_at.isoformat()}


def get_scan_full_evidence_optimized(db: Session, scan_id: uuid.UUID) -> Scan | None:
    """Eager-load all scan relationships to avoid N+1 query overhead during report generation."""
    from sqlalchemy.orm import selectinload
    return (db.query(Scan).options(selectinload(Scan.pages), selectinload(Scan.observations), selectinload(Scan.technologies), selectinload(Scan.security_findings), selectinload(Scan.performance_metrics), selectinload(Scan.accessibility_findings), selectinload(Scan.content_findings), selectinload(Scan.ai_interpretations)).filter(Scan.id == scan_id).first())


__all__ = ["EvidenceAgent", "EvidenceValidationError", "REDACTED", "RULE_VERSION", "get_scan_full_evidence_optimized", "redact_value"]
