import uuid

from sqlalchemy.orm import Session

from app.models.scan import ScanDifference

from app.models.scan import Scan


class EvidenceValidationError(Exception):
    pass


class EvidenceAgent:
    """
    A centralized gatekeeper that ensures no finding is persisted without valid evidence.
    Also provides specific validation for AI Interpretation citations.
    """
    def __init__(self, db: Session, scan_id: uuid.UUID):
        self.db = db
        self.scan_id = scan_id

    def validate_finding(self, evidence: list | None) -> None:
        """
        Validates that a finding contains at least one evidence item.
        """
        if not evidence or len(evidence) == 0:
            raise EvidenceValidationError("A finding cannot be persisted without evidence.")

    def validate_difference_citations(self, difference_id: uuid.UUID, cited_ids: list[str]) -> None:
        """Validate AI citations against one persisted structured diff only."""
        if not cited_ids:
            raise EvidenceValidationError("AI change explanations must cite at least one diff item.")
        try:
            difference_uuid = uuid.UUID(str(difference_id))
        except (TypeError, ValueError) as exc:
            raise EvidenceValidationError(f"Invalid scan difference ID: {difference_id}") from exc
        difference = self.db.query(ScanDifference).filter(ScanDifference.id == difference_uuid).first()
        if not difference:
            raise EvidenceValidationError(f"Scan difference {difference_id} not found.")
        valid_ids = {
            str(item.get("id"))
            for item in (difference.diff_data or {}).get("items", [])
            if item.get("id")
        }
        invalid = [citation for citation in cited_ids if citation not in valid_ids]
        if invalid:
            raise EvidenceValidationError(
                f"LLM hallucinated citation: diff item IDs {invalid} do not exist in this comparison."
            )

    def validate_diagnosis_citations(self, cited_ids: list[str], allowed_ids: list[str]) -> None:
        """Validate AI narrative citations against the deterministic diagnosis evidence set."""
        if not cited_ids:
            raise EvidenceValidationError("Diagnosis narrative must cite at least one diagnosis evidence item.")
        invalid = sorted(set(cited_ids) - set(allowed_ids))
        if invalid:
            raise EvidenceValidationError(
                f"AI narrative cited evidence outside the deterministic diagnosis: {invalid}"
            )

    def validate_ai_citations(self, cited_evidence_ids: list[str]) -> None:
        """
        Validates that every cited evidence ID exists and belongs to this scan.
        This prevents the LLM from hallucinating evidence.
        """
        if not cited_evidence_ids:
            raise EvidenceValidationError("AI Interpretation must cite at least one evidence ID.")

        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            raise EvidenceValidationError(f"Scan {self.scan_id} not found.")

        # Build a set of all valid evidence/finding IDs for this scan
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
                raise EvidenceValidationError(
                    f"LLM hallucinated citation: Evidence ID {cited_id} does not exist in this scan."
                )
