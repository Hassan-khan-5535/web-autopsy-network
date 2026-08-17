import uuid

from sqlalchemy.orm import Session

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
