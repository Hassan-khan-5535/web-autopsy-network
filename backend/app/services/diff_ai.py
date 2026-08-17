from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.scan import ScanDifference
from app.services.evidence import EvidenceAgent, EvidenceValidationError
from app.services.llm import LLMClient, LLMError


class DiffExplanationEngine:
    """Generate evidence-grounded explanations for a persisted scan difference."""

    def __init__(self, db: Session):
        self.db = db
        try:
            self.llm: LLMClient | None = LLMClient()
        except LLMError:
            self.llm = None

    def explain(self, difference_id: UUID) -> dict[str, Any]:
        difference = self.db.query(ScanDifference).filter(ScanDifference.id == difference_id).first()
        if not difference:
            raise ValueError("Scan difference not found.")
        items = (difference.diff_data or {}).get("items", [])
        if not items:
            summary = "No structured changes were observed between the selected scans."
            evidence: list[str] = []
            difference.ai_summary = summary
            difference.ai_evidence = evidence
            self.db.commit()
            return {"summary": summary, "evidence": evidence, "classification": "AI_INTERPRETATION", "status": "deterministic_no_changes"}

        context = "\n".join(
            f"[DIFF_ID: {item['id']}] {item['category']} / {item['change']}: "
            f"before={item.get('before')!r}; after={item.get('after')!r}; "
            f"classification={item.get('classification')}"
            for item in items
        )
        system_prompt = """
You are the Web Autopsy Network History Doctor. Explain only the significance of changes in the supplied structured scan difference.
Return valid JSON with exactly: {"summary": "one concise paragraph", "evidence": ["exact DIFF_ID values"]}.
Every cited value must be copied exactly from a DIFF_ID in the context. Do not cite raw finding IDs. If a change is an absence, explain it as 'no longer detected/observed', never as proof of removal. Do not call a performance change a regression unless the supplied note documents the threshold.
"""
        try:
            if self.llm is None:
                raise LLMError("LLM_API_KEY is not configured; using deterministic fallback.")
            response = self.llm.generate_json(system_prompt, f"Structured comparison items:\n{context}")
            cited = [str(value) for value in response.get("evidence", [])]
            EvidenceAgent(self.db, difference.scan_b_id).validate_difference_citations(difference.id, cited)
            summary = str(response.get("summary", "The comparison contains observed changes."))
            status = "generated"
        except (LLMError, EvidenceValidationError, TypeError, ValueError) as exc:
            cited = [str(item["id"]) for item in items[:3]]
            summary = self._fallback_summary(items)
            status = "graceful_degradation"
            _ = exc

        difference.ai_summary = summary
        difference.ai_evidence = cited
        self.db.commit()
        self.db.refresh(difference)
        return {"summary": summary, "evidence": cited, "classification": "AI_INTERPRETATION", "status": status}

    @staticmethod
    def _fallback_summary(items: list[dict[str, Any]]) -> str:
        changes = ", ".join(item.get("change", "change").replace("_", " ") for item in items[:3])
        suffix = "" if len(items) <= 3 else f" and {len(items) - 3} additional change(s)"
        return f"The comparison observed {changes}{suffix}. Review the cited diff items for the before/after values; absence is reported as no longer observed rather than proof of removal."
