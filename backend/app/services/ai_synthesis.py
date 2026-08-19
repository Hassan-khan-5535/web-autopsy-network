import uuid

import structlog
from uuid import UUID
from sqlalchemy.orm import Session

from app.models.scan import AIInterpretation, Scan
from app.services.evidence import EvidenceAgent, EvidenceValidationError
from app.services.diagnosis import CauseOfDeathEngine, CauseOfDeathNarrative
from app.services.llm import LLMClient, LLMError

logger = structlog.get_logger(__name__)


def wrap_untrusted_content(content: str) -> str:
    """Wrap untrusted HTML/text scraped from target pages in XML delimiters for prompt injection isolation."""
    escaped = content.replace("</untrusted_scanned_content>", "[ESCAPED_TAG]")
    return f"<untrusted_scanned_content>\n{escaped}\n</untrusted_scanned_content>"


class AIDoctorEngine:
    def __init__(self, db: Session, scan_id: UUID):
        self.db = db
        self.scan_id = scan_id
        self.evidence_agent = EvidenceAgent(db, scan_id)
        try:
            self.llm: LLMClient | None = LLMClient()
        except LLMError:
            self.llm = None

    def _build_context(self) -> str:
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            return ""

        context_lines = []
        
        # Observations
        for obs in scan.observations:
            context_lines.append(f"[ID: {obs.id}] {obs.category} - {obs.subject}: {obs.observation}")
            
        # Security Findings
        for sf in scan.security_findings:
            context_lines.append(f"[ID: {sf.id}] SECURITY ({sf.severity}) - {sf.subject}: {sf.statement}")
            
        # Performance Metrics
        for pm in scan.performance_metrics:
            if pm.metric_name.startswith("diagnosis:"):
                context_lines.append(f"[ID: {pm.id}] PERFORMANCE - {pm.metric_name}: {pm.statement}")
            else:
                context_lines.append(f"[ID: {pm.id}] PERFORMANCE - {pm.metric_name}: {pm.value} {pm.unit}")

        # Accessibility Findings
        for af in scan.accessibility_findings:
            context_lines.append(f"[ID: {af.id}] ACCESSIBILITY - {af.subject}: {af.statement}")
            
        # Content Findings
        for cf in scan.content_findings:
            context_lines.append(f"[ID: {cf.id}] CONTENT - {cf.subject}: {cf.statement}")
            
        return "\n".join(context_lines)

    def _fallback_answer(self, question: str, reason: str) -> dict:
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            return {
                "category": "GENERAL",
                "subject": "Evidence unavailable",
                "statement": "No scan evidence is available for this question.",
                "classification": "deterministic_fallback",
                "evidence": [],
            }

        question_lower = question.lower()
        if "performance" in question_lower or "speed" in question_lower or "load" in question_lower:
            candidates = list(scan.performance_metrics)
            category = "PERFORMANCE"
        elif "access" in question_lower or "wcag" in question_lower or "keyboard" in question_lower:
            candidates = list(scan.accessibility_findings)
            category = "ACCESSIBILITY"
        elif "content" in question_lower or "seo" in question_lower or "metadata" in question_lower:
            candidates = list(scan.content_findings)
            category = "CONTENT"
        else:
            candidates = list(scan.security_findings) or list(scan.observations)
            category = "SECURITY" if scan.security_findings else "GENERAL"

        cited_ids: list[str] = []
        statements: list[str] = []
        for item in candidates[:3]:
            item_id = getattr(item, "id", None)
            statement = getattr(item, "statement", None) or getattr(item, "observation", None)
            subject = getattr(item, "subject", None) or getattr(item, "metric_name", None)
            if item_id and statement:
                cited_ids.append(str(item_id))
                statements.append(f"{subject}: {statement}")

        if not statements:
            return {
                "category": category,
                "subject": "No matching findings",
                "statement": "The deterministic evidence store contains no findings matching this question.",
                "classification": "deterministic_fallback",
                "evidence": [],
            }

        return {
            "category": category,
            "subject": "Deterministic evidence summary",
            "statement": "External AI interpretation is unavailable, so this answer uses the stored deterministic evidence instead.\n\n" + "\n".join(statements),
            "classification": "deterministic_fallback",
            "evidence": cited_ids,
        }

    def ask_question(self, question: str) -> dict:
        """
        Answers a user's question about the scan, strictly citing evidence.
        """
        context = self._build_context()
        
        system_prompt = """
You are the AI Doctor for the Web Autopsy Network. You analyze website forensic data.
You MUST answer the user's question using ONLY the provided evidence.
You MUST output your response in valid JSON matching exactly this schema:
{
  "category": "string (e.g., 'PERFORMANCE', 'SECURITY', 'GENERAL')",
  "subject": "string (a short title for your answer)",
  "statement": "string (your detailed answer)",
  "evidence": ["string (the exact ID of the evidence cited)"]
}
If you cannot answer the question based on the evidence, state "Insufficient evidence to answer this question." in the statement, and leave evidence empty [].
DO NOT hallucinate evidence IDs. ONLY use the IDs enclosed in [ID: ...] from the context.
"""
        user_prompt = f"Evidence Context:\n{context}\n\nQuestion: {question}"

        try:
            if self.llm is None:
                raise LLMError("LLM_API_KEY is not configured.")
            response = self.llm.generate_json(system_prompt, user_prompt)
            cited_ids = response.get("evidence", [])
            
            # Validate citations if any were provided
            if cited_ids:
                self.evidence_agent.validate_ai_citations(cited_ids)
                
            return {
                "category": response.get("category", "GENERAL"),
                "subject": response.get("subject", question),
                "statement": response.get("statement", "No answer provided."),
                "classification": "ai_interpretation",
                "evidence": cited_ids
            }
            
        except (LLMError, EvidenceValidationError) as e:
            logger.warning(f"AI Doctor fallback used: {e}")
            return self._fallback_answer(question, str(e))


class AISynthesisEngine:
    def __init__(self, db: Session, scan_id: UUID):
        self.db = db
        self.scan_id = scan_id
        self.evidence_agent = EvidenceAgent(db, scan_id)
        try:
            self.llm: LLMClient | None = LLMClient()
        except LLMError:
            self.llm = None

    def synthesize(self) -> None:
        """
        Generates an automatic summary of the scan when it finishes.
        """
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            return

        diagnosis_engine = CauseOfDeathEngine(self.db, self.scan_id)
        diagnosis = diagnosis_engine.compute(allow_in_progress=True)
        narrative = CauseOfDeathNarrative(self.db).generate(diagnosis)
        diagnosis_engine.persist(narrative=narrative, allow_in_progress=True)

        engine = AIDoctorEngine(self.db, self.scan_id)
        context = engine._build_context()
        
        system_prompt = """
You are the AI Doctor for the Web Autopsy Network. 
Analyze the provided forensic evidence and generate a high-level executive summary of the website's health, security, and performance.
You MUST output your response in valid JSON matching exactly this schema:
{
  "subject": "Executive Summary",
  "statement": "string (your detailed executive summary paragraph)",
  "evidence": ["string (list of 2-5 exact IDs of the most critical evidence items cited)"]
}
DO NOT hallucinate evidence IDs. ONLY use the IDs enclosed in [ID: ...] from the context.
"""
        user_prompt = f"Evidence Context:\n{context}\n\nPlease generate the Executive Summary."
        
        try:
            if self.llm is None:
                raise LLMError("LLM_API_KEY is not configured.")
            response = self.llm.generate_json(system_prompt, user_prompt)
            cited_ids = response.get("evidence", [])
            
            self.evidence_agent.validate_ai_citations(cited_ids)
            
            interpretation = AIInterpretation(
                scan_id=self.scan_id,
                category="SUMMARY",
                subject=response.get("subject", "Executive Summary"),
                statement=response.get("statement", ""),
                evidence=cited_ids
            )
            self.db.add(interpretation)
            self.db.commit()
            
        except (LLMError, EvidenceValidationError) as e:
            logger.warning(f"AI Synthesis fallback used for scan {self.scan_id}: {e}")
            fallback_evidence = [str(item.id) for item in list(scan.security_findings)[:3]]
            if not fallback_evidence:
                fallback_evidence = [str(item.id) for item in list(scan.observations)[:3]]
            if fallback_evidence:
                interpretation = AIInterpretation(
                    scan_id=self.scan_id,
                    category="SUMMARY",
                    subject="Deterministic evidence summary",
                    statement="External AI synthesis is unavailable. The report remains complete using deterministic analysis and stored evidence.",
                    evidence=fallback_evidence,
                )
                self.db.add(interpretation)
                self.db.commit()
