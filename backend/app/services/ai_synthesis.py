import uuid

import structlog
from sqlalchemy.orm import Session

from app.models.scan import AIInterpretation, Scan
from app.services.evidence import EvidenceAgent, EvidenceValidationError
from app.services.llm import LLMClient, LLMError

logger = structlog.get_logger(__name__)


class AIDoctorEngine:
    def __init__(self, db: Session, scan_id: uuid.UUID):
        self.db = db
        self.scan_id = scan_id
        self.evidence_agent = EvidenceAgent(db, scan_id)
        self.llm = LLMClient()

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
            logger.warning(f"AI Doctor failed: {e}")
            return {
                "category": "ERROR",
                "subject": question,
                "statement": f"AI Interpretation failed: {e}",
                "classification": "ai_interpretation",
                "evidence": []
            }


class AISynthesisEngine:
    def __init__(self, db: Session, scan_id: uuid.UUID):
        self.db = db
        self.scan_id = scan_id
        self.evidence_agent = EvidenceAgent(db, scan_id)
        self.llm = LLMClient()

    def synthesize(self) -> None:
        """
        Generates an automatic summary of the scan when it finishes.
        """
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            return

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
            logger.error(f"AI Synthesis failed for scan {self.scan_id}: {e}")
            # We don't fail the scan, we just log and skip
