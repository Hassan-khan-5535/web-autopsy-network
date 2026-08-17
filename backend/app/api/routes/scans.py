from __future__ import annotations

import json
import time
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.config import get_settings
from app.models.scan import (
    AccessibilityFinding,
    AIInterpretation,
    AgentEvent,
    AgentTask,
    ApiEndpoint,
    ContentFinding,
    CauseOfDeathDiagnosis,
    Dependency,
    HTTPResponse,
    Observation,
    Page,
    PerformanceMetric,
    Resource,
    Scan,
    ScanDifference,
    SecurityFinding,
    Technology,
    Website,
)
from app.services.accessibility import AccessibilityEngine
from app.services.admission import AdmissionError, AdmissionService
from app.services.ai_synthesis import AIDoctorEngine, AISynthesisEngine
from app.services.api_intelligence import ApiIntelligenceAgent
from app.services.content import ContentEngine
from app.services.diff import DiffEngine, DiffValidationError
from app.services.diff_ai import DiffExplanationEngine
from app.services.diagnosis import CauseOfDeathEngine, CauseOfDeathNarrative
from app.services.crawler import CrawlerService
from app.services.network_intelligence import NetworkIntelligenceAgent
from app.services.performance import PerformanceEngine
from app.services.security import SecurityAnalysisService
from app.services.structure import StructureAgent
from app.services.technology import TechnologyDetectionService

router = APIRouter()


class ScanCreate(BaseModel):
    url: str
    authorization_acknowledged: bool
    max_depth: int | None = Field(default=None, ge=0)
    max_pages: int | None = Field(default=None, ge=1)


class ScanCompareRequest(BaseModel):
    scan_a: UUID
    scan_b: UUID


class ScanResponse(BaseModel):
    id: UUID
    website_id: UUID
    state: str
    requested_url: str
    error_reason: str | None
    max_depth: int
    max_pages: int
    diagnosis: dict[str, object] | None = None


class ObservationResponse(BaseModel):
    id: UUID
    category: str
    subject: str
    observation: str
    classification: str
    created_at: str
    page_id: UUID | None = None


def _diagnosis_response(scan: Scan) -> dict[str, object] | None:
    diagnosis = scan.cause_of_death
    return CauseOfDeathEngine.to_response(diagnosis) if diagnosis else None


def _scan_response(scan: Scan) -> dict[str, object]:
    return {
        "id": scan.id,
        "website_id": scan.website_id,
        "state": scan.state,
        "requested_url": scan.requested_url,
        "error_reason": scan.error_reason,
        "max_depth": scan.max_depth,
        "max_pages": scan.max_pages,
        "diagnosis": _diagnosis_response(scan),
    }


@router.post("/compare")
def compare_scans(req: ScanCompareRequest, db: Session = Depends(get_db)):
    try:
        diff = DiffEngine(db).compare(req.scan_a, req.scan_b, persist=True)
    except DiffValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    summary = DiffExplanationEngine(db).explain(UUID(diff["difference_id"]))
    diff["ai_summary"] = summary
    return diff


@router.post("", response_model=ScanResponse, status_code=202)
def create_scan(scan_req: ScanCreate, db: Session = Depends(get_db)):
    if not scan_req.authorization_acknowledged:
        raise HTTPException(status_code=422, detail="Authorization must be acknowledged.")

    settings = get_settings()
    parsed = urlsplit(scan_req.url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=422, detail="URL must use http/https and contain a hostname.")
    canonical_url = scan_req.url.strip()
    hostname = parsed.hostname

    max_depth = min(
        scan_req.max_depth if scan_req.max_depth is not None else settings.crawl_default_max_depth,
        settings.crawl_max_depth_cap,
    )
    max_pages = min(
        scan_req.max_pages if scan_req.max_pages is not None else settings.crawl_default_max_pages,
        settings.crawl_max_pages_cap,
    )

    website = (
        db.query(Website)
        .filter(Website.canonical_origin == hostname, Website.tenant_id == "default")
        .first()
    )
    if not website:
        website = Website(tenant_id="default", canonical_origin=hostname)
        db.add(website)
        db.commit()
        db.refresh(website)

    scan = Scan(
        website_id=website.id,
        state="QUEUED",
        requested_url=canonical_url,
        max_depth=max_depth,
        max_pages=max_pages,
        max_concurrency=min(settings.crawl_default_concurrency, settings.crawl_max_concurrency_cap),
        request_delay_ms=max(settings.crawl_default_delay_ms, settings.crawl_min_delay_ms),
        same_domain_mode=settings.crawl_same_domain_mode,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from app.services.tasks import TaskGraphCoordinator
    TaskGraphCoordinator.initialize_scan(db, scan.id)
    db.refresh(scan)
    return _scan_response(scan)


def _progress_payload(scan_id: UUID, db: Session) -> dict[str, object]:
    from app.services.tasks import TaskGraphCoordinator
    TaskGraphCoordinator.recover_stale_tasks(db)
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    tasks = db.query(AgentTask).filter(AgentTask.scan_id == scan_id).order_by(AgentTask.created_at, AgentTask.task_key).all()
    terminal = {"SUCCEEDED", "FAILED", "CANCELLED"}
    total = len(tasks)
    completed = sum(task.status in terminal for task in tasks)
    percent = round(sum(task.progress if task.status not in {"SUCCEEDED", "FAILED", "CANCELLED"} else 100 for task in tasks) / total) if total else 0
    position = None
    if scan.state == "QUEUED":
        position = db.query(Scan).filter(Scan.state == "QUEUED", Scan.cancel_requested.is_(False), Scan.queued_at <= scan.queued_at).count()
    events = db.query(AgentEvent).filter(AgentEvent.scan_id == scan_id).order_by(AgentEvent.created_at.desc()).limit(50).all()
    return {
        "scan_id": str(scan_id),
        "state": scan.state,
        "cancel_requested": scan.cancel_requested,
        "percent": percent,
        "completed_tasks": completed,
        "total_tasks": total,
        "queue_position": position,
        "estimated_wait_seconds": max(0, (position or 0) - 1) * 30 if position else 0,
        "tasks": [{
            "id": str(task.id), "task_key": task.task_key, "task_type": task.task_type,
            "queue": task.queue_name, "status": task.status, "attempt": task.attempt,
            "max_retries": task.max_retries, "progress": task.progress,
            "dependencies": task.dependency_keys or [], "error_reason": task.error_reason,
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "finished_at": task.finished_at.isoformat() if task.finished_at else None,
        } for task in tasks],
        "events": [{"type": event.event_type, "payload": event.payload or {}, "created_at": event.created_at.isoformat()} for event in reversed(events)],
    }


@router.get("/{scan_id}/progress")
def get_scan_progress(scan_id: UUID, db: Session = Depends(get_db)):
    return _progress_payload(scan_id, db)


@router.get("/{scan_id}/progress/stream")
def stream_scan_progress(scan_id: UUID):
    def event_stream():
        from app.core.database import SessionLocal
        for _ in range(60):
            with SessionLocal() as stream_db:
                payload = _progress_payload(scan_id, stream_db)
            yield f"event: progress\\ndata: {json.dumps(payload, default=str)}\\n\\n"
            if payload["state"] in {"COMPLETED", "FAILED", "PARTIAL_FAILED", "CANCELLED"}:
                break
            time.sleep(1)
    return StreamingResponse(event_stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: UUID, db: Session = Depends(get_db)):
    from app.services.tasks import TaskGraphCoordinator
    scan = TaskGraphCoordinator.cancel_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _progress_payload(scan_id, db)


@router.get("/{scan_id}/risk")
def get_scan_risk(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.state != "COMPLETED":
        raise HTTPException(status_code=409, detail="Risk ranking is available only for completed scans")
    from app.services.risk import RUBRIC_WEIGHTS, RiskImpactEngine
    return {"scan_id": str(scan_id), "rubric_weights": RUBRIC_WEIGHTS, "findings": RiskImpactEngine(db, scan_id).rank()}


@router.get("/{scan_id}/diagnosis")
def get_scan_diagnosis(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.state != "COMPLETED":
        raise HTTPException(status_code=409, detail="Diagnosis is available only for completed scans")
    diagnosis = CauseOfDeathEngine(db, scan_id).compute()
    narrative = CauseOfDeathNarrative(db).generate(diagnosis)
    return CauseOfDeathEngine(db, scan_id).persist(narrative=narrative)


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_response(scan)


@router.get("/{scan_id}/evidence")
def get_scan_evidence(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    pages_by_url = {page.canonical_url: page.id for page in scan.pages}
    observations = (
        db.query(Observation)
        .filter(Observation.scan_id == scan_id)
        .order_by(Observation.created_at, Observation.id)
        .all()
    )
    result = [
        {
            "id": str(observation.id),
            "category": observation.category,
            "subject": observation.subject,
            "observation": observation.observation,
            "classification": observation.classification,
            "created_at": observation.created_at.isoformat(),
            "page_id": str(pages_by_url[observation.subject])
            if observation.subject in pages_by_url
            else None,
        }
        for observation in observations
    ]
    findings = (
        db.query(SecurityFinding)
        .filter(SecurityFinding.scan_id == scan_id)
        .order_by(SecurityFinding.created_at, SecurityFinding.id)
        .all()
    )
    result.extend(
        {
            "id": str(finding.id),
            "category": "SECURITY",
            "subject": finding.subject,
            "observation": finding.statement,
            "classification": finding.classification,
            "created_at": finding.created_at.isoformat(),
            "page_id": str(finding.page_id) if finding.page_id else None,
        }
        for finding in findings
    )
    performance_metrics = (
        db.query(PerformanceMetric)
        .filter(PerformanceMetric.scan_id == scan_id)
        .order_by(PerformanceMetric.created_at, PerformanceMetric.id)
        .all()
    )
    result.extend(
        {
            "id": str(metric.id),
            "category": "PERFORMANCE",
            "subject": metric.metric_name,
            "observation": metric.statement,
            "classification": metric.classification,
            "created_at": metric.created_at.isoformat(),
            "page_id": str(metric.page_id) if metric.page_id else None,
        }
        for metric in performance_metrics
    )
    accessibility_findings = (
        db.query(AccessibilityFinding)
        .filter(AccessibilityFinding.scan_id == scan_id)
        .order_by(AccessibilityFinding.created_at, AccessibilityFinding.id)
        .all()
    )
    result.extend(
        {
            "id": str(finding.id),
            "category": "ACCESSIBILITY",
            "subject": finding.subject,
            "observation": finding.statement,
            "classification": finding.classification,
            "created_at": finding.created_at.isoformat(),
            "page_id": str(finding.page_id) if finding.page_id else None,
        }
        for finding in accessibility_findings
    )
    content_findings = (
        db.query(ContentFinding)
        .filter(ContentFinding.scan_id == scan_id)
        .order_by(ContentFinding.created_at, ContentFinding.id)
        .all()
    )
    result.extend(
        {
            "id": str(finding.id),
            "category": "CONTENT",
            "subject": finding.subject,
            "observation": finding.statement,
            "classification": finding.classification,
            "created_at": finding.created_at.isoformat(),
            "page_id": str(finding.page_id) if finding.page_id else None,
        }
        for finding in content_findings
    )
    ai_interpretations = (
        db.query(AIInterpretation)
        .filter(AIInterpretation.scan_id == scan_id)
        .order_by(AIInterpretation.created_at, AIInterpretation.id)
        .all()
    )
    result.extend(
        {
            "id": str(interp.id),
            "category": interp.category,
            "subject": interp.subject,
            "observation": interp.statement,
            "classification": interp.classification,
            "created_at": interp.created_at.isoformat(),
            "page_id": None,
            "evidence": interp.evidence,
        }
        for interp in ai_interpretations
    )
    return result

class QuestionRequest(BaseModel):
    question: str

@router.post("/{scan_id}/ask")
def ask_scan_question(scan_id: UUID, req: QuestionRequest, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    # Rate limit: Max 5 questions per scan
    current_questions_count = db.query(AIInterpretation).filter(
        AIInterpretation.scan_id == scan_id, 
        AIInterpretation.category != "SUMMARY"
    ).count()
    
    if current_questions_count >= 5:
        raise HTTPException(status_code=429, detail="Rate limit exceeded: Max 5 questions per scan.")
        
    change_question = any(
        phrase in req.question.lower()
        for phrase in ("what changed", "previous scan", "last scan", "since the prior", "history")
    )
    if change_question:
        previous = (
            db.query(Scan)
            .filter(
                Scan.website_id == scan.website_id,
                Scan.id != scan.id,
                Scan.state == "COMPLETED",
                Scan.created_at < scan.created_at,
            )
            .order_by(Scan.created_at.desc(), Scan.id.desc())
            .first()
        )
        if not previous:
            answer_data = {
                "category": "HISTORY",
                "subject": "History unavailable",
                "statement": "Insufficient evidence to answer this question because no earlier completed scan exists for this website.",
                "classification": "ai_interpretation",
                "evidence": [],
            }
        else:
            try:
                diff = DiffEngine(db).compare(previous.id, scan.id, persist=True)
                summary = DiffExplanationEngine(db).explain(UUID(diff["difference_id"]))
                answer_data = {
                    "category": "HISTORY",
                    "subject": "Changes since the previous scan",
                    "statement": summary["summary"],
                    "classification": "ai_interpretation",
                    "evidence": summary["evidence"],
                    "difference_id": diff["difference_id"],
                }
            except DiffValidationError as exc:
                answer_data = {
                    "category": "ERROR",
                    "subject": req.question,
                    "statement": str(exc),
                    "classification": "ai_interpretation",
                    "evidence": [],
                }
    else:
        engine = AIDoctorEngine(db, scan_id)
        answer_data = engine.ask_question(req.question)
    
    if answer_data["category"] != "ERROR":
        interp = AIInterpretation(
            scan_id=scan_id,
            category=answer_data["category"],
            subject=answer_data["subject"],
            statement=answer_data["statement"],
            evidence=answer_data.get("evidence", [])
        )
        db.add(interp)
        db.commit()
        db.refresh(interp)
        answer_data["id"] = str(interp.id)
        answer_data["created_at"] = interp.created_at.isoformat()
    
    return answer_data


@router.get("/{scan_id}/accessibility")
def get_scan_accessibility(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = (
        db.query(AccessibilityFinding)
        .filter(AccessibilityFinding.scan_id == scan_id)
        .order_by(AccessibilityFinding.classification, AccessibilityFinding.subject, AccessibilityFinding.created_at)
        .all()
    )
    return [
        {
            "id": str(finding.id),
            "category": finding.category,
            "subject": finding.subject,
            "statement": finding.statement,
            "classification": finding.classification,
            "disclaimer": finding.disclaimer,
            "page_id": str(finding.page_id) if finding.page_id else None,
            "evidence": finding.evidence,
            "created_at": finding.created_at.isoformat(),
        }
        for finding in findings
    ]


@router.get("/{scan_id}/content")
def get_scan_content(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = (
        db.query(ContentFinding)
        .filter(ContentFinding.scan_id == scan_id)
        .order_by(ContentFinding.classification, ContentFinding.subject, ContentFinding.created_at)
        .all()
    )
    return [
        {
            "id": str(finding.id),
            "category": finding.category,
            "subject": finding.subject,
            "statement": finding.statement,
            "classification": finding.classification,
            "page_id": str(finding.page_id) if finding.page_id else None,
            "evidence": finding.evidence,
            "created_at": finding.created_at.isoformat(),
        }
        for finding in findings
    ]


@router.get("/{scan_id}/technologies")
def get_scan_technologies(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    technologies = (
        db.query(Technology)
        .filter(Technology.scan_id == scan_id)
        .order_by(Technology.category, Technology.confidence.desc(), Technology.canonical_name)
        .all()
    )
    return [
        {
            "id": str(technology.id),
            "name": technology.canonical_name,
            "category": technology.category,
            "classification": technology.classification,
            "confidence": technology.confidence,
            "confidence_band": technology.confidence_band,
            "rule_version": technology.rule_version,
            "evidence": [
                {
                    "id": str(evidence.id),
                    "type": evidence.signal_type,
                    "source": evidence.source,
                    "observation": evidence.observation,
                    "match_rule": evidence.match_rule,
                    "weight": evidence.match_weight,
                    "page_id": str(evidence.page_id) if evidence.page_id else None,
                    "created_at": evidence.created_at.isoformat(),
                }
                for evidence in technology.evidence
            ],
        }
        for technology in technologies
    ]


@router.get("/{scan_id}/security")
def get_scan_security(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = (
        db.query(SecurityFinding)
        .filter(SecurityFinding.scan_id == scan_id)
        .order_by(SecurityFinding.severity, SecurityFinding.subject, SecurityFinding.created_at)
        .all()
    )
    return [
        {
            "id": str(finding.id),
            "category": finding.category,
            "subject": finding.subject,
            "statement": finding.statement,
            "classification": finding.classification,
            "confidence": finding.confidence,
            "confidence_band": finding.confidence_band,
            "severity": finding.severity,
            "rule_id": finding.rule_id,
            "rule_version": finding.rule_version,
            "limitations": finding.limitations,
            "page_id": str(finding.page_id) if finding.page_id else None,
            "evidence": finding.evidence,
            "created_at": finding.created_at.isoformat(),
        }
        for finding in findings
    ]


@router.get("/{scan_id}/performance")
def get_scan_performance(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    metrics = (
        db.query(PerformanceMetric)
        .filter(PerformanceMetric.scan_id == scan_id)
        .order_by(PerformanceMetric.scope, PerformanceMetric.page_id, PerformanceMetric.metric_name)
        .all()
    )
    return {
        "scan_id": str(scan_id),
        "rule_version": "phase8-v1",
        "metrics": [
            {
                "id": str(metric.id),
                "scope": metric.scope,
                "metric_name": metric.metric_name,
                "value": metric.value,
                "unit": metric.unit,
                "classification": metric.classification,
                "confidence": metric.confidence,
                "confidence_band": metric.confidence_band,
                "capture_mode": metric.capture_mode,
                "statement": metric.statement,
                "limitations": metric.limitations,
                "page_id": str(metric.page_id) if metric.page_id else None,
                "evidence": metric.evidence,
                "created_at": metric.created_at.isoformat(),
            }
            for metric in metrics
        ],
        "page_metrics": [
            {
                "page_id": str(page.id),
                "url": page.canonical_url,
                "metrics": [
                    {
                        "id": str(metric.id),
                        "scope": metric.scope,
                        "metric_name": metric.metric_name,
                        "value": metric.value,
                        "unit": metric.unit,
                        "classification": metric.classification,
                        "confidence": metric.confidence,
                        "confidence_band": metric.confidence_band,
                        "capture_mode": metric.capture_mode,
                        "statement": metric.statement,
                        "limitations": metric.limitations,
                        "page_id": str(metric.page_id) if metric.page_id else None,
                        "evidence": metric.evidence,
                        "created_at": metric.created_at.isoformat(),
                    }
                    for metric in metrics
                    if metric.page_id == page.id
                ],
            }
            for page in sorted(scan.pages, key=lambda item: (item.depth, item.canonical_url))
        ],
        "site_metrics": [
            {
                "id": str(metric.id),
                "scope": metric.scope,
                "metric_name": metric.metric_name,
                "value": metric.value,
                "unit": metric.unit,
                "classification": metric.classification,
                "confidence": metric.confidence,
                "confidence_band": metric.confidence_band,
                "capture_mode": metric.capture_mode,
                "statement": metric.statement,
                "limitations": metric.limitations,
                "page_id": str(metric.page_id) if metric.page_id else None,
                "evidence": metric.evidence,
                "created_at": metric.created_at.isoformat(),
            }
            for metric in metrics
            if metric.scope == "site"
        ],
        "diagnostics": [
            {
                "id": str(metric.id),
                "scope": metric.scope,
                "metric_name": metric.metric_name,
                "value": metric.value,
                "unit": metric.unit,
                "classification": metric.classification,
                "confidence": metric.confidence,
                "confidence_band": metric.confidence_band,
                "statement": metric.statement,
                "limitations": metric.limitations,
                "page_id": str(metric.page_id) if metric.page_id else None,
                "evidence": metric.evidence,
                "created_at": metric.created_at.isoformat(),
            }
            for metric in metrics
            if metric.metric_name.startswith("diagnosis:")
        ],
    }


@router.get("/{scan_id}/pages")
def get_scan_pages(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    pages = (
        db.query(Page)
        .filter(Page.scan_id == scan_id)
        .order_by(Page.depth, Page.canonical_url)
        .all()
    )
    return [
        {
            "id": str(page.id),
            "url": page.canonical_url,
            "canonical_url": page.canonical_url,
            "depth": page.depth,
            "status_code": page.status_code,
            "title": page.title,
            "discovered_from": page.discovered_from.canonical_url if page.discovered_from else None,
            "discovered_from_page_id": str(page.discovered_from_page_id)
            if page.discovered_from_page_id
            else None,
        }
        for page in pages
    ]


@router.get("/{scan_id}/architecture")
def get_scan_architecture(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return StructureAgent(db, scan_id).analyze()


@router.get("/{scan_id}/dependencies")
def get_scan_dependencies(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    dependencies = (
        db.query(Dependency)
        .filter(Dependency.scan_id == scan_id)
        .order_by(Dependency.category, Dependency.domain)
        .all()
    )
    return [
        {
            "id": str(dep.id),
            "domain": dep.domain,
            "category": dep.category,
            "classification": dep.classification,
            "confidence": dep.confidence,
            "reference_count": dep.reference_count,
            "sample_resource_urls": dep.sample_resource_urls or [],
            "created_at": dep.created_at.isoformat(),
        }
        for dep in dependencies
    ]


@router.get("/{scan_id}/api-endpoints")
def get_scan_api_endpoints(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    endpoints = (
        db.query(ApiEndpoint)
        .filter(ApiEndpoint.scan_id == scan_id)
        .order_by(ApiEndpoint.url_or_path, ApiEndpoint.http_method)
        .all()
    )
    return [
        {
            "id": str(ep.id),
            "url_or_path": ep.url_or_path,
            "http_method": ep.http_method,
            "content_type": ep.content_type,
            "classification": ep.classification,
            "confidence": ep.confidence,
            "discovered_from_source": ep.discovered_from_source,
            "created_at": ep.created_at.isoformat(),
        }
        for ep in endpoints
    ]


@router.get("/{scan_id}/pages/{page_id}/rendered")
def get_page_rendered(scan_id: UUID, page_id: UUID, db: Session = Depends(get_db)):
    page = db.query(Page).filter(Page.id == page_id, Page.scan_id == scan_id).first()
    if not page:
        raise HTTPException(status_code=404, detail="Page not found for this scan.")

    resp = db.query(HTTPResponse).filter(HTTPResponse.page_id == page.id).first()
    if not resp:
        raise HTTPException(status_code=404, detail="No HTTP response recorded for page.")

    resources = db.query(Resource).filter(Resource.page_id == page.id).all()
    observations = db.query(Observation).filter(Observation.scan_id == scan_id).all()

    return {
        "page_id": str(page.id),
        "url": page.canonical_url,
        "raw_body": resp.raw_body,
        "rendered_body": resp.rendered_body,
        "timing_data": resp.timing_data,
        "resources": [
            {
                "id": str(r.id),
                "url": r.url,
                "type": r.type,
                "capture_source": r.capture_source,
            }
            for r in resources
        ],
        "console_logs": [
            {
                "id": str(o.id),
                "type": o.subject,
                "text": o.observation,
            }
            for o in observations
            if o.category == "BROWSER_CONSOLE"
        ],
    }
