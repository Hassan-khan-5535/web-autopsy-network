from __future__ import annotations

import hashlib
import io
import json
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.config import get_settings
from app.models.scan import (
    AccessibilityFinding,
    AssessmentAuditEvent,
    AssessmentAuthorization,
    AIInterpretation,
    AgentEvent,
    AgentTask,
    ApiEndpoint,
    ContentFinding,
    CauseOfDeathDiagnosis,
    Dependency,
    HTTPObservation,
    HTTPResponse,
    Observation,
    Page,
    PerformanceMetric,
    Resource,
    ReconAsset,
    ReconEndpoint,
    ReconParameter,
    RecurringScanSchedule,
    Scan,
    ScanDifference,
    SecurityFinding,
    Technology,
    Website,
)
from app.services.accessibility import AccessibilityEngine
from app.services.admission import AdmissionError, AdmissionService
from app.services.assessment import (
    AssessmentPolicyError,
    append_audit_event,
    authorization_public,
    consent_hash,
    encrypt_secret,
    normalize_authentication,
    normalize_domains,
    normalize_paths,
    hostname_allowed,
    path_allowed,
    profile_policy,
)
from app.services.ai_synthesis import AIDoctorEngine, AISynthesisEngine
from app.services.api_intelligence import ApiIntelligenceAgent
from app.services.api_agent import APIAgent
from app.services.vulnerability import VulnerabilityAgent
from app.services.secrets import SecretsAgent
from app.services.cve_intelligence import CVEIntelligenceAgent
from app.services.evidence import EvidenceAgent
from app.services.configuration import CONFIGURATION_RULES, RULE_VERSION as CONFIGURATION_RULE_VERSION
from app.services.correlation import CorrelationAgent
from app.services.risk import RiskAgent
from app.services.reporting import SecurityReportService
from app.services.content import ContentEngine
from app.services.continuous import PostureTimelineService, RecurringScheduleError, RecurringScheduleService, as_utc
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


class AuthenticationConfig(BaseModel):
    type: Literal["cookie", "header", "basic"]
    name: str | None = None
    value: str | None = None
    username: str | None = None
    password: str | None = None


class ScanCreate(BaseModel):
    url: str
    authorization_acknowledged: bool
    max_depth: int | None = Field(default=None, ge=0)
    max_pages: int | None = Field(default=None, ge=1)
    assessment_profile: Literal["safe", "normal", "aggressive"] = "safe"
    allowed_paths: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    max_requests: int | None = Field(default=None, ge=1)
    max_concurrency: int | None = Field(default=None, ge=1)
    rate_limit_per_host_ms: int | None = Field(default=None, ge=100)
    robots_override: bool = False
    authentication: AuthenticationConfig | None = None
    test_account_ref: str | None = Field(default=None, max_length=255)
    expires_at: datetime | None = None
    recon_mode: Literal["passive_only", "active_safe"] = "passive_only"


class ScanCompareRequest(BaseModel):
    scan_a: UUID
    scan_b: UUID


class RecurringScheduleUpdate(BaseModel):
    enabled: bool


class ScanResponse(BaseModel):
    id: UUID
    website_id: UUID
    state: str
    status: str | None = None
    requested_url: str
    error_reason: str | None
    max_depth: int
    max_pages: int
    max_concurrency: int | None = None
    request_delay_ms: int | None = None
    same_domain_mode: str | None = None
    assessment_profile: str | None = None
    max_requests: int | None = None
    recon_mode: str | None = None
    requests_used: int | None = None
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
        "status": (
            "queued" if scan.state == "QUEUED" else
            "paused" if scan.state == "PAUSED" else
            "completed" if scan.state == "COMPLETED" else
            "cancelled" if scan.state == "CANCELLED" else
            "failed" if scan.state in {"FAILED", "PARTIAL_FAILED"} else
            "running"
        ),
        "requested_url": scan.requested_url,
        "error_reason": scan.error_reason,
        "max_depth": scan.max_depth,
        "max_pages": scan.max_pages,
        "max_concurrency": scan.max_concurrency,
        "request_delay_ms": scan.request_delay_ms,
        "same_domain_mode": scan.same_domain_mode,
        "assessment_profile": scan.assessment_profile or "legacy_passive",
        "max_requests": scan.max_requests or scan.max_pages,
        "recon_mode": scan.recon_mode or "passive_only",
        "requests_used": scan.requests_used,
        "diagnosis": _diagnosis_response(scan),
    }


def _schedule_response(schedule: RecurringScanSchedule) -> dict[str, object]:
    return {
        "id": str(schedule.id),
        "website_id": str(schedule.website_id),
        "source_scan_id": str(schedule.source_scan_id),
        "target_url": schedule.target_url,
        "cadence": schedule.cadence,
        "enabled": schedule.enabled,
        "next_run_at": as_utc(schedule.next_run_at).isoformat(),
        "last_run_at": as_utc(schedule.last_run_at).isoformat() if schedule.last_run_at else None,
        "last_scan_id": str(schedule.last_scan_id) if schedule.last_scan_id else None,
        "blocked_at": as_utc(schedule.blocked_at).isoformat() if schedule.blocked_at else None,
        "last_block_reason": schedule.last_block_reason,
        "created_by": schedule.created_by,
        "created_at": as_utc(schedule.created_at).isoformat(),
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


@router.get("/{scan_id}/posture-timeline")
def get_scan_posture_timeline(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return PostureTimelineService(db).timeline(scan.website_id)


@router.post("/{scan_id}/recurring-schedule")
def create_weekly_recurring_schedule(
    scan_id: UUID,
    db: Session = Depends(get_db),
    actor_id: str | None = Header(default=None, alias="X-Actor-ID"),
):
    try:
        schedule = RecurringScheduleService(db).create_weekly(scan_id, actor_id.strip() if actor_id and actor_id.strip() else "anonymous")
    except RecurringScheduleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _schedule_response(schedule)


@router.get("/{scan_id}/recurring-schedule")
def get_recurring_schedule(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    schedule = db.query(RecurringScanSchedule).filter(
        (RecurringScanSchedule.source_scan_id == scan_id)
        | (RecurringScanSchedule.id == scan.recurring_schedule_id)
    ).order_by(RecurringScanSchedule.created_at.desc()).first()
    return _schedule_response(schedule) if schedule else None


@router.patch("/recurring-schedules/{schedule_id}")
def update_recurring_schedule(
    schedule_id: UUID,
    update: RecurringScheduleUpdate,
    db: Session = Depends(get_db),
    actor_id: str | None = Header(default=None, alias="X-Actor-ID"),
):
    schedule = db.query(RecurringScanSchedule).filter(RecurringScanSchedule.id == schedule_id).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Recurring schedule not found")
    schedule.enabled = update.enabled
    if update.enabled:
        schedule.blocked_at = None
        schedule.last_block_reason = None
        if as_utc(schedule.next_run_at) < datetime.now(UTC):
            schedule.next_run_at = datetime.now(UTC) + timedelta(days=7)
    db.commit()
    db.refresh(schedule)
    return _schedule_response(schedule)


@router.post("", response_model=ScanResponse, status_code=202)
def create_scan(
    scan_req: ScanCreate,
    db: Session = Depends(get_db),
    actor_id: str | None = Header(default=None, alias="X-Actor-ID"),
):
    if not scan_req.authorization_acknowledged:
        raise HTTPException(status_code=422, detail="Authorization must be acknowledged.")

    settings = get_settings()
    actor_value = actor_id.strip() if isinstance(actor_id, str) and actor_id.strip() else "anonymous"
    try:
        canonical_url = AdmissionService.normalize_url(scan_req.url)
        parsed = urlsplit(canonical_url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        allowed_domains = normalize_domains(scan_req.allowed_domains) or [hostname]
        allowed_paths = normalize_paths(scan_req.allowed_paths)
        excluded_paths = normalize_paths(scan_req.excluded_paths)
        if not hostname_allowed(hostname, allowed_domains):
            raise AssessmentPolicyError("The target hostname must be included in allowed_domains.")
        if scan_req.assessment_profile == "aggressive" and not scan_req.allowed_domains:
            raise AssessmentPolicyError("Aggressive assessment requires explicit allowed-domain confirmation.")
        if not path_allowed(canonical_url, allowed_paths, excluded_paths):
            raise AssessmentPolicyError("The target URL is outside the allowed/excluded path scope.")
        policy = profile_policy(
            scan_req.assessment_profile,
            max_depth=scan_req.max_depth,
            max_requests=scan_req.max_requests,
            max_concurrency=scan_req.max_concurrency,
            rate_limit_per_host_ms=scan_req.rate_limit_per_host_ms,
        )
        if scan_req.robots_override and scan_req.assessment_profile not in {
            item.strip() for item in settings.assessment_robots_override_profiles.split(",") if item.strip()
        }:
            raise AssessmentPolicyError(
                "robots_override is not permitted for this assessment profile by deployment policy."
            )
        auth_type, auth_payload = normalize_authentication(
            scan_req.authentication.model_dump(exclude_none=True) if scan_req.authentication else None
        )
    except (AdmissionError, AssessmentPolicyError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    max_pages = min(
        scan_req.max_pages if scan_req.max_pages is not None else policy["max_requests"],
        policy["max_requests"],
    )
    if scan_req.assessment_profile == "safe":
        max_pages = min(max_pages, settings.assessment_safe_max_requests)

    website = (
        db.query(Website)
        .filter(Website.canonical_origin == hostname, Website.tenant_id == "default")
        .first()
    )
    if not website:
        website = Website(tenant_id="default", canonical_origin=hostname)
        db.add(website)
        db.flush()

    scan = Scan(
        website_id=website.id,
        state="QUEUED",
        requested_url=canonical_url,
        max_depth=policy["max_depth"],
        max_pages=max_pages,
        max_concurrency=policy["max_concurrency"],
        request_delay_ms=policy["rate_limit_per_host_ms"],
        same_domain_mode=settings.crawl_same_domain_mode,
        assessment_profile=scan_req.assessment_profile,
        max_requests=policy["max_requests"],
        recon_mode=scan_req.recon_mode,
    )
    db.add(scan)
    db.flush()

    authorized_at = datetime.now(UTC)
    auth_fingerprint = hashlib.sha256(
        json.dumps(auth_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16] if auth_payload else None
    scope_json = {
        "target_url": canonical_url,
        "allowed_domains": allowed_domains,
        "allowed_paths": allowed_paths,
        "excluded_paths": excluded_paths,
        "assessment_profile": scan_req.assessment_profile,
        "robots_override": scan_req.robots_override,
        "authentication_type": auth_type,
        "authentication_secret_fingerprint": auth_fingerprint,
        "max_depth": policy["max_depth"],
        "max_requests": policy["max_requests"],
        "max_concurrency": policy["max_concurrency"],
        "rate_limit_per_host_ms": policy["rate_limit_per_host_ms"],
        "recon_mode": scan_req.recon_mode,
    }
    consent_payload = {
        **scope_json,
        "actor_id": actor_value,
        "test_account_ref": scan_req.test_account_ref,
        "authorized_at": authorized_at.isoformat(),
        "expires_at": scan_req.expires_at.isoformat() if scan_req.expires_at else None,
        "policy_version": settings.assessment_policy_version,
    }
    authorization = AssessmentAuthorization(
        scan_id=scan.id,
        authorization_type="acknowledged" if auth_type == "none" else f"acknowledged_with_{auth_type}",
        actor_id=actor_value,
        target_url=canonical_url,
        allowed_paths=allowed_paths,
        excluded_paths=excluded_paths,
        allowed_domains=allowed_domains,
        assessment_profile=scan_req.assessment_profile,
        robots_override=scan_req.robots_override,
        max_depth=policy["max_depth"],
        max_pages=max_pages,
        max_requests=policy["max_requests"],
        max_concurrency=policy["max_concurrency"],
        rate_limit_per_host_ms=policy["rate_limit_per_host_ms"],
        test_account_ref=scan_req.test_account_ref,
        auth_secret_encrypted=encrypt_secret(auth_payload) if auth_payload else None,
        auth_secret_fingerprint=auth_fingerprint,
        consent_hash=consent_hash(consent_payload),
        authorized_at=authorized_at,
        expires_at=scan_req.expires_at,
        policy_version=settings.assessment_policy_version,
        scope_json=scope_json,
    )
    db.add(authorization)
    db.flush()
    append_audit_event(
        db,
        scan_id=scan.id,
        authorization_id=authorization.id,
        event_type="AUTHORIZATION_RECORDED",
        actor_id=actor_value,
        payload={
            "target_url": canonical_url,
            "assessment_profile": scan_req.assessment_profile,
            "scope": scope_json,
            "consent_hash": authorization.consent_hash,
        },
    )
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
        "status": (
            "queued" if scan.state == "QUEUED" else
            "paused" if scan.state == "PAUSED" else
            "completed" if scan.state == "COMPLETED" else
            "cancelled" if scan.state == "CANCELLED" else
            "failed" if scan.state in {"FAILED", "PARTIAL_FAILED"} else
            "running"
        ),
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
            "dependencies": task.dependency_keys or [], "event_requirements": task.event_requirements or [], "error_reason": task.error_reason,
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "finished_at": task.finished_at.isoformat() if task.finished_at else None,
            "deadline_at": task.deadline_at.isoformat() if task.deadline_at else None,
        } for task in tasks],
        "events": [{"type": event.event_type, "event_key": event.event_key, "payload": event.payload or {}, "created_at": event.created_at.isoformat()} for event in reversed(events)],
        "orchestration": scan.orchestration_state or {},
        "budget": scan.orchestration_budget or {},
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


@router.get("/{scan_id}/report")
def get_security_report(scan_id: UUID, db: Session = Depends(get_db)):
    try:
        return SecurityReportService(db).build(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/{scan_id}/report/export/{format_name}")
def export_security_report(scan_id: UUID, format_name: Literal["pdf", "json", "sarif"], db: Session = Depends(get_db)):
    service = SecurityReportService(db)
    try:
        if format_name == "pdf":
            payload = service.pdf(scan_id)
            media_type = "application/pdf"
            filename = f"web-autopsy-report-{scan_id}.pdf"
        elif format_name == "sarif":
            payload = json.dumps(service.sarif(scan_id), indent=2, sort_keys=True).encode("utf-8")
            media_type = "application/sarif+json"
            filename = f"web-autopsy-report-{scan_id}.sarif.json"
        else:
            payload = json.dumps(service.build(scan_id), indent=2, sort_keys=True).encode("utf-8")
            media_type = "application/json"
            filename = f"web-autopsy-report-{scan_id}.json"
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return StreamingResponse(io.BytesIO(payload), media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


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
    http_observations = (
        db.query(HTTPObservation)
        .filter(HTTPObservation.scan_id == scan_id)
        .order_by(HTTPObservation.created_at, HTTPObservation.id)
        .all()
    )
    result.extend(
        {
            "id": str(item.id),
            "category": "HTTP_AGENT",
            "subject": item.subject,
            "observation": f"{item.observation_type}: {json.dumps(item.value or {}, sort_keys=True)}",
            "classification": item.classification,
            "created_at": item.created_at.isoformat(),
            "page_id": str(item.page_id) if item.page_id else None,
            "evidence": [item.source],
        }
        for item in http_observations
    )
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


@router.get("/{scan_id}/api-agent")
def get_scan_api_agent(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return APIAgent(db, scan_id).report()


@router.get("/{scan_id}/vulnerability-agent")
def get_scan_vulnerability_agent(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return VulnerabilityAgent(db, scan_id).report()


@router.get("/{scan_id}/secrets")
def get_scan_secrets(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return SecretsAgent(db, scan_id).report()


@router.get("/{scan_id}/cve-intelligence")
def get_scan_cve_intelligence(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return CVEIntelligenceAgent(db, scan_id, fetch_feeds=False).report()


@router.get("/{scan_id}/evidence-agent")
def get_scan_evidence_reviews(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return EvidenceAgent(db, scan_id).report()


@router.get("/{scan_id}/attack-surface-graph")
def get_scan_attack_surface_graph(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return CorrelationAgent(db, scan_id).report()


@router.get("/{scan_id}/risk-prioritization")
def get_scan_risk_prioritization(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return RiskAgent(db, scan_id).report()


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


@router.get("/{scan_id}/assessment/authorization")
def get_assessment_authorization(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    authorization = db.query(AssessmentAuthorization).filter(AssessmentAuthorization.scan_id == scan_id).first()
    if authorization:
        return authorization_public(authorization)
    hostname = (urlsplit(scan.requested_url).hostname or "").lower().rstrip(".")
    return {
        "id": None,
        "scan_id": str(scan.id),
        "authorization_type": "legacy_passive",
        "actor_id": "legacy",
        "target_url": scan.requested_url,
        "allowed_paths": [],
        "excluded_paths": [],
        "allowed_domains": [hostname] if hostname else [],
        "assessment_profile": "legacy_passive",
        "robots_override": False,
        "max_depth": scan.max_depth,
        "max_pages": scan.max_pages,
        "max_requests": scan.max_requests or scan.max_pages,
        "max_concurrency": scan.max_concurrency,
        "rate_limit_per_host_ms": scan.request_delay_ms,
        "test_account_ref": None,
        "authentication_type": "none",
        "authentication_configured": False,
        "secret_fingerprint": None,
        "consent_hash": None,
        "authorized_at": scan.created_at.isoformat() if scan.created_at else None,
        "expires_at": None,
        "policy_version": "legacy",
        "scope_json": {"legacy": True},
    }


@router.get("/{scan_id}/assessment/audit")
def get_assessment_audit(scan_id: UUID, db: Session = Depends(get_db)):
    if not db.query(Scan).filter(Scan.id == scan_id).first():
        raise HTTPException(status_code=404, detail="Scan not found")
    events = (
        db.query(AssessmentAuditEvent)
        .filter(AssessmentAuditEvent.scan_id == scan_id)
        .order_by(AssessmentAuditEvent.sequence_number.asc())
        .all()
    )
    return [
        {
            "id": str(event.id),
            "scan_id": str(event.scan_id),
            "authorization_id": str(event.authorization_id) if event.authorization_id else None,
            "sequence_number": event.sequence_number,
            "event_type": event.event_type,
            "actor_id": event.actor_id,
            "payload": event.payload or {},
            "previous_hash": event.previous_hash,
            "event_hash": event.event_hash,
            "created_at": event.created_at.isoformat() if event.created_at else None,
        }
        for event in events
    ]


@router.post("/{scan_id}/pause")
def pause_scan(scan_id: UUID, db: Session = Depends(get_db), actor_id: str | None = Header(default=None, alias="X-Actor-ID")):
    from app.services.tasks import TaskGraphCoordinator
    scan = TaskGraphCoordinator.pause_scan(db, scan_id, actor_id or "anonymous")
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _progress_payload(scan_id, db)


@router.post("/{scan_id}/resume")
def resume_scan(scan_id: UUID, db: Session = Depends(get_db), actor_id: str | None = Header(default=None, alias="X-Actor-ID")):
    from app.services.tasks import TaskGraphCoordinator
    scan = TaskGraphCoordinator.resume_scan(db, scan_id, actor_id or "anonymous")
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _progress_payload(scan_id, db)


@router.get("/{scan_id}/recon")
def get_scan_recon(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    assets = (
        db.query(ReconAsset)
        .filter(ReconAsset.scan_id == scan_id)
        .order_by(ReconAsset.asset_type, ReconAsset.value)
        .all()
    )
    endpoints = (
        db.query(ReconEndpoint)
        .filter(ReconEndpoint.scan_id == scan_id)
        .order_by(ReconEndpoint.endpoint_kind, ReconEndpoint.url_or_path, ReconEndpoint.http_method)
        .all()
    )
    parameters = (
        db.query(ReconParameter)
        .filter(ReconParameter.scan_id == scan_id)
        .order_by(ReconParameter.location, ReconParameter.name)
        .all()
    )
    return {
        "scan_id": str(scan_id),
        "mode": scan.recon_mode or "disabled",
        "requests_used": scan.requests_used,
        "max_requests": scan.max_requests or scan.max_pages,
        "assets": [
            {
                "id": str(item.id),
                "asset_type": item.asset_type,
                "value": item.value,
                "hostname": item.hostname,
                "source": item.source,
                "discovery_mode": item.discovery_mode,
                "classification": item.classification,
                "scope_status": item.scope_status,
                "confidence": item.confidence,
                "attributes": item.attributes or {},
                "evidence": item.evidence or [],
                "created_at": item.created_at.isoformat(),
            }
            for item in assets
        ],
        "endpoints": [
            {
                "id": str(item.id),
                "endpoint_kind": item.endpoint_kind,
                "url_or_path": item.url_or_path,
                "http_method": item.http_method,
                "source": item.source,
                "discovery_mode": item.discovery_mode,
                "classification": item.classification,
                "confidence": item.confidence,
                "scope_status": item.scope_status,
                "status_code": item.status_code,
                "content_type": item.content_type,
                "page_id": str(item.page_id) if item.page_id else None,
                "attributes": item.attributes or {},
                "evidence": item.evidence or [],
                "created_at": item.created_at.isoformat(),
            }
            for item in endpoints
        ],
        "parameters": [
            {
                "id": str(item.id),
                "endpoint_id": str(item.endpoint_id) if item.endpoint_id else None,
                "page_id": str(item.page_id) if item.page_id else None,
                "name": item.name,
                "location": item.location,
                "source": item.source,
                "discovery_mode": item.discovery_mode,
                "classification": item.classification,
                "confidence": item.confidence,
                "scope_status": item.scope_status,
                "example_value": item.example_value,
                "evidence": item.evidence or [],
                "created_at": item.created_at.isoformat(),
            }
            for item in parameters
        ],
        "summary": {
            "asset_count": len(assets),
            "endpoint_count": len(endpoints),
            "parameter_count": len(parameters),
            "cloud_asset_candidates": sum(item.asset_type == "cloud_public_asset" for item in assets),
            "subdomain_count": sum(item.asset_type == "subdomain" for item in assets),
            "login_admin_sensitive_count": sum(
                item.classification in {"LOGIN_PATH", "ADMIN_PATH", "SENSITIVE_PATH"}
                for item in assets + endpoints
            ),
        },
    }


@router.get("/{scan_id}/http-observations")
def get_scan_http_observations(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    observations = (
        db.query(HTTPObservation)
        .filter(HTTPObservation.scan_id == scan_id)
        .order_by(HTTPObservation.created_at, HTTPObservation.observation_type, HTTPObservation.subject)
        .all()
    )
    return {
        "scan_id": str(scan_id),
        "rule_version": "phase3-http-v1",
        "observations": [
            {
                "id": str(item.id),
                "page_id": str(item.page_id) if item.page_id else None,
                "http_response_id": str(item.http_response_id) if item.http_response_id else None,
                "observation_type": item.observation_type,
                "subject": item.subject,
                "source": item.source,
                "classification": item.classification,
                "confidence": item.confidence,
                "value": item.value or {},
                "redacted": item.redacted,
                "truncated": item.truncated,
                "created_at": item.created_at.isoformat(),
            }
            for item in observations
        ],
        "summary": {
            "observation_count": len(observations),
            "types": dict(sorted(Counter(item.observation_type for item in observations).items())),
            "redacted_count": sum(bool(item.redacted) for item in observations),
            "truncated_count": sum(bool(item.truncated) for item in observations),
        },
    }


@router.get("/{scan_id}/configuration")
def get_scan_configuration(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.scan_id == scan_id,
            SecurityFinding.category == "configuration",
        )
        .order_by(SecurityFinding.severity, SecurityFinding.rule_id, SecurityFinding.created_at)
        .all()
    )
    return {
        "scan_id": str(scan_id),
        "rule_version": CONFIGURATION_RULE_VERSION,
        "rules": [CONFIGURATION_RULES[rule_id].as_dict() for rule_id in sorted(CONFIGURATION_RULES)],
        "findings": [
            {
                "id": str(finding.id),
                "page_id": str(finding.page_id) if finding.page_id else None,
                "subject": finding.subject,
                "statement": finding.statement,
                "classification": finding.classification,
                "confidence": finding.confidence,
                "confidence_band": finding.confidence_band,
                "severity": finding.severity,
                "rule_id": finding.rule_id,
                "rule_version": finding.rule_version,
                "evidence": finding.evidence,
                "limitations": finding.limitations,
                "created_at": finding.created_at.isoformat(),
            }
            for finding in findings
        ],
        "summary": {
            "rule_count": len(CONFIGURATION_RULES),
            "finding_count": len(findings),
            "high_count": sum(1 for finding in findings if finding.severity == "high"),
            "medium_count": sum(1 for finding in findings if finding.severity == "medium"),
            "low_count": sum(1 for finding in findings if finding.severity == "low"),
        },
    }
