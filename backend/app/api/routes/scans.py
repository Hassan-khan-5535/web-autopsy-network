from __future__ import annotations

from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.config import get_settings
from app.models.scan import (
    AccessibilityFinding,
    AIInterpretation,
    ApiEndpoint,
    ContentFinding,
    Dependency,
    HTTPResponse,
    Observation,
    Page,
    PerformanceMetric,
    Resource,
    Scan,
    SecurityFinding,
    Technology,
    Website,
)
from app.services.accessibility import AccessibilityEngine
from app.services.admission import AdmissionError, AdmissionService
from app.services.ai_synthesis import AIDoctorEngine, AISynthesisEngine
from app.services.api_intelligence import ApiIntelligenceAgent
from app.services.content import ContentEngine
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


class ScanResponse(BaseModel):
    id: UUID
    state: str
    requested_url: str
    error_reason: str | None
    max_depth: int
    max_pages: int


class ObservationResponse(BaseModel):
    id: UUID
    category: str
    subject: str
    observation: str
    classification: str
    created_at: str
    page_id: UUID | None = None


def _scan_response(scan: Scan) -> dict[str, object]:
    return {
        "id": scan.id,
        "state": scan.state,
        "requested_url": scan.requested_url,
        "error_reason": scan.error_reason,
        "max_depth": scan.max_depth,
        "max_pages": scan.max_pages,
    }


@router.post("", response_model=ScanResponse, status_code=202)
def create_scan(scan_req: ScanCreate, db: Session = Depends(get_db)):
    if not scan_req.authorization_acknowledged:
        raise HTTPException(status_code=422, detail="Authorization must be acknowledged.")

    settings = get_settings()
    try:
        canonical_url, _ = AdmissionService.validate_and_resolve(scan_req.url)
    except AdmissionError as exc:
        raise HTTPException(status_code=422, detail=f"URL Admission failed: {exc}") from exc

    hostname = urlsplit(canonical_url).hostname
    if not hostname:
        raise HTTPException(status_code=422, detail="URL must contain a hostname.")

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
        state="CREATED",
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

    CrawlerService(db, scan, canonical_url).crawl()
    db.refresh(scan)
    if scan.state == "COMPLETED":
        scan.state = "ANALYZING"
        db.commit()
        try:
            TechnologyDetectionService(db, scan.id).detect()
            StructureAgent(db, scan.id).analyze()
            ApiIntelligenceAgent(db, scan.id).analyze()
            NetworkIntelligenceAgent(db, scan.id).analyze()
            SecurityAnalysisService(db, scan.id).analyze()
            PerformanceEngine(db, scan.id).analyze()
            AccessibilityEngine(db, scan.id).analyze()
            ContentEngine(db, scan.id).analyze()
            
            scan.state = "SYNTHESIZING"
            db.commit()
            
            AISynthesisEngine(db, scan.id).synthesize()
            
            scan.state = "COMPLETED"
            db.commit()
        except Exception as exc:
            scan.state = "FAILED"
            scan.error_reason = f"Analysis pipeline failed: {exc}"
            db.commit()
        db.refresh(scan)

    return _scan_response(scan)


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
