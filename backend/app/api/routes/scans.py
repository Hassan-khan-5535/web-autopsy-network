from __future__ import annotations

from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.config import get_settings
from app.models.scan import Observation, Page, Scan, Technology, Website
from app.services.admission import AdmissionError, AdmissionService
from app.services.crawler import CrawlerService
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
        try:
            TechnologyDetectionService(db, scan.id).detect()
        except Exception as exc:
            scan.state = "FAILED"
            scan.error_reason = f"Technology detection failed: {exc}"
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
    return [
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
