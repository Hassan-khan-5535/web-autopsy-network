from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.scan import Scan, Website, Observation
from app.services.admission import AdmissionService, AdmissionError
from app.services.collector import HTTPCollectorService

router = APIRouter()

class ScanCreate(BaseModel):
    url: str
    authorization_acknowledged: bool

class ScanResponse(BaseModel):
    id: UUID
    state: str
    requested_url: str
    error_reason: str | None

class ObservationResponse(BaseModel):
    id: UUID
    category: str
    subject: str
    observation: str
    classification: str
    created_at: str

@router.post("", response_model=ScanResponse, status_code=202)
def create_scan(scan_req: ScanCreate, db: Session = Depends(get_db)):
    if not scan_req.authorization_acknowledged:
        raise HTTPException(status_code=422, detail="Authorization must be acknowledged.")

    # 1. Admission Check
    try:
        canonical_url, _ = AdmissionService.validate_and_resolve(scan_req.url)
    except AdmissionError as e:
        raise HTTPException(status_code=422, detail=f"URL Admission failed: {str(e)}")

    from urllib.parse import urlparse
    hostname = urlparse(canonical_url).hostname

    # 2. Get or create Website
    # Hardcoding tenant_id for Phase 2 as auth is basic scaffolding
    tenant_id = "default"
    website = db.query(Website).filter(Website.canonical_origin == hostname, Website.tenant_id == tenant_id).first()
    if not website:
        website = Website(tenant_id=tenant_id, canonical_origin=hostname)
        db.add(website)
        db.commit()
        db.refresh(website)

    # 3. Create Scan (QUEUED -> collecting immediately because it's sync in this phase)
    scan = Scan(
        website_id=website.id,
        state="QUEUED",
        requested_url=scan_req.url
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # 4. Synchronous collection for Phase 2 (will be background task in later phases)
    # The requirement says: "kicks off collection synchronously"
    HTTPCollectorService.collect(db, scan.id, scan_req.url)
    db.refresh(scan)

    return {
        "id": scan.id,
        "state": scan.state,
        "requested_url": scan.requested_url,
        "error_reason": scan.error_reason
    }

@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": scan.id,
        "state": scan.state,
        "requested_url": scan.requested_url,
        "error_reason": scan.error_reason
    }

@router.get("/{scan_id}/evidence")
def get_scan_evidence(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    observations = db.query(Observation).filter(Observation.scan_id == scan_id).order_by(Observation.created_at).all()
    
    return [
        {
            "id": str(obs.id),
            "category": obs.category,
            "subject": obs.subject,
            "observation": obs.observation,
            "classification": obs.classification,
            "created_at": obs.created_at.isoformat()
        } for obs in observations
    ]
