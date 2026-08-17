from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.scan import Scan, Website

router = APIRouter()


@router.get("/websites/{website_id}/scans")
def list_website_scans(website_id: UUID, db: Session = Depends(get_db)):
    website = db.query(Website).filter(Website.id == website_id).first()
    if not website:
        raise HTTPException(status_code=404, detail="Website not found")
    scans = (
        db.query(Scan)
        .filter(Scan.website_id == website_id)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .all()
    )
    return {
        "website_id": str(website_id),
        "canonical_origin": website.canonical_origin,
        "scans": [
            {
                "id": str(scan.id),
                "state": scan.state,
                "requested_url": scan.requested_url,
                "created_at": scan.created_at.isoformat(),
                "page_count": len(scan.pages),
            }
            for scan in scans
        ],
    }
