from datetime import UTC, datetime, timedelta

from app.models.base import Base
from app.models.scan import Page, Scan, Technology, TechnologyEvidence, Website
from app.core.database import engine, SessionLocal

Base.metadata.create_all(engine)
with SessionLocal() as db:
    website = db.query(Website).filter(Website.canonical_origin == "demo.example").first()
    if not website:
        website = Website(canonical_origin="demo.example")
        db.add(website)
        db.flush()
        previous = Scan(website_id=website.id, requested_url="https://demo.example", state="COMPLETED", created_at=datetime.now(UTC) - timedelta(days=1))
        current = Scan(website_id=website.id, requested_url="https://demo.example", state="COMPLETED", created_at=datetime.now(UTC))
        db.add_all([previous, current])
        db.flush()
        old_page = Page(scan_id=previous.id, canonical_url="https://demo.example/", depth=0, status_code=200, title="Demo Home")
        old_about = Page(scan_id=previous.id, canonical_url="https://demo.example/about", depth=1, status_code=200, title="About")
        new_page = Page(scan_id=current.id, canonical_url="https://demo.example/", depth=0, status_code=200, title="Demo Home")
        new_contact = Page(scan_id=current.id, canonical_url="https://demo.example/contact", depth=1, status_code=200, title="Contact")
        db.add_all([old_page, old_about, new_page, new_contact])
        db.flush()
        old_tech = Technology(scan_id=previous.id, canonical_name="React", category="frontend", classification="inferred", confidence=0.8, confidence_band="high", rule_version="demo")
        new_tech = Technology(scan_id=current.id, canonical_name="Next.js", category="frontend", classification="inferred", confidence=0.95, confidence_band="high", rule_version="demo")
        db.add_all([old_tech, new_tech])
        db.flush()
        db.add_all([
            TechnologyEvidence(technology_id=old_tech.id, scan_id=previous.id, page_id=old_page.id, signal_type="script", match_rule="react", source="https://demo.example/", observation="react bundle", match_weight=0.8),
            TechnologyEvidence(technology_id=new_tech.id, scan_id=current.id, page_id=new_page.id, signal_type="script", match_rule="next", source="https://demo.example/", observation="__NEXT_DATA__", match_weight=0.95),
        ])
        db.commit()
    current = db.query(Scan).filter(Scan.website_id == website.id, Scan.state == "COMPLETED").order_by(Scan.created_at.desc()).first()
    print(current.id)
