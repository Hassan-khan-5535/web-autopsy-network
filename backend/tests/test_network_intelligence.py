from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.scan import Dependency, Page, PageLink, Resource, Scan, Technology, Website
from app.services.network_intelligence import NetworkIntelligenceAgent


def test_network_intelligence_agent_categorization(db: Session):
    website = Website(canonical_origin="mysite.com")
    db.add(website)
    db.commit()

    scan = Scan(website_id=website.id, requested_url="https://mysite.com", state="COLLECTING")
    db.add(scan)
    db.commit()

    page = Page(scan_id=scan.id, canonical_url="https://mysite.com/", depth=0)
    db.add(page)
    db.commit()

    # Add Phase 4 Technology detection output
    tech = Technology(
        scan_id=scan.id,
        canonical_name="Google Analytics",
        category="Analytics",
        classification="inferred",
        confidence=0.95,
        confidence_band="high",
        rule_version="1.0",
    )
    db.add(tech)
    db.commit()

    # Add external resources
    db.add(Resource(page_id=page.id, url="https://www.google-analytics.com/analytics.js", type="script"))
    db.add(Resource(page_id=page.id, url="https://fonts.googleapis.com/css?family=Inter", type="link"))
    db.add(Resource(page_id=page.id, url="https://unknown-cdn.net/library.js", type="script"))

    # Add external link
    db.add(PageLink(source_page_id=page.id, target_url="https://external-partner.org/about", is_external=True))
    db.commit()

    agent = NetworkIntelligenceAgent(db, scan.id)
    deps = agent.analyze()

    assert len(deps) >= 3

    deps_by_domain = {dep.domain: dep for dep in deps}

    # Google Analytics domain categorized from Phase 4 Tech output
    assert "www.google-analytics.com" in deps_by_domain
    assert deps_by_domain["www.google-analytics.com"].category == "Analytics"

    # Fonts domain
    assert "fonts.googleapis.com" in deps_by_domain

    # Unclassified domain
    assert "unknown-cdn.net" in deps_by_domain
    assert deps_by_domain["unknown-cdn.net"].category == "Unclassified External Dependency"

    # DB persistence check
    db_deps = db.query(Dependency).filter(Dependency.scan_id == scan.id).all()
    assert len(db_deps) == len(deps)
