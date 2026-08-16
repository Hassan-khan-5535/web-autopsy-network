from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.main import app
from app.models.scan import Page, PageLink, Scan, Website
from app.services.api_intelligence import ApiIntelligenceAgent
from app.services.network_intelligence import NetworkIntelligenceAgent
from app.services.structure import StructureAgent

client = TestClient(app)


def test_phase5_rest_endpoints(db: Session):
    app.dependency_overrides[get_db] = lambda: db

    website = Website(canonical_origin="example.com")
    db.add(website)
    db.commit()

    scan = Scan(website_id=website.id, requested_url="https://example.com", state="COMPLETED")
    db.add(scan)
    db.commit()

    page = Page(scan_id=scan.id, canonical_url="https://example.com/", depth=0, title="Home")
    db.add(page)
    db.commit()

    db.add(PageLink(source_page_id=page.id, target_url="https://external.org", is_external=True))
    db.commit()

    # Populate Phase 5 agents data
    StructureAgent(db, scan.id).analyze()
    ApiIntelligenceAgent(db, scan.id).analyze()
    NetworkIntelligenceAgent(db, scan.id).analyze()

    # Test GET /scans/{id}/architecture
    resp = client.get(f"/v1/scans/{scan.id}/architecture")
    assert resp.status_code == 200
    data = resp.json()
    assert "site_tree" in data
    assert "link_summary" in data
    assert "form_inventory" in data
    assert "page_types" in data

    # Test GET /scans/{id}/dependencies
    resp = client.get(f"/v1/scans/{scan.id}/dependencies")
    assert resp.status_code == 200
    deps = resp.json()
    assert isinstance(deps, list)
    assert len(deps) >= 1
    assert deps[0]["domain"] == "external.org"

    # Test GET /scans/{id}/api-endpoints
    resp = client.get(f"/v1/scans/{scan.id}/api-endpoints")
    assert resp.status_code == 200
    endpoints = resp.json()
    assert isinstance(endpoints, list)

    app.dependency_overrides.clear()
