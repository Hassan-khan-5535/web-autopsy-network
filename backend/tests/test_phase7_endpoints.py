from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.main import app
from app.models.scan import Header, HTTPResponse, Page, Scan, Website
from app.services.security import SecurityAnalysisService

client = TestClient(app)


def test_phase7_security_endpoint_and_evidence_feed(db: Session) -> None:
    app.dependency_overrides[get_db] = lambda: db
    try:
        website = Website(id=uuid4(), canonical_origin="security.example")
        db.add(website)
        db.flush()
        scan = Scan(
            id=uuid4(),
            website_id=website.id,
            requested_url="https://security.example/",
            state="COMPLETED",
        )
        db.add(scan)
        db.flush()
        page = Page(
            id=uuid4(),
            scan_id=scan.id,
            canonical_url="https://security.example/",
            depth=0,
        )
        db.add(page)
        db.flush()
        response = HTTPResponse(
            page_id=page.id,
            status_code=200,
            final_url=page.canonical_url,
            raw_body="<html><script>inline()</script></html>",
        )
        db.add(response)
        db.flush()
        db.add(Header(http_response_id=response.id, name="server", value="nginx/1.25"))
        db.commit()

        SecurityAnalysisService(db, scan.id).analyze()

        response = client.get(f"/v1/scans/{scan.id}/security")
        assert response.status_code == 200
        findings = response.json()
        assert findings
        assert all(item["classification"] in {"OBSERVED", "INFERRED"} for item in findings)
        assert all(0 <= item["confidence"] <= 100 for item in findings)
        assert all(item["evidence"] for item in findings)

        evidence_response = client.get(f"/v1/scans/{scan.id}/evidence")
        assert evidence_response.status_code == 200
        assert any(item["category"] == "SECURITY" for item in evidence_response.json())
    finally:
        app.dependency_overrides.clear()
