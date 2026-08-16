from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.main import app
from app.models.scan import HTTPResponse, Page, Scan, Website
from app.services.performance import PerformanceEngine

client = TestClient(app)


def test_phase8_performance_endpoint_and_evidence_feed(db: Session) -> None:
    app.dependency_overrides[get_db] = lambda: db
    try:
        website = Website(id=uuid4(), canonical_origin="endpoint.example")
        db.add(website)
        db.flush()
        scan = Scan(
            id=uuid4(),
            website_id=website.id,
            requested_url="https://endpoint.example/",
            state="COMPLETED",
            max_depth=1,
            max_pages=5,
            max_concurrency=1,
            request_delay_ms=100,
            same_domain_mode="hostname",
        )
        db.add(scan)
        db.flush()
        page = Page(scan_id=scan.id, canonical_url=scan.requested_url, depth=0, title="Endpoint")
        db.add(page)
        db.flush()
        db.add(
            HTTPResponse(
                page_id=page.id,
                status_code=200,
                final_url=scan.requested_url,
                content_type="text/html",
                raw_body="<html><head></head><body></body></html>",
                timings_ms=42,
            )
        )
        db.commit()
        PerformanceEngine(db, scan.id).analyze()

        response = client.get(f"/v1/scans/{scan.id}/performance")
        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == str(scan.id)
        assert data["rule_version"] == "phase8-v1"
        assert data["metrics"]
        assert data["page_metrics"][0]["page_id"] == str(page.id)
        assert data["site_metrics"]
        assert any(metric["metric_name"] == "ttfb_ms" for metric in data["metrics"])
        assert all(metric["evidence"] for metric in data["metrics"])

        evidence_response = client.get(f"/v1/scans/{scan.id}/evidence")
        assert evidence_response.status_code == 200
        evidence = evidence_response.json()
        assert any(item["category"] == "PERFORMANCE" for item in evidence)
    finally:
        app.dependency_overrides.clear()


def test_phase8_performance_endpoint_returns_404_for_unknown_scan(db: Session) -> None:
    app.dependency_overrides[get_db] = lambda: db
    try:
        response = client.get(f"/v1/scans/{uuid4()}/performance")
        assert response.status_code == 404
        assert response.json()["detail"] == "Scan not found"
    finally:
        app.dependency_overrides.clear()
