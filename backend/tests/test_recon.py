from uuid import uuid4

from app.models.scan import (
    ApiEndpoint,
    AssessmentAuthorization,
    HTTPResponse,
    Page,
    PageLink,
    ReconAsset,
    ReconEndpoint,
    ReconParameter,
    Resource,
    Scan,
    Website,
)
from app.services.recon import ReconAgent
from app.services.tasks import TaskGraphCoordinator


def _scan(db, *, mode="passive_only", allowed_domains=None, allowed_paths=None, excluded_paths=None):
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.flush()
    scan = Scan(
        website_id=website.id,
        requested_url="https://example.com/",
        state="COMPLETED",
        max_depth=2,
        max_pages=30,
        max_concurrency=2,
        request_delay_ms=1000,
        max_requests=30,
        recon_mode=mode,
    )
    db.add(scan)
    db.flush()
    if mode != "disabled":
        db.add(AssessmentAuthorization(
            scan_id=scan.id,
            actor_id="test",
            target_url=scan.requested_url,
            allowed_domains=allowed_domains or ["example.com"],
            allowed_paths=allowed_paths or [],
            excluded_paths=excluded_paths or [],
            assessment_profile="safe",
            max_depth=2,
            max_pages=30,
            max_requests=30,
            max_concurrency=2,
            rate_limit_per_host_ms=1,
            consent_hash="a" * 64,
            scope_json={},
        ))
    db.flush()
    return scan


def test_recon_normalizes_public_sources_and_existing_evidence(db, monkeypatch):
    scan = _scan(db, allowed_domains=["example.com"])
    page = Page(scan_id=scan.id, canonical_url="https://example.com/login?next=/dashboard", depth=0)
    db.add(page)
    db.flush()
    html = """
    <html><body>
      <form action="/api/login" method="POST"><input name="email"><input name="password" type="password"></form>
      <script>fetch('/api/profile?id=42'); const asset = 'https://bucket.s3.amazonaws.com/app.js';</script>
    </body></html>
    """
    db.add(HTTPResponse(page_id=page.id, status_code=200, final_url=page.canonical_url, content_type="text/html", raw_body=html))
    db.add(Resource(page_id=page.id, url="https://cdn.example.com/app.js?version=1", type="script"))
    db.add(PageLink(source_page_id=page.id, target_url="https://example.com/docs?lang=en", is_external=False))
    db.add(ApiEndpoint(scan_id=scan.id, url_or_path="https://example.com/api/orders?limit=10", http_method="GET", discovered_from_source="test"))
    db.commit()

    def fake_public_get(self, url, params):
        if "certspotter" in url:
            return [{"dns_names": ["example.com", "www.example.com", "*.api.example.com"]}]
        return {"Status": 0, "Answer": [{"name": "example.com.", "type": 1, "TTL": 60, "data": "93.184.216.34"}]}

    monkeypatch.setattr(ReconAgent, "_public_get", fake_public_get)
    result = ReconAgent(db, scan.id).run()

    assert result["mode"] == "passive_only"
    assert db.query(Page).count() == 1
    assets = db.query(ReconAsset).filter_by(scan_id=scan.id).all()
    endpoints = db.query(ReconEndpoint).filter_by(scan_id=scan.id).all()
    parameters = db.query(ReconParameter).filter_by(scan_id=scan.id).all()
    assert any(item.asset_type == "subdomain" and item.value == "www.example.com" for item in assets)
    assert any(item.asset_type == "dns_record" and item.scope_status == "in_scope" and item.hostname == "example.com" for item in assets)
    assert any(item.asset_type == "cloud_public_asset" for item in assets)
    assert any(item.classification == "LOGIN_PATH" for item in endpoints)
    assert any(item.endpoint_kind == "javascript" and "/api/profile" in item.url_or_path for item in endpoints)
    assert any(item.name == "email" and item.location == "form" for item in parameters)
    assert any(item.name == "limit" and item.location == "query" for item in parameters)
    assert result["assets"] == len(assets)

    ReconAgent(db, scan.id).run()
    assert db.query(ReconAsset).filter_by(scan_id=scan.id).count() == len(assets)
    assert db.query(ReconEndpoint).filter_by(scan_id=scan.id).count() == len(endpoints)


def test_recon_scope_blocks_out_of_scope_active_safe_candidates(db, monkeypatch):
    scan = _scan(db, mode="active_safe", allowed_domains=["example.com"], allowed_paths=["/docs"])
    db.commit()
    agent = ReconAgent(db, scan.id)
    assert agent._normalize_target_url("https://other.example.net/docs") is None
    assert agent._normalize_target_url("https://example.com/admin") is None

    calls = []
    def fake_safe_get(self, url, source):
        calls.append((url, source))
        return {"status_code": 200, "content_type": "text/html", "text": ""}

    monkeypatch.setattr(ReconAgent, "_safe_get", fake_safe_get)
    agent._active_safe_discovery()
    assert all("other.example.net" not in url for url, _ in calls)
    assert all("/docs" in url or "/robots.txt" in url for url, _ in calls)


def test_recon_legacy_scan_does_not_add_recon_task(db):
    scan = _scan(db, mode="disabled")
    TaskGraphCoordinator.initialize_scan(db, scan.id)
    TaskGraphCoordinator.after_collection(db, scan.id)
    task_types = {task.task_type for task in scan.agent_tasks}
    assert "recon" not in task_types
