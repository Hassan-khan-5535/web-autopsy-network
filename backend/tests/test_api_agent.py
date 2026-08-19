from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.api.routes.scans import router
from app.main import app
from app.models.scan import ApiEndpoint, Header, HTTPResponse, Page, ReconEndpoint, ReconParameter, Scan, Website
from app.services.api_agent import API_AGENT_RULES, APIAgent, RULE_VERSION
from app.services.http_agent import HTTPAgent
from app.services.tasks import TaskGraphCoordinator

client = TestClient(app)


def _scan(db: Session):
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.flush()
    scan = Scan(
        website_id=website.id,
        requested_url="https://example.com/",
        state="COMPLETED",
        max_depth=1,
        max_pages=6,
        max_concurrency=1,
        request_delay_ms=1000,
        max_requests=20,
        recon_mode="passive_only",
    )
    db.add(scan)
    db.flush()
    return scan


def _page(db: Session, scan: Scan, url: str, *, status: int = 200, content_type: str = "application/json", body: str = "{}", headers: list[tuple[str, str]] | None = None):
    page = Page(scan_id=scan.id, canonical_url=url, depth=1, status_code=status)
    db.add(page)
    db.flush()
    response = HTTPResponse(page_id=page.id, status_code=status, final_url=url, content_type=content_type, raw_body=body)
    db.add(response)
    db.flush()
    for name, value in headers or []:
        db.add(Header(http_response_id=response.id, name=name, value=value))
    db.commit()
    return page, response


def test_api_agent_rules_have_complete_metadata():
    assert set(API_AGENT_RULES) == {
        "API-INV-001", "API-METHOD-001", "API-PARAM-001", "API-AUTH-001", "API-AUTH-002",
        "API-DATA-001", "API-RATE-001", "API-ERROR-001", "API-POLICY-001", "API-SCHEMA-001",
    }
    for rule in API_AGENT_RULES.values():
        assert rule.rule_id and rule.title and rule.prerequisites and rule.detection_logic
        assert rule.evidence_requirements and rule.remediation_guidance
        assert rule.severity in {"info", "low", "medium", "high"}
        assert 0 < rule.confidence <= 100
        assert rule.as_dict()["rule_version"] == RULE_VERSION


def test_api_agent_detects_schema_inventory_and_security_signals(db: Session):
    scan = _scan(db)
    _page(
        db,
        scan,
        "https://example.com/openapi.json",
        body='{"openapi":"3.0.0","paths":{"/api/users":{"get":{}},"/api/admin/users":{"get":{}}},"components":{"securitySchemes":{"bearerAuth":{"type":"http"}}}}',
    )
    admin_page, _ = _page(
        db,
        scan,
        "https://example.com/api/admin/users",
        body='{"id":1,"password":"redacted","access_token":"redacted"}',
        headers=[
            ("allow", "GET, TRACE"),
            ("access-control-allow-origin", "*"),
            ("retry-after", "30"),
            ("x-ratelimit-limit", "60"),
        ],
    )
    _page(
        db,
        scan,
        "https://example.com/api/error",
        status=500,
        body="Traceback (most recent call last): Exception: SQLSTATE 42P01",
    )
    _page(
        db,
        scan,
        "http://example.com/api/basic",
        status=401,
        body='{"error":"unauthorized"}',
        headers=[("www-authenticate", "Basic realm=api")],
    )
    endpoint = ApiEndpoint(
        scan_id=scan.id,
        url_or_path="https://example.com/api/legacy",
        http_method="GET",
        content_type="application/json",
        classification="inferred",
        confidence=0.9,
        discovered_from_source="fixture JavaScript",
    )
    db.add(endpoint)
    db.flush()
    db.add(ReconEndpoint(
        scan_id=scan.id,
        endpoint_kind="api",
        url_or_path="https://example.com/api/legacy",
        http_method="GET",
        source="fixture recon",
        discovery_mode="passive_only",
        classification="INFERRED",
        confidence=0.9,
        scope_status="in_scope",
        page_id=admin_page.id,
        dedupe_key="fixture-api-legacy",
    ))
    db.add(ReconParameter(
        scan_id=scan.id,
        endpoint_id=endpoint.id,
        page_id=admin_page.id,
        name="api_key",
        location="query",
        source="fixture query",
        discovery_mode="passive_only",
        classification="INFERRED",
        confidence=0.9,
        scope_status="in_scope",
        dedupe_key="fixture-api-key",
    ))
    db.commit()

    HTTPAgent(db, scan.id).analyze()
    findings = APIAgent(db, scan.id).analyze()
    rule_ids = {finding.rule_id for finding in findings}
    assert {"API-SCHEMA-001", "API-INV-001", "API-METHOD-001", "API-PARAM-001", "API-AUTH-001", "API-AUTH-002", "API-DATA-001", "API-RATE-001", "API-ERROR-001", "API-POLICY-001"}.issubset(rule_ids)
    assert all(finding.category == "api" and finding.evidence and finding.limitations for finding in findings)
    assert all("redacted" not in str(finding.evidence).lower() for finding in findings)

    report = APIAgent(db, scan.id).report()
    assert report["rule_version"] == RULE_VERSION
    assert report["summary"]["inventory_count"] >= 4
    assert report["summary"]["schema_count"] == 1
    assert report["schemas"][0]["security_schemes"] == ["bearerAuth"]
    assert any(item["route"].endswith("/api/legacy") for item in report["inventory"])


def test_api_agent_is_idempotent_and_task_ordered(db: Session):
    scan = _scan(db)
    _page(db, scan, "https://example.com/api/users", body='{"id":1}')
    TaskGraphCoordinator.initialize_scan(db, scan.id)
    TaskGraphCoordinator.after_collection(db, scan.id)
    task_map = {task.task_type: task for task in scan.agent_tasks}
    assert task_map["api_agent"].dependency_keys == ["collection", "api_intelligence", "http_agent", "recon"]
    assert "api_agent" in task_map["diagnosis"].dependency_keys

    HTTPAgent(db, scan.id).analyze()
    first = APIAgent(db, scan.id).analyze()
    first_ids = {finding.id for finding in first}
    second = APIAgent(db, scan.id).analyze()
    assert {finding.id for finding in second}.isdisjoint(first_ids)


def test_api_agent_route_returns_rich_report(db: Session):
    scan = _scan(db)
    _page(db, scan, "https://example.com/api/users", body='{"id":1}')
    HTTPAgent(db, scan.id).analyze()
    app.dependency_overrides[get_db] = lambda: db
    try:
        response = client.get(f"/v1/scans/{scan.id}/api-agent")
        assert response.status_code == 200
        payload = response.json()
        assert payload["scan_id"] == str(scan.id)
        assert payload["rule_version"] == RULE_VERSION
        assert "inventory" in payload and "schemas" in payload and "indicators" in payload
        assert len(payload["rules"]) == len(API_AGENT_RULES)
    finally:
        app.dependency_overrides.clear()
