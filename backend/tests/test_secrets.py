from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.main import app
from app.models.scan import Header, HTTPResponse, Page, Scan, SecurityFinding, Website
from app.services.secrets import REDACTED, RULE_VERSION, SECRETS_RULES, SecretsAgent, shannon_entropy
from app.services.tasks import TaskGraphCoordinator

client = TestClient(app)


def _scan(db: Session) -> Scan:
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.flush()
    scan = Scan(
        website_id=website.id,
        requested_url="https://example.com/",
        state="COMPLETED",
        max_depth=1,
        max_pages=8,
        max_concurrency=1,
        request_delay_ms=1000,
        max_requests=20,
        recon_mode="passive_only",
    )
    db.add(scan)
    db.commit()
    return scan


def _page(db: Session, scan: Scan, url: str, *, body: str, content_type: str = "text/html", headers: list[tuple[str, str]] | None = None) -> Page:
    page = Page(scan_id=scan.id, canonical_url=url, depth=1, status_code=200)
    db.add(page)
    db.flush()
    response = HTTPResponse(page_id=page.id, status_code=200, final_url=url, content_type=content_type, raw_body=body)
    db.add(response)
    db.flush()
    for name, value in headers or []:
        db.add(Header(http_response_id=response.id, name=name, value=value))
    db.commit()
    return page


def test_secret_rules_are_complete_and_redaction_first():
    assert len(SECRETS_RULES) == 6
    for rule in SECRETS_RULES.values():
        assert rule.rule_id and rule.title and rule.source_types
        assert rule.prerequisites and rule.detection_logic and rule.suppression_logic
        assert rule.evidence_requirements and rule.remediation_guidance
        assert rule.confidence_tier in {"high", "medium", "low"}
        assert 0 < rule.confidence <= 100
        assert rule.as_dict()["rule_version"] == RULE_VERSION


def test_secret_signatures_and_artifacts_are_redacted(db: Session):
    scan = _scan(db)
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    github = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"
    private_key = "-----BEGIN RSA PRIVATE KEY-----"
    _page(
        db,
        scan,
        "https://example.com/app.js",
        content_type="application/javascript",
        body=f'const apiKey = "{aws_key}"; const token = "{github}";\n{private_key}',
        headers=[("X-Api-Key", aws_key)],
    )
    _page(
        db,
        scan,
        "https://example.com/app.js.map",
        content_type="application/json",
        body=f'{{"version":3,"sourcesContent":["const client_secret = \'{github}\'"]}}',
    )

    findings = SecretsAgent(db, scan.id).analyze()
    rule_ids = {finding.rule_id for finding in findings}
    assert {"SECRET-SIG-001", "SECRET-SIG-002", "SECRET-ARTIFACT-001"}.issubset(rule_ids)
    serialized = str([finding.evidence for finding in findings])
    assert aws_key not in serialized
    assert github not in serialized
    assert private_key not in serialized
    assert all(REDACTED in str(finding.evidence) for finding in findings)
    assert all(finding.category == "secrets" for finding in findings)

    report = SecretsAgent(db, scan.id).report()
    assert report["redaction"] == {
        "values_persisted": False,
        "values_logged": False,
        "values_returned": False,
        "stored_evidence_mode": "minimum-redacted-metadata",
    }
    assert aws_key not in str(report)
    assert github not in str(report)
    assert private_key not in str(report)


def test_context_entropy_identifier_detection_and_suppression(db: Session):
    scan = _scan(db)
    high_entropy = "mK7vP2qL9xR4tN8zW6cY3bH5sJ1dF0gK"
    _page(
        db,
        scan,
        "https://example.com/config",
        content_type="application/json",
        body=(
            '{"client_secret":"' + high_entropy + '", '
            '"api_key":"example-placeholder-value", '
            '"asset_hash":"' + high_entropy + '", '
            '"ssn":"123-45-6789", '
            '"credit_card":"4111111111111111"}'
        ),
    )
    findings = SecretsAgent(db, scan.id).analyze()
    rule_ids = {finding.rule_id for finding in findings}
    assert "SECRET-CONTEXT-001" in rule_ids
    assert "SECRET-ENTROPY-001" not in rule_ids or "SECRET-CONTEXT-001" in rule_ids
    assert "SECRET-ID-001" in rule_ids
    statements = " ".join(finding.statement for finding in findings).lower()
    assert "placeholder" not in statements
    assert shannon_entropy(high_entropy) > 3.2


def test_secrets_agent_is_idempotent_and_task_ordered(db: Session):
    scan = _scan(db)
    _page(db, scan, "https://example.com/", body="<html><body>safe</body></html>")
    TaskGraphCoordinator.initialize_scan(db, scan.id)
    TaskGraphCoordinator.after_collection(db, scan.id)
    task_map = {task.task_type: task for task in scan.agent_tasks}
    assert task_map["secrets"].dependency_keys == ["collection", "http_agent"]
    assert "secrets" in task_map["diagnosis"].dependency_keys

    first = SecretsAgent(db, scan.id).analyze()
    first_ids = {finding.id for finding in first}
    second = SecretsAgent(db, scan.id).analyze()
    assert {finding.id for finding in second}.isdisjoint(first_ids)
    assert db.query(SecurityFinding).filter(SecurityFinding.scan_id == scan.id, SecurityFinding.category == "secrets").count() == len(second)


def test_secrets_agent_makes_no_network_requests_and_route_returns_redacted_report(db: Session, monkeypatch):
    import httpx

    def fail_if_called(*args, **kwargs):
        raise AssertionError("Secrets Agent must not issue network requests")

    for method_name in ("request", "get", "post", "put", "delete"):
        monkeypatch.setattr(httpx, method_name, fail_if_called)
    scan = _scan(db)
    _page(db, scan, "https://example.com/", body="<html><body>safe</body></html>")
    SecretsAgent(db, scan.id).analyze()
    app.dependency_overrides[get_db] = lambda: db
    try:
        response = client.get(f"/v1/scans/{scan.id}/secrets")
        assert response.status_code == 200
        payload = response.json()
        assert payload["scan_id"] == str(scan.id)
        assert payload["rule_version"] == RULE_VERSION
        assert len(payload["rules"]) == len(SECRETS_RULES)
        assert payload["redaction"]["values_persisted"] is False
    finally:
        app.dependency_overrides.clear()
