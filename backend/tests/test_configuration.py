from app.models.scan import Header, HTTPObservation, HTTPResponse, Page, Scan, Website
from app.services.configuration import CONFIGURATION_RULES, ConfigurationAgent, RULE_VERSION
from app.services.http_agent import HTTPAgent
from app.services.tasks import TaskGraphCoordinator


def _scan_page(db, url: str, *, status: int = 200, content_type: str = "text/html", body: str = "<html><body>ok</body></html>"):
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.flush()
    scan = Scan(
        website_id=website.id,
        requested_url=url,
        state="COMPLETED",
        max_depth=0,
        max_pages=1,
        max_concurrency=1,
        request_delay_ms=1000,
        max_requests=10,
        recon_mode="passive_only",
    )
    db.add(scan)
    db.flush()
    page = Page(scan_id=scan.id, canonical_url=url, status_code=status)
    db.add(page)
    db.flush()
    response = HTTPResponse(
        page_id=page.id,
        status_code=status,
        final_url=url,
        content_type=content_type,
        raw_body=body,
    )
    db.add(response)
    db.commit()
    return scan, page, response


def _headers(db, response, values):
    for name, value in values:
        db.add(Header(http_response_id=response.id, name=name, value=value))
    db.commit()


def _run(db, scan):
    HTTPAgent(db, scan.id).analyze()
    return ConfigurationAgent(db, scan.id).analyze()


def _rules(findings):
    return {finding.rule_id for finding in findings}


def test_configuration_rules_have_complete_metadata():
    expected = {
        "CFG-HEADERS-001", "CFG-CORS-001", "CFG-TLS-001", "CFG-TLS-002",
        "CFG-DIR-001", "CFG-EXPOSED-ARTIFACT-001", "CFG-ERROR-001",
        "CFG-CACHE-001", "CFG-DISCLOSURE-001", "CFG-COOKIE-001", "CFG-HTTP-001",
    }
    assert set(CONFIGURATION_RULES) == expected
    for rule in CONFIGURATION_RULES.values():
        assert rule.rule_id and rule.prerequisites and rule.detection_logic
        assert rule.evidence_requirements and rule.remediation_guidance
        assert rule.severity in {"low", "medium", "high"}
        assert 0 < rule.confidence <= 100
        assert rule.cwe and rule.owasp
        assert rule.as_dict()["rule_version"] == RULE_VERSION


def test_headers_cors_tls_and_dangerous_method_rules(db):
    scan, _, response = _scan_page(db, "https://example.com/login")
    _headers(db, response, [
        ("access-control-allow-origin", "*"),
        ("access-control-allow-credentials", "true"),
        ("allow", "GET, TRACE"),
    ])
    findings = _run(db, scan)
    rules = _rules(findings)
    assert "CFG-HEADERS-001" in rules
    assert "CFG-CORS-001" in rules
    assert "CFG-TLS-002" in rules
    assert "CFG-HTTP-001" in rules
    assert all(item.evidence and item.limitations for item in findings)


def test_directory_artifact_and_verbose_error_rules(db):
    artifact_scan, _, artifact_response = _scan_page(
        db,
        "https://example.com/.env",
        status=200,
        content_type="text/plain",
        body="APP_KEY=redacted-value",
    )
    artifact_findings = _run(db, artifact_scan)
    assert "CFG-EXPOSED-ARTIFACT-001" in _rules(artifact_findings)

    error_scan, _, _ = _scan_page(
        db,
        "https://example.com/error",
        status=500,
        content_type="text/plain",
        body="Traceback (most recent call last):\n  File app.py",
    )
    error_findings = _run(db, error_scan)
    assert "CFG-ERROR-001" in _rules(error_findings)

    listing_scan, _, listing_response = _scan_page(
        db,
        "https://example.com/backups/",
        body="<html><title>Index of /backups</title><a href='a.zip'>a.zip</a><a href='b.zip'>b.zip</a></html>",
    )
    listing_findings = _run(db, listing_scan)
    assert "CFG-DIR-001" in _rules(listing_findings)

    generic_scan, _, generic_response = _scan_page(
        db,
        "https://example.com/.env",
        body="<!doctype html><html><body>Not found</body></html>",
    )
    generic_findings = _run(db, generic_scan)
    assert "CFG-EXPOSED-ARTIFACT-001" not in _rules(generic_findings)


def test_cookie_cache_and_disclosure_rules(db):
    scan, _, response = _scan_page(db, "https://example.com/account")
    _headers(db, response, [
        ("set-cookie", "session=secret; Path=/; SameSite=None"),
        ("cache-control", "public, s-maxage=60"),
        ("server", "nginx/1.24.0"),
    ])
    findings = _run(db, scan)
    rules = _rules(findings)
    assert "CFG-CACHE-001" in rules
    assert "CFG-COOKIE-001" in rules
    assert "CFG-DISCLOSURE-001" in rules
    assert all("secret" not in str(item.evidence).lower() for item in findings)


def test_http_agent_and_configuration_tasks_are_dependency_ordered(db):
    scan, _, _ = _scan_page(db, "https://example.com/")
    TaskGraphCoordinator.initialize_scan(db, scan.id)
    TaskGraphCoordinator.after_collection(db, scan.id)
    task_map = {task.task_type: task for task in scan.agent_tasks}
    assert task_map["configuration"].dependency_keys == ["collection", "http_agent"]
    assert "configuration" in task_map["diagnosis"].dependency_keys


def test_configuration_is_idempotent(db):
    scan, _, response = _scan_page(db, "https://example.com/login")
    _headers(db, response, [("access-control-allow-origin", "*"), ("access-control-allow-credentials", "true")])
    first = _run(db, scan)
    first_ids = {finding.id for finding in first}
    second = ConfigurationAgent(db, scan.id).analyze()
    assert second
    assert {finding.id for finding in second}.isdisjoint(first_ids)


def test_configuration_handles_missing_response_observation(db):
    scan, page, response = _scan_page(db, "https://example.com/")
    db.delete(response)
    db.add(HTTPObservation(
        scan_id=scan.id,
        page_id=page.id,
        observation_type="response_anomaly",
        subject="persisted_response",
        source="browser_worker",
        classification="UNKNOWN",
        value={"anomaly": "no_persisted_response", "status_code": None},
        dedupe_key="response-anomaly-no-response",
    ))
    db.commit()

    findings = ConfigurationAgent(db, scan.id).analyze()

    assert findings == []
