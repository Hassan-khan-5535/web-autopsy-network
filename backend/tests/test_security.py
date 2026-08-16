from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.models.scan import Header, HTTPResponse, Observation, Page, Scan, SecurityFinding, Website
from app.services.security import EvidenceValidationError, FindingCandidate, SecurityAnalysisService


def make_scan_with_page(
    db: Session,
    *,
    url: str = "https://security.example/",
    body: str = "<html><head></head><body></body></html>",
    headers: list[tuple[str, str]] | None = None,
) -> Scan:
    website = Website(id=uuid4(), tenant_id="default", canonical_origin="security.example")
    db.add(website)
    db.flush()
    scan = Scan(
        id=uuid4(),
        website_id=website.id,
        state="COMPLETED",
        requested_url=url,
        max_depth=1,
        max_pages=5,
        max_concurrency=1,
        request_delay_ms=100,
        same_domain_mode="hostname",
    )
    db.add(scan)
    db.flush()
    page = Page(scan_id=scan.id, canonical_url=url, depth=0, title="Security fixture")
    db.add(page)
    db.flush()
    response = HTTPResponse(
        page_id=page.id,
        status_code=200,
        final_url=url,
        content_type="text/html",
        raw_body=body,
        rendered_body=body,
    )
    db.add(response)
    db.flush()
    for name, value in headers or []:
        db.add(Header(http_response_id=response.id, name=name.lower(), value=value))
    db.commit()
    db.refresh(scan)
    return scan


def test_passive_security_engine_persists_header_cookie_cors_and_metadata_findings(
    db: Session,
) -> None:
    body = """
    <html><head>
      <script>window.inlineSecret = 'not-a-credential';</script>
      <script src="/static/app.js.map"></script>
    </head><body><!-- api_key should not be used --></body></html>
    """
    headers = [
        ("server", "nginx/1.25.4"),
        ("set-cookie", "session_id=abc; Path=/; SameSite=None"),
        ("access-control-allow-origin", "*"),
        ("access-control-allow-credentials", "true"),
    ]
    scan = make_scan_with_page(db, body=body, headers=headers)
    db.add(
        Observation(
            scan_id=scan.id,
            category="HTTP",
            subject="http://security.example/",
            observation="Redirects to https://security.example/",
            classification="OBSERVED",
        )
    )
    db.commit()

    findings = SecurityAnalysisService(db, scan.id).analyze()
    subjects = {finding.subject for finding in findings}
    rules = {finding.rule_id for finding in findings}

    assert "Content-Security-Policy" in subjects
    assert "HTTPS transport" in subjects
    assert "HTTP to HTTPS redirect" in subjects
    assert "Session-like cookie: session_id" in subjects
    assert "CORS wildcard with credentials" in subjects
    assert "Verbose server header" in subjects
    assert "Source map reference" in subjects
    assert "Sensitive-looking HTML comment" in subjects
    assert "CSP and inline script surface" in subjects
    assert "cors_wildcard_credentials" in rules
    assert all(finding.evidence for finding in findings)
    assert all(finding.rule_version == "phase7-v1" for finding in findings)
    assert all(finding.classification in {"OBSERVED", "INFERRED"} for finding in findings)
    assert all(0 <= finding.confidence <= 100 for finding in findings)
    assert any(finding.classification == "INFERRED" for finding in findings)
    assert (
        db.query(SecurityFinding).filter(SecurityFinding.scan_id == scan.id).count()
        == len(findings)
    )


def test_strong_headers_are_reported_as_observed_low_risk_configuration(db: Session) -> None:
    headers = [
        ("content-security-policy", "default-src 'self'; script-src 'self'"),
        ("strict-transport-security", "max-age=31536000; includeSubDomains"),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "strict-origin"),
        ("permissions-policy", "geolocation=()"),
        ("x-xss-protection", "0"),
        ("access-control-allow-origin", "https://app.example"),
    ]
    scan = make_scan_with_page(db, headers=headers)

    findings = SecurityAnalysisService(db, scan.id).analyze()
    by_subject = {finding.subject: finding for finding in findings}

    assert "strongly configured" in by_subject["Content-Security-Policy"].statement
    assert "strong HSTS duration" in by_subject["Strict-Transport-Security"].statement
    assert by_subject["X-Frame-Options"].severity == "info"
    assert by_subject["X-Content-Type-Options"].severity == "info"
    assert by_subject["CORS configuration"].severity == "info"


def test_security_analysis_is_idempotent(db: Session) -> None:
    scan = make_scan_with_page(db)
    service = SecurityAnalysisService(db, scan.id)
    first = service.analyze()
    first_rules = {finding.rule_id for finding in first}
    second = SecurityAnalysisService(db, scan.id).analyze()
    second_rules = {finding.rule_id for finding in second}

    assert len(first) == len(second)
    assert (
        db.query(SecurityFinding).filter(SecurityFinding.scan_id == scan.id).count()
        == len(second)
    )
    assert first_rules == second_rules


def test_security_analysis_makes_no_network_requests(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    import httpx

    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("Phase 7 security analysis must not issue network requests")

    for method_name in ("request", "get", "post", "put", "delete"):
        monkeypatch.setattr(httpx, method_name, fail_if_called)

    scan = make_scan_with_page(db)
    findings = SecurityAnalysisService(db, scan.id).analyze()
    assert findings


def test_evidence_agent_rejects_security_finding_without_evidence(db: Session) -> None:
    scan = make_scan_with_page(db)
    service = SecurityAnalysisService(db, scan.id)
    candidate = FindingCandidate(
        subject="Unsupported claim",
        statement="This claim has no supporting evidence.",
        classification="INFERRED",
        confidence=90,
        confidence_band="high",
        severity="high",
        rule_id="unsupported",
        evidence=(),
    )

    with pytest.raises(EvidenceValidationError):
        service._persist_candidate(candidate)
    assert db.query(SecurityFinding).filter(SecurityFinding.scan_id == scan.id).count() == 0
