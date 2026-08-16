from __future__ import annotations

import json
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import app.services.technology as technology_module
from app.models.scan import Base, Header, HTTPResponse, Page, Resource, Scan, Technology, Website
from app.services.technology import (
    DetectionCandidate,
    EvidenceValidationError,
    TechnologyDetectionService,
)


@pytest.fixture
def db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def make_known_stack_scan(db: Session) -> Scan:
    base_url = "https://known-stack.example"
    website = Website(
        id=uuid4(),
        tenant_id="default",
        canonical_origin=urlsplit(base_url).hostname or "known-stack.example",
    )
    db.add(website)
    db.flush()
    scan = Scan(
        id=uuid4(),
        website_id=website.id,
        state="COMPLETED",
        requested_url=base_url,
        max_depth=1,
        max_pages=5,
        max_concurrency=1,
        request_delay_ms=100,
        same_domain_mode="hostname",
    )
    db.add(scan)
    db.flush()
    page = Page(scan_id=scan.id, canonical_url=base_url, depth=0, title="Known stack")
    db.add(page)
    db.flush()
    html = """
    <html>
      <head>
        <meta name="generator" content="WordPress 6.0">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        <script src="https://www.googletagmanager.com/gtag/js?id=G-TEST"></script>
        <script src="https://www.googletagmanager.com/gtm.js?id=GTM-TEST"></script>
        <script src="https://js.stripe.com/v3/"></script>
        <script src="https://cdn.auth0.com/js/auth0/9.28/auth0.min.js"></script>
        <script src="https://known-stack.example/_next/static/chunks/app.js"></script>
        <script id="__next_data__">{"page": "home"}</script>
        <script>gtag('config', 'G-TEST');</script>
      </head>
      <body><div data-reactroot class="container btn btn-primary">Known stack</div></body>
    </html>
    """
    response = HTTPResponse(
        page_id=page.id,
        status_code=200,
        final_url=base_url,
        content_type="text/html",
        timings_ms=12.5,
        raw_body=html,
    )
    db.add(response)
    db.flush()
    db.add_all(
        [
            Header(http_response_id=response.id, name="server", value="cloudflare"),
            Header(http_response_id=response.id, name="cf-ray", value="test-ray"),
        ]
    )
    db.add_all(
        [
            Resource(
                page_id=page.id,
                url="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css",
                type="link",
                attributes={"rel": ["stylesheet"]},
            ),
            Resource(
                page_id=page.id,
                url="https://www.googletagmanager.com/gtag/js?id=G-TEST",
                type="script",
                attributes={},
            ),
            Resource(
                page_id=page.id,
                url="https://www.googletagmanager.com/gtm.js?id=GTM-TEST",
                type="script",
                attributes={},
            ),
            Resource(
                page_id=page.id,
                url="https://known-stack.example/_next/static/chunks/app.js",
                type="script",
                attributes={},
            ),
            Resource(
                page_id=page.id,
                url="https://js.stripe.com/v3/",
                type="script",
                attributes={},
            ),
            Resource(
                page_id=page.id,
                url="https://cdn.auth0.com/js/auth0/9.28/auth0.min.js",
                type="script",
                attributes={},
            ),
        ]
    )
    db.commit()
    db.refresh(scan)
    return scan


def test_known_stack_detection_persists_evidence_and_confidence(db: Session) -> None:
    scan = make_known_stack_scan(db)

    detections = TechnologyDetectionService(db, scan.id).detect()
    by_name = {d.canonical_name: d for d in detections}

    expected = {
        "Next.js",
        "React",
        "Bootstrap",
        "WordPress",
        "Google Tag Manager",
        "Cloudflare",
        "Stripe",
        "Auth0",
    }
    assert expected <= set(by_name)
    assert all(d.classification == "inferred" for d in detections)
    assert all(0 <= d.confidence <= 100 for d in detections)
    assert all(d.evidence for d in detections)
    assert all(e.observation and e.source and e.match_rule for d in detections for e in d.evidence)
    assert by_name["Next.js"].confidence >= 70
    assert by_name["Cloudflare"].confidence >= 70


def test_confidence_is_repeatable_for_same_evidence(db: Session) -> None:
    scan = make_known_stack_scan(db)
    service = TechnologyDetectionService(db, scan.id)
    first = {
        (d.canonical_name, d.category): (d.confidence, d.confidence_band, d.rule_version)
        for d in service.detect()
    }
    second = {
        (d.canonical_name, d.category): (d.confidence, d.confidence_band, d.rule_version)
        for d in TechnologyDetectionService(db, scan.id).detect()
    }
    assert first == second


def test_evidence_agent_rejects_detection_without_linked_evidence(db: Session) -> None:
    scan = make_known_stack_scan(db)
    service = TechnologyDetectionService(db, scan.id)
    candidate = DetectionCandidate(
        technology="Unsupported Vendor",
        category="cms",
        confidence=90,
        confidence_band="high",
        rule_version="phase4-v1",
        signals=(),
    )

    with pytest.raises(EvidenceValidationError):
        service._persist_candidate(candidate)
    assert db.query(Technology).filter(Technology.scan_id == scan.id).count() == 0


def test_custom_json_signature_is_detected_without_engine_changes(db: Session, tmp_path) -> None:
    scan = make_known_stack_scan(db)
    custom_path = tmp_path / "custom_rules.json"
    custom_path.write_text(
        json.dumps(
            {
                "version": "custom-test-v1",
                "rules": [
                    {
                        "id": "custom-marker",
                        "technology": "Contest CMS",
                        "category": "cms",
                        "signal_type": "dom_pattern",
                        "pattern": "Known stack",
                        "weight": 80,
                        "field": "html",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(technology_module, "RULESET_PATH", custom_path)
    try:
        detections = TechnologyDetectionService(db, scan.id).detect()
    finally:
        monkeypatch.undo()

    custom = next(d for d in detections if d.canonical_name == "Contest CMS")
    assert custom.rule_version == "custom-test-v1"
    assert custom.evidence[0].match_rule == "custom-marker"
