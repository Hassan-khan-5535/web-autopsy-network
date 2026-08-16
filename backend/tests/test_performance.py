from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from app.models.scan import (
    Dependency,
    HTTPResponse,
    Page,
    PerformanceMetric,
    Resource,
    Scan,
    Website,
)
from app.services.performance import MetricCandidate, PerformanceEngine, PerformanceEvidenceError


def make_scan_with_page(
    db: Session,
    *,
    url: str = "https://performance.example/",
    body: str = "<html><head></head><body></body></html>",
    timings_ms: float | None = 123.0,
    timing_data: dict | None = None,
) -> tuple[Scan, Page, HTTPResponse]:
    website = Website(id=uuid4(), tenant_id="default", canonical_origin="performance.example")
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
    page = Page(scan_id=scan.id, canonical_url=url, depth=0, title="Performance fixture")
    db.add(page)
    db.flush()
    response = HTTPResponse(
        page_id=page.id,
        status_code=200,
        final_url=url,
        content_type="text/html",
        timings_ms=timings_ms,
        timing_data=timing_data,
        raw_body=body,
        rendered_body=body,
    )
    db.add(response)
    db.commit()
    db.refresh(scan)
    db.refresh(page)
    return scan, page, response


def add_resource(
    db: Session,
    page: Page,
    url: str,
    resource_type: str,
    *,
    capture_source: str = "static_http",
    attributes: dict | None = None,
) -> Resource:
    resource = Resource(
        page_id=page.id,
        url=url,
        type=resource_type,
        attributes=attributes,
        capture_source=capture_source,
    )
    db.add(resource)
    db.commit()
    return resource


def test_performance_engine_persists_page_metrics_and_site_aggregates(db: Session) -> None:
    body = """
    <html><head>
      <script src="/static/app.js"></script>
      <script async src="/static/async.js"></script>
      <link rel="stylesheet" href="/static/site.css">
    </head><body><img src="/static/logo.png"></body></html>
    """
    timing_data = {"navigation": {"domInteractive": 210, "domComplete": 430, "loadEventEnd": 510}}
    scan, page, _ = make_scan_with_page(db, body=body, timing_data=timing_data)
    add_resource(
        db, page, "https://performance.example/static/app.js", "script", attributes={"size": 250000}
    )
    add_resource(
        db,
        page,
        "https://performance.example/static/site.css",
        "link",
        attributes={"rel": ["stylesheet"], "size": 20000},
    )
    add_resource(
        db, page, "https://performance.example/static/logo.png", "img", attributes={"size": 5000}
    )
    add_resource(
        db,
        page,
        "https://cdn.example/vendor.js",
        "script",
        attributes={"size": 10000},
        capture_source="browser_runtime",
    )
    add_resource(
        db,
        page,
        "https://performance.example/static/app.js",
        "script",
        capture_source="browser_runtime",
    )
    add_resource(
        db, page, "https://analytics.example/pixel", "other", capture_source="browser_runtime"
    )
    db.add(
        Dependency(
            scan_id=scan.id, domain="analytics.example", category="Analytics", reference_count=1
        )
    )
    db.commit()

    metrics = PerformanceEngine(db, scan.id).analyze()
    by_name = {metric.metric_name: metric for metric in metrics if metric.page_id == page.id}

    assert by_name["static_resource_reference_count"].value == 3
    assert by_name["js_payload_size_bytes"].value == 250000
    assert by_name["css_payload_size_bytes"].value == 20000
    assert by_name["image_payload_size_bytes"].value == 5000
    assert by_name["ttfb_ms"].value == 123
    assert by_name["page_load_time_ms"].value == 510
    assert by_name["dom_interactive_ms"].value == 210
    assert by_name["render_blocking_resource_count"].value == 2
    assert by_name["request_count"].value == 3
    assert by_name["third_party_request_count"].value == 2
    assert by_name["third_party_payload_size_bytes"].classification == "OBSERVED"
    assert by_name["third_party_payload_size_bytes"].value == 0
    assert all(metric.evidence for metric in metrics)
    assert any(metric.scope == "site" for metric in metrics)


def test_browser_timings_are_unknown_without_browser_timing_data(db: Session) -> None:
    scan, page, _ = make_scan_with_page(db, timing_data=None)
    metrics = PerformanceEngine(db, scan.id).analyze()
    by_name = {metric.metric_name: metric for metric in metrics if metric.page_id == page.id}

    for name in (
        "page_load_time_ms",
        "dom_interactive_ms",
        "dom_complete_ms",
        "dom_content_loaded_ms",
    ):
        assert by_name[name].value is None
        assert by_name[name].classification == "UNKNOWN"
        assert "UNKNOWN" in by_name[name].statement
    assert by_name["ttfb_ms"].value == 123


def test_blocking_detection_and_diagnoses_are_evidence_backed(db: Session) -> None:
    scripts = "".join(f'<script src="/static/app-{index}.js"></script>' for index in range(6))
    body = (
        f'<html><head>{scripts}<link rel="stylesheet" href="/site.css"></head><body></body></html>'
    )
    scan, page, _ = make_scan_with_page(
        db, body=body, timing_data={"navigation": {"loadEventEnd": 400}}
    )
    for index in range(6):
        add_resource(
            db,
            page,
            f"https://performance.example/static/app-{index}.js",
            "script",
            attributes={"size": 50000},
        )
    add_resource(
        db,
        page,
        "https://performance.example/site.css",
        "link",
        attributes={"rel": ["stylesheet"]},
    )
    for index in range(3):
        add_resource(
            db,
            page,
            f"https://analytics.example/request-{index}",
            "other",
            capture_source="browser_runtime",
        )
    add_resource(
        db, page, "https://performance.example/runtime", "other", capture_source="browser_runtime"
    )
    db.add(
        Dependency(
            scan_id=scan.id, domain="analytics.example", category="Analytics", reference_count=3
        )
    )
    db.commit()

    metrics = PerformanceEngine(db, scan.id).analyze()
    names = {metric.metric_name for metric in metrics}
    diagnoses = [metric for metric in metrics if metric.classification == "INFERRED"]

    assert "diagnosis:large_js_payload" in names
    assert "diagnosis:render_blocking_resources" in names
    assert "diagnosis:third_party_request_overhead" in names
    assert all(metric.evidence for metric in diagnoses)
    assert all(metric.statement for metric in diagnoses)


def test_evidence_agent_rejects_metric_without_evidence(db: Session) -> None:
    scan, _, _ = make_scan_with_page(db)
    service = PerformanceEngine(db, scan.id)
    candidate = MetricCandidate(
        scope="page",
        metric_name="unsupported_claim",
        value=1,
        unit="count",
        classification="INFERRED",
        confidence=90,
        confidence_band="high",
        capture_mode="derived",
        statement="This claim has no supporting evidence.",
        evidence=(),
    )

    with pytest.raises(PerformanceEvidenceError):
        service._persist_candidate(candidate)
    assert db.query(PerformanceMetric).filter(PerformanceMetric.scan_id == scan.id).count() == 0


def test_performance_analysis_makes_no_network_requests(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    import httpx

    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("Phase 8 performance analysis must not issue network requests")

    for method_name in ("request", "get", "post", "put", "delete"):
        monkeypatch.setattr(httpx, method_name, fail_if_called)

    scan, _, _ = make_scan_with_page(db)
    assert PerformanceEngine(db, scan.id).analyze()


def test_performance_analysis_is_idempotent(db: Session) -> None:
    scan, _, _ = make_scan_with_page(db)
    first = PerformanceEngine(db, scan.id).analyze()
    first_names = sorted(metric.metric_name for metric in first)
    first_count = db.query(PerformanceMetric).filter(PerformanceMetric.scan_id == scan.id).count()

    second = PerformanceEngine(db, scan.id).analyze()
    second_names = sorted(metric.metric_name for metric in second)
    second_count = db.query(PerformanceMetric).filter(PerformanceMetric.scan_id == scan.id).count()

    assert first_count == len(first)
    assert second_count == len(second)
    assert first_count == second_count
    assert first_names == second_names
