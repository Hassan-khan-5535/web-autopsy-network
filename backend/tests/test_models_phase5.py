from __future__ import annotations

from app.models.scan import ApiEndpoint, Dependency, Scan, Website


def test_dependency_model(db):
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.commit()

    scan = Scan(website_id=website.id, requested_url="https://example.com")
    db.add(scan)
    db.commit()

    dep = Dependency(
        scan_id=scan.id,
        domain="cdn.example.com",
        category="CDN",
        classification="inferred",
        confidence=0.9,
        reference_count=3,
        sample_resource_urls=["https://cdn.example.com/js/app.js"],
    )
    db.add(dep)
    db.commit()
    db.refresh(dep)

    assert dep.id is not None
    assert dep.scan_id == scan.id
    assert dep.domain == "cdn.example.com"
    assert dep.category == "CDN"
    assert dep.confidence == 0.9
    assert dep.reference_count == 3
    assert dep.sample_resource_urls == ["https://cdn.example.com/js/app.js"]


def test_api_endpoint_model(db):
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.commit()

    scan = Scan(website_id=website.id, requested_url="https://example.com")
    db.add(scan)
    db.commit()

    endpoint = ApiEndpoint(
        scan_id=scan.id,
        url_or_path="/api/v1/users",
        http_method="GET",
        content_type="application/json",
        classification="inferred",
        confidence=0.85,
        discovered_from_source="inline script fetch",
    )
    db.add(endpoint)
    db.commit()
    db.refresh(endpoint)

    assert endpoint.id is not None
    assert endpoint.scan_id == scan.id
    assert endpoint.url_or_path == "/api/v1/users"
    assert endpoint.http_method == "GET"
    assert endpoint.content_type == "application/json"
    assert endpoint.confidence == 0.85
