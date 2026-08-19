from unittest.mock import MagicMock, patch
from uuid import uuid4

import httpx
import pytest

from app.models.scan import Page, Scan, Website
from app.services.admission import AdmissionService
from app.services.browser_client import BrowserWorkerClient
from app.services.scanner_security import (
    ScannerSecurityError,
    bounded_headers,
    bounded_html_body,
    redact_sensitive_text,
    revalidate_egress,
)


def test_egress_revalidates_dns_and_blocks_non_web_ports(monkeypatch):
    calls = []

    def resolver(url, **kwargs):
        calls.append((url, kwargs))
        return url, "93.184.216.34"

    monkeypatch.setattr(AdmissionService, "validate_and_resolve", staticmethod(resolver))
    assert revalidate_egress("https://example.com/path", assessment_profile="safe", explicit_allowlist=True) == "https://example.com/path"
    assert len(calls) == 1
    with pytest.raises(ScannerSecurityError, match="port"):
        revalidate_egress("https://example.com:8443/path", assessment_profile="safe", explicit_allowlist=True)


def test_response_limits_reject_hostile_headers_declared_sizes_and_unknown_compression():
    oversized_headers = httpx.Response(200, headers={"x-large": "x" * 200})
    with pytest.raises(ScannerSecurityError, match="headers"):
        bounded_headers(oversized_headers, 32)

    declared_large = httpx.Response(200, headers={"content-type": "text/html", "content-length": "1000"}, content=b"<html></html>")
    with pytest.raises(ScannerSecurityError, match="Declared"):
        bounded_html_body(declared_large, 32)

    unknown_encoding = httpx.Response(200, headers={"content-type": "text/html", "content-encoding": "zstd"}, content=b"<html></html>")
    with pytest.raises(ScannerSecurityError, match="compression"):
        bounded_html_body(unknown_encoding, 1024)


def test_response_body_is_stream_bounded_and_secret_text_is_redacted():
    response = httpx.Response(200, headers={"content-type": "text/html"}, content=b"<html>" + b"x" * 64 + b"</html>")
    response.headers.pop("content-length", None)
    body, truncated = bounded_html_body(response, 24)
    assert truncated is True
    assert len(body.encode()) <= 24
    assert "secret=[REDACTED]" in redact_sensitive_text("secret=super-secret-value")
    assert "super-secret-value" not in redact_sensitive_text("secret=super-secret-value")


def test_browser_rejects_cross_scan_page_ownership_before_worker_call(db):
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.flush()
    scan_a = Scan(website_id=website.id, requested_url="https://example.com", state="COLLECTING")
    scan_b = Scan(website_id=website.id, requested_url="https://example.com", state="COLLECTING")
    db.add_all([scan_a, scan_b])
    db.flush()
    page_b = Page(scan_id=scan_b.id, canonical_url="https://example.com/", depth=0)
    db.add(page_b)
    db.commit()

    with patch("httpx.post") as post:
        assert BrowserWorkerClient(db).analyze_page(scan_a.id, page_b.id, "https://example.com/") is False
        post.assert_not_called()


def test_browser_request_uses_no_credentials_by_default_and_binds_budget_payload(db):
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.flush()
    scan = Scan(website_id=website.id, requested_url="https://example.com", state="COLLECTING")
    db.add(scan)
    db.flush()
    page = Page(scan_id=scan.id, canonical_url="https://example.com/", depth=0)
    db.add(page)
    db.commit()
    payload = {"status": "success", "rendered_html": "<html></html>", "network_requests": [], "console_logs": []}
    with patch("httpx.post", return_value=MagicMock(status_code=200, json=lambda: payload)) as post:
        assert BrowserWorkerClient(db).analyze_page(scan.id, page.id, "https://example.com/") is True
        request = post.call_args.kwargs["json"]
        assert request["headers"] == {}
        assert request["scan_id"] == str(scan.id)
        assert request["page_id"] == str(page.id)
        assert request["resource_limits"]["max_cpu_seconds"] > 0
        assert request["resource_limits"]["max_memory_mb"] > 0
        assert request["resource_limits"]["max_network_events"] > 0
