import asyncio

import pytest
from pydantic import ValidationError

from browser_worker import app as worker


def test_browser_worker_enforces_domain_and_path_scope_with_public_resolution(monkeypatch):
    monkeypatch.setattr(worker.socket, "getaddrinfo", lambda *_args, **_kwargs: [(2, 1, 6, "", ("93.184.216.34", 0))])
    assert worker.is_url_allowed("https://example.com/allowed", allowed_domains=["example.com"], allowed_paths=["/allowed"], excluded_paths=[]) is True
    assert worker.is_url_allowed("https://sub.example.com/allowed", allowed_domains=["example.com"], allowed_paths=["/allowed"], excluded_paths=[]) is True
    assert worker.is_url_allowed("https://example.com/blocked", allowed_domains=["example.com"], allowed_paths=["/allowed"], excluded_paths=[]) is False
    assert worker.is_url_allowed("https://other.example/allowed", allowed_domains=["example.com"], allowed_paths=["/allowed"], excluded_paths=[]) is False


def test_browser_worker_rejects_unexpected_render_fields_and_bounds_contract():
    with pytest.raises(ValidationError):
        worker.RenderRequest(url="https://example.com", unexpected="value")
    request = worker.RenderRequest(url="https://example.com", resource_limits={"max_network_events": 3, "max_console_events": 2, "max_rendered_bytes": 1024})
    assert request.resource_limits.max_network_events == 3
    assert request.resource_limits.max_console_events == 2


def test_browser_worker_blocks_target_before_playwright_initialization(monkeypatch):
    monkeypatch.setattr(worker, "is_url_allowed", lambda *_args, **_kwargs: False)
    response = asyncio.run(worker.render_page(worker.RenderRequest(url="http://127.0.0.1/")))
    assert response.status == "failed"
    assert "SSRF Check blocked" in (response.error or "")


def test_browser_worker_redacts_sensitive_error_text():
    rendered = worker._redact("Authorization=Bearer-sensitive-token secret=top-secret")
    assert "sensitive-token" not in rendered
    assert "top-secret" not in rendered
    assert "[REDACTED]" in rendered
