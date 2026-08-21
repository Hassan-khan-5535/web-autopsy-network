from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from sqlalchemy.orm import Session

from app.models.scan import AssessmentAuthorization, HTTPResponse, Page, Scan, Website
from app.services.sqli import RULE_VERSION, SQLiDetectionAgent


class _BooleanFixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        value = parse_qs(urlsplit(self.path).query).get("id", [""])[0].lower()
        if "1=2" in value or "'1'='2" in value:
            body = "empty"
        else:
            body = "normal results"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *_args: object) -> None:
        return


class _RateLimitedBooleanFixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        value = parse_qs(urlsplit(self.path).query).get("id", [""])[0].lower()
        if "1=2" in value or "'1'='2" in value:
            self.send_response(429)
            self.send_header("Retry-After", "2")
            body = "rate limited"
        else:
            self.send_response(200)
            body = "normal results"
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *_args: object) -> None:
        return


class _SQLiFixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        value = parse_qs(urlsplit(self.path).query).get("id", [""])[0]
        if "'" in value and "''" not in value:
            body, status = "SQLite error: near syntax error", 500
        else:
            body, status = "ok", 200
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *_args: object) -> None:
        return


def _fixture_scan(db: Session, port: int, *, enabled: bool) -> tuple[Scan, Page]:
    website = Website(canonical_origin="127.0.0.1")
    db.add(website)
    db.flush()
    scan = Scan(
        website_id=website.id,
        state="COMPLETED",
        requested_url=f"http://127.0.0.1:{port}/search?id=1",
        max_depth=1,
        max_pages=3,
        max_concurrency=1,
        request_delay_ms=1,
        max_requests=30,
        recon_mode="active_safe",
        assessment_profile="safe",
        requests_used=0,
    )
    db.add(scan)
    db.flush()
    auth = AssessmentAuthorization(
        scan_id=scan.id,
        authorization_type="acknowledged",
        actor_id="test",
        target_url=scan.requested_url,
        allowed_paths=["/search"],
        excluded_paths=[],
        allowed_domains=["127.0.0.1"],
        assessment_profile="safe",
        max_depth=1,
        max_pages=3,
        max_requests=30,
        max_concurrency=1,
        rate_limit_per_host_ms=1,
        consent_hash="fixture",
        scope_json={
            "allowed_ports": [port],
            "allowed_paths": ["/search"],
            "excluded_paths": [],
            "sqli_validation_enabled": enabled,
        },
    )
    db.add(auth)
    page = Page(scan_id=scan.id, canonical_url=scan.requested_url, depth=0, status_code=200)
    db.add(page)
    db.flush()
    db.add(HTTPResponse(page_id=page.id, status_code=200, final_url=page.canonical_url, content_type="text/html", raw_body="ok"))
    db.commit()
    return scan, page


def test_sqli_agent_is_disabled_without_explicit_opt_in(db: Session):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SQLiFixtureHandler)
    try:
        scan, _ = _fixture_scan(db, server.server_port, enabled=False)
        agent = SQLiDetectionAgent(db, scan.id)
        findings = agent.analyze()
        assert findings == []
        assert agent.report()["summary"]["enabled"] is False
        assert agent.report()["safe_validation"]["network_requests_issued"] == 0
    finally:
        server.server_close()


def test_sqli_agent_detects_reproducible_boolean_differential_after_five_baselines(db: Session, monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BooleanFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scan, page = _fixture_scan(db, server.server_port, enabled=True)
        monkeypatch.setattr("app.services.sqli.revalidate_egress", lambda url, **_kwargs: url)
        agent = SQLiDetectionAgent(db, scan.id)
        findings = agent.analyze()
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "SQLI-DIFF-001"
        assert finding.severity == "high"
        assert finding.classification == "OBSERVED"
        assert finding.page_id == page.id
        report = agent.report()
        assert report["summary"]["stages"]["differential"] == 1
        gate = next(item for item in finding.evidence if item.get("type") == "validation_gate")
        assert gate["baseline_samples"] == 5
        assert gate["pair_count"] == 3
        assert gate["true_matches_baseline"] is True
        assert gate["false_hash_differs"] is True
        assert gate["false_length_ratio"] > 0.10
        assert report["safe_validation"]["mutating_requests_issued"] == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_sqli_agent_suppresses_boolean_difference_when_rate_limited(db: Session, monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RateLimitedBooleanFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scan, _ = _fixture_scan(db, server.server_port, enabled=True)
        monkeypatch.setattr("app.services.sqli.revalidate_egress", lambda url, **_kwargs: url)
        agent = SQLiDetectionAgent(db, scan.id)
        assert agent.analyze() == []
        assert agent.report()["summary"]["differential_validation"]["noise_suppressed"] > 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_sqli_agent_detects_reproducible_error_based_get_canary(db: Session, monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SQLiFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scan, page = _fixture_scan(db, server.server_port, enabled=True)
        monkeypatch.setattr("app.services.sqli.revalidate_egress", lambda url, **_kwargs: url)
        agent = SQLiDetectionAgent(db, scan.id)
        findings = agent.analyze()
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "SQLI-ERROR-001"
        assert finding.category == "sqli"
        assert finding.severity == "high"
        assert finding.classification == "OBSERVED"
        assert finding.page_id == page.id
        assert finding.rule_version == RULE_VERSION
        assert finding.evidence
        assert all("payload_value_stored" not in str(item) or item.get("payload_value_stored") is False for item in finding.evidence)
        report = agent.report()
        assert report["summary"]["stages"]["error_based"] == 1
        assert report["summary"]["payloads_sent"] > 0
        assert report["safe_validation"]["forms_submitted"] == 0
        assert report["safe_validation"]["mutating_requests_issued"] == 0
        assert report["safe_validation"]["data_extraction_attempted"] is False
        observations = [item for item in scan.http_observations if item.observation_type == "sqli_validation"]
        assert observations
        assert all(item.redacted for item in observations)
        assert all(item.value.get("payload_value_stored") is False for item in observations)
        assert all("payload_value" not in item.value for item in observations)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
