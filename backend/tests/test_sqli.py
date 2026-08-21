from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from sqlalchemy.orm import Session

from app.models.scan import AssessmentAuthorization, HTTPResponse, Page, Scan, Website
from app.services.sqli import (
    RULE_VERSION,
    TIMING_BASELINE_SAMPLES,
    TIMING_MAX_DELAY_SECONDS,
    TIMING_VALUES_SECONDS,
    SQLiDetectionAgent,
)


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


class _TimingFixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        value = parse_qs(urlsplit(self.path).query).get("id", [""])[0].lower()
        delay = 0
        if "if(1=1,sleep(1)" in value:
            delay = 1
        elif "if(1=1,sleep(3)" in value:
            delay = 3
        elif "if(1=1,sleep(5)" in value:
            delay = 5
        if delay:
            time.sleep(delay)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"normal results")

    def log_message(self, *_args: object) -> None:
        return


class _UnionFixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        value = parse_qs(urlsplit(self.path).query).get("id", [""])[0].lower()
        if "union select" in value:
            null_count = value.split("union select", 1)[1].count("null")
            if null_count == 3:
                body, status = "normal page structure 123", 200
            else:
                body, status = "SQLite error: column mismatch", 500
        else:
            body, status = "normal page structure 123", 200
        self.send_response(status)
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


def _fixture_scan(db: Session, port: int, *, enabled: bool, extended: bool = False, request_budget: int = 30) -> tuple[Scan, Page]:
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
        max_requests=request_budget,
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
        max_requests=request_budget,
        max_concurrency=1,
        rate_limit_per_host_ms=1,
        consent_hash="fixture",
        scope_json={
            "allowed_ports": [port],
            "allowed_paths": ["/search"],
            "excluded_paths": [],
            "sqli_validation_enabled": enabled,
            "sqli_extended_validation_enabled": extended,
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


def test_sqli_stage3_uses_ten_baselines_and_correlated_bounded_delays(db: Session, monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _TimingFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scan, page = _fixture_scan(db, server.server_port, enabled=True, extended=True, request_budget=100)
        monkeypatch.setattr("app.services.sqli.revalidate_egress", lambda url, **_kwargs: url)
        agent = SQLiDetectionAgent(db, scan.id)
        findings = agent.analyze()
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "SQLI-TIMING-001"
        assert finding.page_id == page.id
        report = agent.report()
        assert report["summary"]["stages"]["timing_safe"] == 1
        assert report["summary"]["timing_validation"]["baseline_samples_required"] == TIMING_BASELINE_SAMPLES
        gate = next(item for item in finding.evidence if item.get("type") == "validation_gate")
        assert gate["baseline_sample_count"] == 10
        assert gate["timing_values_seconds"] == list(TIMING_VALUES_SECONDS)
        assert gate["database_type"] == "mysql"
        assert gate["correlation"] >= 0.85
        assert gate["safe_control_elapsed_ms"] < gate["delay_threshold_ms"]
        assert gate["max_delay_seconds"] == TIMING_MAX_DELAY_SECONDS
        assert gate["heavy_delay_payloads_used"] is False
        assert gate["network_jitter_accounted"] is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_sqli_stage4_infers_null_only_column_count_and_preserves_structure(db: Session, monkeypatch):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _UnionFixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scan, page = _fixture_scan(db, server.server_port, enabled=True, extended=True, request_budget=100)
        monkeypatch.setattr("app.services.sqli.revalidate_egress", lambda url, **_kwargs: url)
        agent = SQLiDetectionAgent(db, scan.id)
        surface = agent._surfaces()[0]
        baseline = agent._request(surface.url, "union_baseline")
        finding = agent._stage4(surface, baseline)
        assert finding is not None
        assert finding.rule_id == "SQLI-UNION-001"
        assert finding.page_id == page.id
        gate = next(item for item in finding.evidence if item.get("type") == "validation_gate")
        assert gate["column_count"] == 3
        assert gate["null_only"] is True
        assert gate["mismatch_count"] >= 1
        assert gate["sensitive_data_checked"] is True
        assert gate["sensitive_data_detected"] is False
        assert gate["matching_variant"]["database_variant"] in {"generic", "mysql", "oracle", "mssql"}
        assert all(item["column_count"] <= 3 for item in gate["column_results"])
        assert all("payload" not in str(item).lower() for item in gate["column_results"])
        assert agent._structure_hash("normal page structure 123") == agent._structure_hash("normal page structure 456")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_sqli_stage4_sensitive_data_guard_and_column_cap():
    assert not SQLiDetectionAgent._contains_sensitive_data("normal page structure")
    assert SQLiDetectionAgent._contains_sensitive_data("api_key=abcdefghijklmnopqrstuvwxyz123456")
    try:
        SQLiDetectionAgent._union_payloads(4)
    except ValueError:
        pass
    else:
        raise AssertionError("union payloads accepted a column count above the bounded cap")


def test_sqli_stage3_rejects_unsupported_or_heavy_delay_values(db: Session):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SQLiFixtureHandler)
    try:
        scan, _ = _fixture_scan(db, server.server_port, enabled=True, extended=True, request_budget=100)
        agent = SQLiDetectionAgent(db, scan.id)
        assert all("randomblob" not in payload.lower() for _, payload in agent._timing_payloads(5))
        assert all("sleep(10" not in payload.lower() and "sleep(10" not in payload.lower() for _, payload in agent._timing_payloads(5))
        try:
            agent._timing_payloads(TIMING_MAX_DELAY_SECONDS + 1)
        except ValueError:
            pass
        else:
            raise AssertionError("timing payloads accepted a delay above the five-second cap")
    finally:
        server.server_close()


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
