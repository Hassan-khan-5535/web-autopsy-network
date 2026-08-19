import json

from app.models.scan import HTTPObservation, HTTPResponse, Header, Page, Scan, Website
from app.services.http_agent import HTTPAgent
from app.services.tasks import TaskGraphCoordinator


def _scan(db, *, url="https://example.com/"):
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
        recon_mode="disabled",
    )
    db.add(scan)
    db.flush()
    return scan


def test_http_agent_redacts_secrets_and_normalizes_behavior(db):
    scan = _scan(db)
    page = Page(scan_id=scan.id, canonical_url="https://example.com/?token=visible", status_code=200)
    db.add(page)
    db.flush()
    response = HTTPResponse(
        page_id=page.id,
        status_code=200,
        final_url="https://example.com/login?session=final",
        content_type="text/html; charset=utf-8",
        timings_ms=42.5,
        raw_body="<html>ok</html>",
        body_truncated=True,
        redirect_chain=[["https://example.com/?token=visible", "https://example.com/login?session=secret"]],
    )
    db.add(response)
    db.flush()
    headers = [
        ("authorization", "Bearer super-secret-token"),
        ("set-cookie", "session=super-secret; Path=/; Secure; HttpOnly; SameSite=Lax"),
        ("cache-control", "public, max-age=60"),
        ("etag", "\"abc\""),
        ("content-encoding", "gzip"),
        ("content-length", "17"),
        ("access-control-allow-origin", "https://client.example"),
        ("content-security-policy", "default-src 'self'"),
        ("strict-transport-security", "max-age=31536000; includeSubDomains"),
        ("location", "https://example.com/next?code=secret"),
    ]
    for name, value in headers:
        db.add(Header(http_response_id=response.id, name=name, value=value))
    db.commit()

    observations = HTTPAgent(db, scan.id).analyze()
    assert observations
    encoded = json.dumps([item.value for item in observations], sort_keys=True)
    subjects = " ".join(item.subject for item in observations)
    assert "super-secret" not in encoded
    assert "super-secret-token" not in encoded
    assert "visible" not in subjects
    assert "secret" not in subjects

    by_type = {}
    for item in observations:
        by_type.setdefault(item.observation_type, []).append(item)
    assert by_type["status_code"][0].value["status_band"] == "2xx_success"
    assert by_type["tls"][0].value["https_observed"] is True
    assert by_type["tls"][0].value["certificate_details_captured"] is False
    assert by_type["cache"][0].value["cache_control_directives"]["max-age"] == "60"
    assert by_type["compression"][0].value["content_encoding"] == ["gzip"]
    assert by_type["cors"][0].value["origin_matrix_tested"] is False
    assert by_type["content_type"][0].value["body_truncated"] is True
    assert any(item.redacted for item in by_type["cookie"])
    assert any(item.redacted for item in by_type["header"])
    assert by_type["redirect"][0].value["hop_count"] == 1
    assert any(item.value.get("anomaly") == "response_body_truncated" for item in by_type["response_anomaly"])


def test_http_agent_handles_error_and_missing_response(db):
    scan = _scan(db)
    error_page = Page(scan_id=scan.id, canonical_url="https://example.com/missing", status_code=404)
    empty_page = Page(scan_id=scan.id, canonical_url="https://example.com/no-response", status_code=None)
    db.add_all([error_page, empty_page])
    db.flush()
    db.add(HTTPResponse(page_id=error_page.id, status_code=404, final_url=error_page.canonical_url, content_type=None))
    db.commit()

    observations = HTTPAgent(db, scan.id).analyze()
    anomalies = [item for item in observations if item.observation_type == "response_anomaly"]
    assert any(item.value.get("anomaly") == "error_response" for item in anomalies)
    assert any(item.value.get("anomaly") == "no_persisted_response" for item in anomalies)


def test_http_agent_task_is_additive_and_security_waits_for_it(db):
    scan = _scan(db)
    TaskGraphCoordinator.initialize_scan(db, scan.id)
    TaskGraphCoordinator.after_collection(db, scan.id)
    task_map = {task.task_type: task for task in scan.agent_tasks}
    assert "http_agent" in task_map
    assert task_map["http_agent"].dependency_keys == ["collection"]
    assert "http_agent" in (task_map["security"].dependency_keys or [])
