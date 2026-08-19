from __future__ import annotations

import ipaddress
import socket
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.api.routes.scans import ScanCreate, create_scan, get_assessment_audit, get_assessment_authorization
from app.models.scan import AssessmentAuditEvent, AssessmentAuthorization, Scan, Website
from app.services.admission import AdmissionService, SSRFViolationError
from app.services.assessment import (
    append_audit_event,
    decrypt_secret,
    encrypt_secret,
    hostname_allowed,
    path_allowed,
    profile_policy,
)
from app.services.tasks import TaskGraphCoordinator


def test_profile_caps_are_server_enforced():
    safe = profile_policy(
        "safe",
        max_depth=99,
        max_requests=999,
        max_concurrency=99,
        rate_limit_per_host_ms=1,
    )
    assert safe == {
        "max_depth": 2,
        "max_requests": 30,
        "max_concurrency": 2,
        "rate_limit_per_host_ms": 1000,
    }


def test_scope_matches_domains_paths_and_exclusions():
    assert hostname_allowed("static.example.com", ["example.com"])
    assert not hostname_allowed("example.net", ["example.com"])
    assert path_allowed("https://example.com/docs/guide", ["/docs"], [])
    assert not path_allowed("https://example.com/admin", [], ["/admin"])
    assert not path_allowed("https://example.com/checkout/pay", [], ["/checkout/*"])


def test_private_and_reserved_addresses_are_blocked(monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.20", 443))],
    )
    with pytest.raises(SSRFViolationError):
        AdmissionService.validate_and_resolve("https://internal.example")


def test_aggressive_requires_explicit_allowlist(monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    with pytest.raises(SSRFViolationError):
        AdmissionService.validate_and_resolve("https://example.com", assessment_profile="aggressive")
    canonical, address = AdmissionService.validate_and_resolve(
        "https://example.com", assessment_profile="aggressive", explicit_allowlist=True
    )
    assert canonical == "https://example.com/"
    assert address == "93.184.216.34"


def test_authorization_recorded_with_hash_and_encrypted_secret(db, monkeypatch):
    monkeypatch.setattr(
        AdmissionService,
        "validate_and_resolve",
        staticmethod(lambda url, **kwargs: ("https://example.com/", "93.184.216.34")),
    )
    monkeypatch.setattr(TaskGraphCoordinator, "initialize_scan", classmethod(lambda cls, db, scan_id: None))
    request = ScanCreate(
        url="https://example.com",
        authorization_acknowledged=True,
        assessment_profile="safe",
        allowed_paths=["/"],
        excluded_paths=["/admin"],
        allowed_domains=["example.com"],
        authentication={"type": "header", "name": "X-Test-Token", "value": "secret-token"},
        test_account_ref="vault:test-account-1",
    )
    response = create_scan(request, db)
    scan = db.query(Scan).filter(Scan.id == response["id"]).one()
    authorization = db.query(AssessmentAuthorization).filter(AssessmentAuthorization.scan_id == scan.id).one()
    event = db.query(AssessmentAuditEvent).filter(AssessmentAuditEvent.scan_id == scan.id).one()

    assert response["assessment_profile"] == "safe"
    assert authorization.consent_hash and len(authorization.consent_hash) == 64
    assert authorization.auth_secret_encrypted
    assert "secret-token" not in authorization.auth_secret_encrypted
    assert decrypt_secret(authorization.auth_secret_encrypted) == {
        "type": "header",
        "name": "X-Test-Token",
        "value": "secret-token",
    }
    assert event.event_type == "AUTHORIZATION_RECORDED"
    assert event.event_hash != event.previous_hash
    public = get_assessment_authorization(scan.id, db)
    assert public["authentication_configured"] is True
    assert "secret-token" not in str(public)
    assert get_assessment_audit(scan.id, db)[0]["event_hash"] == event.event_hash


def test_audit_events_form_a_hash_chain(db):
    website = Website(tenant_id="default", canonical_origin="example.com")
    db.add(website)
    db.flush()
    scan = Scan(website_id=website.id, requested_url="https://example.com/", state="QUEUED")
    db.add(scan)
    db.flush()
    first = append_audit_event(db, scan_id=scan.id, event_type="ONE", actor_id="u1", payload={"x": 1})
    db.commit()
    second = append_audit_event(db, scan_id=scan.id, event_type="TWO", actor_id="u1", payload={"x": 2})
    db.commit()
    assert second.previous_hash == first.event_hash
    assert second.sequence_number == first.sequence_number + 1


def test_legacy_scan_authorization_has_safe_compatibility_view(db):
    website = Website(tenant_id="default", canonical_origin="legacy.example")
    db.add(website)
    db.flush()
    scan = Scan(
        website_id=website.id,
        requested_url="https://legacy.example/",
        state="COMPLETED",
        max_depth=2,
        max_pages=30,
    )
    db.add(scan)
    db.commit()
    public = get_assessment_authorization(scan.id, db)
    assert public["assessment_profile"] == "legacy_passive"
    assert public["authorization_type"] == "legacy_passive"
    assert public["consent_hash"] is None


def test_pause_resume_are_additive_controls(db):
    website = Website(tenant_id="default", canonical_origin="example.com")
    db.add(website)
    db.flush()
    scan = Scan(website_id=website.id, requested_url="https://example.com/", state="QUEUED")
    db.add(scan)
    db.commit()
    TaskGraphCoordinator.initialize_scan(db, scan.id)
    paused = TaskGraphCoordinator.pause_scan(db, scan.id, "tester")
    assert paused is not None and paused.state == "PAUSED"
    resumed = TaskGraphCoordinator.resume_scan(db, scan.id, "tester")
    assert resumed is not None and resumed.state == "QUEUED"
