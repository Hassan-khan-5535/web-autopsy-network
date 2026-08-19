from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from app.models.scan import (
    ApiEndpoint,
    AssessmentAuthorization,
    HTTPObservation,
    ReconAsset,
    ReconEndpoint,
    Scan,
    ScanRiskSummary,
    SecurityFinding,
    Website,
)
from app.services.continuous import PostureTimelineService, RecurringScheduleService, as_utc
from app.services.diff import DiffEngine


def _scan(db: Session, website: Website, url: str) -> Scan:
    item = Scan(
        id=uuid4(), website_id=website.id, state="COMPLETED", requested_url=url,
        max_depth=1, max_pages=10, max_concurrency=1, request_delay_ms=1000,
        same_domain_mode="hostname", assessment_profile="safe", max_requests=10,
        recon_mode="passive_only",
    )
    db.add(item)
    db.flush()
    return item


def _finding(scan: Scan, category: str, subject: str, severity: str, rule_id: str) -> SecurityFinding:
    return SecurityFinding(
        scan_id=scan.id, category=category, subject=subject, statement=f"Stored {subject} finding.",
        classification="OBSERVED", confidence=90.0, confidence_band="high", severity=severity,
        rule_id=rule_id, rule_version="test", evidence=[{"id": f"{rule_id}-evidence"}], limitations="Stored evidence only.",
    )


def _authorization(db: Session, scan: Scan, *, expires_at: datetime | None) -> AssessmentAuthorization:
    item = AssessmentAuthorization(
        scan_id=scan.id, authorization_type="acknowledged", actor_id="test-user",
        target_url=scan.requested_url, allowed_domains=["www.w3schools.com"],
        allowed_paths=[], excluded_paths=[], assessment_profile="safe", robots_override=False,
        max_depth=1, max_pages=10, max_requests=10, max_concurrency=1,
        rate_limit_per_host_ms=1000, test_account_ref=None, auth_secret_encrypted=None,
        auth_secret_fingerprint=None, consent_hash="a" * 64, authorized_at=datetime.now(UTC),
        expires_at=expires_at, policy_version="assessment-v1", scope_json={"target_url": scan.requested_url},
    )
    db.add(item)
    db.flush()
    return item


def test_extension12_diff_detects_posture_changes_and_timeline(db: Session):
    website = Website(id=uuid4(), tenant_id="default", canonical_origin="www.w3schools.com")
    db.add(website)
    db.flush()
    prior = _scan(db, website, "https://www.w3schools.com/")
    current = _scan(db, website, "https://www.w3schools.com/")
    db.add_all([
        ReconAsset(scan_id=prior.id, asset_type="host", value="www.w3schools.com", hostname="www.w3schools.com", source="test", discovery_mode="passive_only", classification="OBSERVED", scope_status="in_scope", confidence=1.0, attributes={}, evidence=[], dedupe_key="prior-host"),
        ReconAsset(scan_id=current.id, asset_type="host", value="www.w3schools.com", hostname="www.w3schools.com", source="test", discovery_mode="passive_only", classification="OBSERVED", scope_status="in_scope", confidence=1.0, attributes={}, evidence=[], dedupe_key="current-host"),
        ReconAsset(scan_id=current.id, asset_type="service", value="assets.w3schools.com", hostname="assets.w3schools.com", source="test", discovery_mode="passive_only", classification="OBSERVED", scope_status="in_scope", confidence=1.0, attributes={}, evidence=[], dedupe_key="new-asset"),
        ReconEndpoint(scan_id=current.id, endpoint_kind="api", url_or_path="https://www.w3schools.com/api/example", http_method="GET", source="test", discovery_mode="passive_only", classification="OBSERVED", confidence=1.0, scope_status="in_scope", status_code=200, content_type="application/json", page_id=None, attributes={}, evidence=[], dedupe_key="new-endpoint"),
        ApiEndpoint(scan_id=current.id, url_or_path="https://www.w3schools.com/api/example", http_method="GET", content_type="application/json", classification="OBSERVED", confidence=1.0, discovered_from_source="test"),
        HTTPObservation(scan_id=prior.id, page_id=None, http_response_id=None, observation_type="header", subject="content-security-policy", source="test", classification="OBSERVED", confidence=1.0, value={"present": False}, redacted=True, truncated=False, dedupe_key="prior-csp"),
        HTTPObservation(scan_id=current.id, page_id=None, http_response_id=None, observation_type="header", subject="content-security-policy", source="test", classification="OBSERVED", confidence=1.0, value={"present": True}, redacted=True, truncated=False, dedupe_key="current-csp"),
        _finding(prior, "configuration", "TLS setting", "medium", "CFG-1"),
        _finding(current, "configuration", "TLS setting", "high", "CFG-1"),
        _finding(current, "vulnerability", "Outdated component", "high", "VULN-1"),
        _finding(current, "secrets", "Public token marker", "high", "SECRET-1"),
        ScanRiskSummary(scan_id=prior.id, website_id=website.id, deterministic_version="test", overall_score=30.0, risk_band="low", eligible_assessment_count=1, assessment_count=1, summary={}),
        ScanRiskSummary(scan_id=current.id, website_id=website.id, deterministic_version="test", overall_score=80.0, risk_band="high", eligible_assessment_count=3, assessment_count=3, summary={}),
    ])
    db.commit()

    diff = DiffEngine(db).compare(prior.id, current.id, persist=True)
    changes = {item["change"] for item in diff["items"]}

    assert {"asset_added", "endpoint_added", "security_header_changed", "vulnerability_added", "newly_exposed_secret", "severity_changed", "risk_score_changed"}.issubset(changes)
    PostureTimelineService(db).refresh_snapshot(prior.id)
    PostureTimelineService(db).refresh_snapshot(current.id)
    timeline = PostureTimelineService(db).timeline(website.id)
    assert len(timeline["snapshots"]) == 2
    assert timeline["snapshots"][-1]["comparison_summary"]["baseline"] is False


def test_extension12_weekly_schedule_rechecks_authorization_and_blocks_expiry(db: Session, monkeypatch):
    website = Website(id=uuid4(), tenant_id="default", canonical_origin="www.w3schools.com")
    db.add(website)
    db.flush()
    source = _scan(db, website, "https://www.w3schools.com/")
    authorization = _authorization(db, source, expires_at=datetime.now(UTC) + timedelta(days=30))
    db.commit()
    service = RecurringScheduleService(db)
    schedule = service.create_weekly(source.id, "test-user")
    schedule.next_run_at = datetime.now(UTC) - timedelta(seconds=1)
    db.commit()

    from app.services.tasks import TaskGraphCoordinator
    monkeypatch.setattr(TaskGraphCoordinator, "initialize_scan", lambda _db, _scan_id: None)
    result = service.run_due()

    assert len(result["created_scan_ids"]) == 1
    created = db.query(Scan).filter(Scan.id == UUID(result["created_scan_ids"][0])).one()
    assert created.recurring_schedule_id == schedule.id
    assert created.assessment_authorization.target_url == "https://www.w3schools.com/"
    assert as_utc(schedule.next_run_at) > datetime.now(UTC)

    authorization.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    schedule.enabled = True
    schedule.next_run_at = datetime.now(UTC) - timedelta(seconds=1)
    db.commit()
    blocked = service.run_due()
    assert blocked["created_scan_ids"] == []
    assert blocked["blocked"][0]["reason"] == "Stored authorization has expired."
    assert schedule.enabled is False
