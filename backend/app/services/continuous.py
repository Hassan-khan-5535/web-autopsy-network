"""Extension 12 differential posture and recurring assessment services.

Scheduled execution creates ordinary bounded scans through the existing task graph.
The checker never performs target requests itself and fails closed when stored
authorization, scope, or current policy cannot be validated.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.scan import (
    ApiEndpoint,
    AssessmentAuthorization,
    HTTPObservation,
    ReconAsset,
    ReconEndpoint,
    RecurringScanSchedule,
    Scan,
    ScanRiskSummary,
    SecurityFinding,
    SecurityPostureSnapshot,
)
from app.services.admission import AdmissionError, AdmissionService
from app.services.assessment import (
    AssessmentPolicyError,
    append_audit_event,
    consent_hash,
    hostname_allowed,
    path_allowed,
    profile_policy,
)
from app.services.diff import DiffEngine, DiffValidationError

POSTURE_VERSION = "extension12-v1"
WEEKLY = timedelta(days=7)


def utc_now() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class PostureTimelineService:
    """Persist compact same-target posture snapshots after completed scans."""

    def __init__(self, db: Session):
        self.db = db

    def refresh_snapshot(self, scan_id: UUID) -> SecurityPostureSnapshot | None:
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or scan.state != "COMPLETED":
            return None
        risk = self.db.query(ScanRiskSummary).filter(ScanRiskSummary.scan_id == scan.id).first()
        prior = (
            self.db.query(SecurityPostureSnapshot)
            .filter(SecurityPostureSnapshot.website_id == scan.website_id, SecurityPostureSnapshot.scan_id != scan.id)
            .order_by(SecurityPostureSnapshot.created_at.desc(), SecurityPostureSnapshot.id.desc())
            .first()
        )
        comparison: dict[str, Any] = {"baseline": True, "prior_scan_id": None, "change_counts": {}, "difference_id": None}
        if prior:
            try:
                diff = DiffEngine(self.db).compare(prior.scan_id, scan.id, persist=True)
                comparison = {
                    "baseline": False,
                    "prior_scan_id": str(prior.scan_id),
                    "difference_id": diff.get("difference_id"),
                    "change_counts": dict(sorted(Counter(item["change"] for item in diff.get("items", [])).items())),
                    "item_count": diff.get("item_count", 0),
                }
            except DiffValidationError as exc:
                comparison = {"baseline": False, "prior_scan_id": str(prior.scan_id), "change_counts": {}, "difference_id": None, "limitation": str(exc)}
        posture = {
            "asset_count": self.db.query(ReconAsset).filter(ReconAsset.scan_id == scan.id).count(),
            "endpoint_count": self.db.query(ReconEndpoint).filter(ReconEndpoint.scan_id == scan.id).count() + self.db.query(ApiEndpoint).filter(ApiEndpoint.scan_id == scan.id).count(),
            "header_observation_count": self.db.query(HTTPObservation).filter(HTTPObservation.scan_id == scan.id, HTTPObservation.observation_type == "header").count(),
            "technology_count": len(scan.technologies),
            "security_finding_count": self.db.query(SecurityFinding).filter(SecurityFinding.scan_id == scan.id).count(),
            "vulnerability_count": self._finding_count(scan.id, ("vulnerability", "cve")),
            "configuration_finding_count": self._finding_count(scan.id, ("configuration", "config")),
            "secret_finding_count": self._finding_count(scan.id, ("secret",)),
            "severity_counts": dict(sorted(Counter((item.severity or "info").lower() for item in scan.security_findings).items())),
        }
        values = {
            "website_id": scan.website_id,
            "posture_version": POSTURE_VERSION,
            "overall_risk_score": risk.overall_score if risk else 0.0,
            "risk_band": risk.risk_band if risk else "info",
            "posture_summary": posture,
            "comparison_summary": comparison,
        }
        snapshot = self.db.query(SecurityPostureSnapshot).filter(SecurityPostureSnapshot.scan_id == scan.id).first()
        if snapshot:
            for key, value in values.items():
                setattr(snapshot, key, value)
        else:
            snapshot = SecurityPostureSnapshot(scan_id=scan.id, **values)
            self.db.add(snapshot)
        self.db.commit()
        self.db.refresh(snapshot)
        return snapshot

    def timeline(self, website_id: UUID) -> dict[str, Any]:
        snapshots = self.db.query(SecurityPostureSnapshot).filter(SecurityPostureSnapshot.website_id == website_id).order_by(SecurityPostureSnapshot.created_at, SecurityPostureSnapshot.id).all()
        return {
            "website_id": str(website_id),
            "posture_version": POSTURE_VERSION,
            "snapshots": [
                {
                    "scan_id": str(item.scan_id), "overall_risk_score": item.overall_risk_score,
                    "risk_band": item.risk_band, "posture_summary": item.posture_summary,
                    "comparison_summary": item.comparison_summary, "created_at": as_utc(item.created_at).isoformat(),
                }
                for item in snapshots
            ],
            "limitation": "A missing observation in a later scan is not evidence that an asset or finding is resolved.",
        }

    def _finding_count(self, scan_id: UUID, tokens: tuple[str, ...]) -> int:
        return sum(1 for item in self.db.query(SecurityFinding).filter(SecurityFinding.scan_id == scan_id).all() if any(token in (item.category or "").lower() for token in tokens))


class RecurringScheduleError(ValueError):
    """Raised when a recurring schedule cannot safely create a scan."""


class RecurringScheduleService:
    """Persist weekly schedules and submit due scans only after a fresh policy gate."""

    def __init__(self, db: Session):
        self.db = db

    def create_weekly(self, source_scan_id: UUID, actor_id: str) -> RecurringScanSchedule:
        scan = self.db.query(Scan).filter(Scan.id == source_scan_id).first()
        if not scan or not scan.assessment_authorization:
            raise RecurringScheduleError("A persisted scan authorization is required before scheduling recurring assessments.")
        authorization = scan.assessment_authorization
        self._validate_authorization(authorization)
        existing = self.db.query(RecurringScanSchedule).filter(RecurringScanSchedule.source_scan_id == scan.id, RecurringScanSchedule.enabled.is_(True)).first()
        if existing:
            return existing
        schedule = RecurringScanSchedule(
            website_id=scan.website_id,
            source_scan_id=scan.id,
            source_authorization_id=authorization.id,
            target_url=authorization.target_url,
            cadence="weekly",
            enabled=True,
            next_run_at=utc_now() + WEEKLY,
            authorization_snapshot=self._authorization_snapshot(authorization),
            created_by=actor_id or "system",
        )
        self.db.add(schedule)
        self.db.flush()
        append_audit_event(self.db, scan_id=scan.id, authorization_id=authorization.id, event_type="RECURRING_SCHEDULE_CREATED", actor_id=actor_id or "system", payload={"schedule_id": str(schedule.id), "cadence": schedule.cadence, "next_run_at": schedule.next_run_at.isoformat()})
        self.db.commit()
        self.db.refresh(schedule)
        return schedule

    def run_due(self, now: datetime | None = None) -> dict[str, Any]:
        now = now or utc_now()
        schedules = self.db.query(RecurringScanSchedule).filter(RecurringScanSchedule.enabled.is_(True), RecurringScanSchedule.next_run_at <= now).order_by(RecurringScanSchedule.next_run_at, RecurringScanSchedule.id).all()
        result: dict[str, Any] = {"checked": len(schedules), "created_scan_ids": [], "blocked": []}
        for schedule in schedules:
            try:
                scan = self._create_due_scan(schedule, now)
                result["created_scan_ids"].append(str(scan.id))
            except RecurringScheduleError as exc:
                schedule.enabled = False
                schedule.blocked_at = now
                schedule.last_block_reason = str(exc)
                self.db.commit()
                result["blocked"].append({"schedule_id": str(schedule.id), "reason": str(exc)})
        return result

    def _create_due_scan(self, schedule: RecurringScanSchedule, now: datetime) -> Scan:
        authorization = self.db.query(AssessmentAuthorization).filter(AssessmentAuthorization.id == schedule.source_authorization_id).first()
        if not authorization:
            raise RecurringScheduleError("Stored authorization is unavailable.")
        self._validate_authorization(authorization)
        snapshot = self._authorization_snapshot(authorization)
        if snapshot != schedule.authorization_snapshot:
            raise RecurringScheduleError("Stored authorization or scope has changed; renew the recurring schedule explicitly.")
        try:
            policy = profile_policy(authorization.assessment_profile, max_depth=authorization.max_depth, max_requests=authorization.max_requests, max_concurrency=authorization.max_concurrency, rate_limit_per_host_ms=authorization.rate_limit_per_host_ms)
            canonical_url = AdmissionService.normalize_url(authorization.target_url)
        except (AdmissionError, AssessmentPolicyError) as exc:
            raise RecurringScheduleError(f"Stored authorization no longer meets current policy: {exc}") from exc
        parsed = urlsplit(canonical_url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname_allowed(hostname, authorization.allowed_domains) or not path_allowed(canonical_url, authorization.allowed_paths, authorization.excluded_paths):
            raise RecurringScheduleError("Target is outside the currently stored authorized domain or path scope.")
        scan = Scan(
            website_id=schedule.website_id, state="QUEUED", requested_url=canonical_url,
            max_depth=min(policy["max_depth"], authorization.max_depth),
            max_pages=min(policy["max_requests"], authorization.max_pages),
            max_concurrency=min(policy["max_concurrency"], authorization.max_concurrency),
            request_delay_ms=max(policy["rate_limit_per_host_ms"], authorization.rate_limit_per_host_ms),
            same_domain_mode="hostname", assessment_profile=authorization.assessment_profile,
            max_requests=min(policy["max_requests"], authorization.max_requests), recon_mode="passive_only",
            recurring_schedule_id=schedule.id,
        )
        self.db.add(scan)
        self.db.flush()
        copied = AssessmentAuthorization(
            scan_id=scan.id, authorization_type=authorization.authorization_type, actor_id=authorization.actor_id,
            target_url=authorization.target_url, allowed_paths=authorization.allowed_paths, excluded_paths=authorization.excluded_paths,
            allowed_domains=authorization.allowed_domains, assessment_profile=authorization.assessment_profile,
            robots_override=authorization.robots_override, max_depth=scan.max_depth, max_pages=scan.max_pages,
            max_requests=scan.max_requests, max_concurrency=scan.max_concurrency, rate_limit_per_host_ms=scan.request_delay_ms,
            test_account_ref=authorization.test_account_ref, auth_secret_encrypted=authorization.auth_secret_encrypted,
            auth_secret_fingerprint=authorization.auth_secret_fingerprint,
            consent_hash=consent_hash({**snapshot, "recurring_schedule_id": str(schedule.id), "scheduled_at": now.isoformat()}),
            authorized_at=authorization.authorized_at, expires_at=authorization.expires_at,
            policy_version=authorization.policy_version, scope_json={**authorization.scope_json, "recurring_schedule_id": str(schedule.id)},
        )
        self.db.add(copied)
        self.db.flush()
        append_audit_event(self.db, scan_id=scan.id, authorization_id=copied.id, event_type="RECURRING_SCAN_AUTHORIZATION_RECHECKED", actor_id="schedule-checker", payload={"schedule_id": str(schedule.id), "source_authorization_id": str(authorization.id), "scope": snapshot})
        schedule.last_run_at = now
        schedule.last_scan_id = scan.id
        schedule.next_run_at = now + WEEKLY
        schedule.blocked_at = None
        schedule.last_block_reason = None
        self.db.commit()
        from app.services.tasks import TaskGraphCoordinator
        TaskGraphCoordinator.initialize_scan(self.db, scan.id)
        return scan

    @staticmethod
    def _authorization_snapshot(authorization: AssessmentAuthorization) -> dict[str, Any]:
        return {"target_url": authorization.target_url, "allowed_domains": authorization.allowed_domains or [], "allowed_paths": authorization.allowed_paths or [], "excluded_paths": authorization.excluded_paths or [], "assessment_profile": authorization.assessment_profile, "max_depth": authorization.max_depth, "max_pages": authorization.max_pages, "max_requests": authorization.max_requests, "max_concurrency": authorization.max_concurrency, "rate_limit_per_host_ms": authorization.rate_limit_per_host_ms, "robots_override": authorization.robots_override, "policy_version": authorization.policy_version}

    @staticmethod
    def _validate_authorization(authorization: AssessmentAuthorization) -> None:
        now = utc_now()
        expires_at = as_utc(authorization.expires_at)
        if expires_at and expires_at <= now:
            raise RecurringScheduleError("Stored authorization has expired.")
        if authorization.assessment_profile != "safe":
            raise RecurringScheduleError("Recurring scans are limited to the stored safe assessment profile.")
        if not authorization.target_url or not authorization.allowed_domains:
            raise RecurringScheduleError("Stored authorization is missing the target or allowed-domain scope.")
