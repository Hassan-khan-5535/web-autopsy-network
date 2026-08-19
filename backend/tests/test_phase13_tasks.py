from datetime import UTC, datetime, timedelta

from datetime import UTC, datetime, timedelta

import pytest

from app.models.scan import AgentTask, AssessmentAuthorization, Scan, Website
from app.api.routes.scans import ScanCreate, _progress_payload, create_scan
from app.services.tasks import OUTPUT_READY, ScopePolicyViolation, TaskGraphCoordinator, TaskRunner, output_event_key


class FakeDispatcher:
    def __init__(self):
        self.dispatched = []

    def dispatch(self, task_id, queue_name):
        self.dispatched.append((str(task_id), queue_name))


def make_scan(db, hostname):
    website = Website(canonical_origin=hostname)
    db.add(website)
    db.flush()
    scan = Scan(website_id=website.id, requested_url=f"https://{hostname}", state="CREATED")
    db.add(scan)
    db.commit()
    return scan


def authorize_safe_scan(db, scan, *, allowed_domains=None):
    scan.assessment_profile = "safe"
    authorization = AssessmentAuthorization(
        scan_id=scan.id,
        authorization_type="acknowledged",
        actor_id="test-user",
        target_url=scan.requested_url,
        allowed_paths=["/"],
        excluded_paths=[],
        allowed_domains=allowed_domains or [scan.requested_url.split("//", 1)[1]],
        assessment_profile="safe",
        robots_override=False,
        max_depth=1,
        max_pages=5,
        max_requests=5,
        max_concurrency=1,
        rate_limit_per_host_ms=1000,
        consent_hash="a" * 64,
        authorized_at=datetime.now(UTC),
        policy_version="assessment-v1",
        scope_json={"target_url": scan.requested_url},
    )
    db.add(authorization)
    db.commit()
    return authorization


def test_post_scan_returns_queued_without_running_pipeline(db, monkeypatch):
    dispatcher = FakeDispatcher()
    monkeypatch.setattr("app.services.tasks.get_dispatcher", lambda: dispatcher)
    response = create_scan(ScanCreate(url="https://queued.example", authorization_acknowledged=True), db)
    assert response["state"] == "QUEUED"
    scan_id = response["id"]
    tasks = db.query(AgentTask).filter(AgentTask.scan_id == scan_id).all()
    assert {task.task_key for task in tasks} == {"admission", "collection"}


def test_task_graph_is_explicit_and_idempotent(db, monkeypatch):
    dispatcher = FakeDispatcher()
    monkeypatch.setattr("app.services.tasks.get_dispatcher", lambda: dispatcher)
    scan = make_scan(db, "queue.example")
    TaskGraphCoordinator.initialize_scan(db, scan.id)
    TaskGraphCoordinator.initialize_scan(db, scan.id)
    tasks = db.query(AgentTask).filter(AgentTask.scan_id == scan.id).all()
    assert {task.task_key for task in tasks} == {"admission", "collection"}
    assert next(task for task in tasks if task.task_key == "collection").dependency_keys == ["admission"]
    assert dispatcher.dispatched


def test_multiple_scans_are_isolated_and_cancellation_propagates(db, monkeypatch):
    dispatcher = FakeDispatcher()
    monkeypatch.setattr("app.services.tasks.get_dispatcher", lambda: dispatcher)
    scans = [make_scan(db, f"target-{index}.example") for index in range(6)]
    for scan in scans:
        TaskGraphCoordinator.initialize_scan(db, scan.id)
    for scan in scans:
        task_scan_ids = {task.scan_id for task in db.query(AgentTask).filter(AgentTask.scan_id == scan.id).all()}
        assert task_scan_ids == {scan.id}
    target = scans[0]
    TaskGraphCoordinator.cancel_scan(db, target.id)
    assert target.cancel_requested is True
    assert all(task.status in {"CANCELLED", "DISPATCHED"} for task in db.query(AgentTask).filter(AgentTask.scan_id == target.id).all())


def test_stale_task_is_requeued_with_retry_budget(db, monkeypatch):
    dispatcher = FakeDispatcher()
    monkeypatch.setattr("app.services.tasks.get_dispatcher", lambda: dispatcher)
    scan = make_scan(db, "recovery.example")
    task = AgentTask(
        scan_id=scan.id,
        task_key="analysis:test",
        task_type="security",
        queue_name="analysis",
        status="RUNNING",
        attempt=1,
        max_retries=1,
        progress=40,
        dependency_keys=[],
        updated_at=datetime.now(UTC) - timedelta(minutes=10),
    )
    scan.state = "ANALYZING"
    scan.queued_at = datetime.now(UTC)
    db.add(task)
    db.commit()
    TaskGraphCoordinator.recover_stale_tasks(db)
    db.refresh(task)
    assert task.status in {"RETRYING", "DISPATCHED"}
    assert task.error_reason and "heartbeat" in task.error_reason


def test_progress_payload_reports_task_and_queue_state(db, monkeypatch):
    dispatcher = FakeDispatcher()
    monkeypatch.setattr("app.services.tasks.get_dispatcher", lambda: dispatcher)
    scan = make_scan(db, "progress.example")
    TaskGraphCoordinator.initialize_scan(db, scan.id)
    payload = _progress_payload(scan.id, db)
    assert payload["scan_id"] == str(scan.id)
    assert payload["total_tasks"] == 2
    assert payload["queue_position"] == 1
    assert payload["tasks"][0]["dependencies"] == []


def test_event_requirement_releases_only_after_same_scan_output_event(db, monkeypatch):
    dispatcher = FakeDispatcher()
    monkeypatch.setattr("app.services.tasks.get_dispatcher", lambda: dispatcher)
    scan = make_scan(db, "event-release.example")
    task = TaskGraphCoordinator._upsert_task(
        db, scan.id, "api_agent", dependencies=[], event_requirements=[output_event_key("recon")]
    )
    db.commit()

    TaskGraphCoordinator.dispatch_ready(db, scan.id)
    assert task.status == "QUEUED"

    TaskGraphCoordinator._event(db, scan.id, None, OUTPUT_READY, {"task_key": "recon"}, event_key=output_event_key("recon"))
    db.commit()
    TaskGraphCoordinator.dispatch_ready(db, scan.id)
    db.refresh(task)

    assert task.status == "DISPATCHED"
    assert dispatcher.dispatched == [(str(task.id), "analysis")]


def test_event_isolation_prevents_cross_scan_release(db, monkeypatch):
    dispatcher = FakeDispatcher()
    monkeypatch.setattr("app.services.tasks.get_dispatcher", lambda: dispatcher)
    first = make_scan(db, "first-isolated.example")
    second = make_scan(db, "second-isolated.example")
    task = TaskGraphCoordinator._upsert_task(
        db, first.id, "api_agent", dependencies=[], event_requirements=[output_event_key("recon")]
    )
    TaskGraphCoordinator._event(db, second.id, None, OUTPUT_READY, {"task_key": "recon"}, event_key=output_event_key("recon"))
    db.commit()

    TaskGraphCoordinator.dispatch_ready(db, first.id)
    db.refresh(task)

    assert task.status == "QUEUED"
    assert dispatcher.dispatched == []


def test_dispatch_budget_fails_closed_without_issuing_work(db, monkeypatch):
    dispatcher = FakeDispatcher()
    monkeypatch.setattr("app.services.tasks.get_dispatcher", lambda: dispatcher)
    scan = make_scan(db, "budget.example")
    scan.orchestration_budget = {
        "task_dispatch_limit": 0,
        "task_dispatches_used": 0,
        "per_queue_active_limit": 1,
        "task_timeout_seconds": 60,
    }
    task = TaskGraphCoordinator._upsert_task(db, scan.id, "technology", dependencies=[])
    db.commit()

    TaskGraphCoordinator.dispatch_ready(db, scan.id)
    db.refresh(task)

    assert task.status == "FAILED"
    assert task.error_reason == "Per-scan task dispatch budget exhausted."
    assert dispatcher.dispatched == []


def test_deadline_expiry_requeues_within_retry_budget(db, monkeypatch):
    dispatcher = FakeDispatcher()
    monkeypatch.setattr("app.services.tasks.get_dispatcher", lambda: dispatcher)
    scan = make_scan(db, "deadline.example")
    scan.state = "ANALYZING"
    scan.queued_at = datetime.now(UTC)
    task = AgentTask(
        scan_id=scan.id,
        task_key="analysis:deadline",
        task_type="security",
        queue_name="analysis",
        status="RUNNING",
        attempt=1,
        max_retries=1,
        dependency_keys=[],
        deadline_at=datetime.now(UTC) - timedelta(seconds=1),
        updated_at=datetime.now(UTC),
    )
    db.add(task)
    db.commit()

    TaskGraphCoordinator.recover_stale_tasks(db)
    db.refresh(task)

    assert task.status in {"RETRYING", "DISPATCHED"}
    assert task.error_reason and "deadline" in task.error_reason.lower()


def test_scope_gate_fails_closed_before_agent_action(db):
    scan = make_scan(db, "scope.example")
    authorize_safe_scan(db, scan, allowed_domains=["different.example"])

    with pytest.raises(ScopePolicyViolation, match="hostname or path"):
        TaskRunner._assert_action_authorized(scan)


def test_after_collection_includes_report_agent_after_synthesis(db):
    scan = make_scan(db, "report-agent.example")
    TaskGraphCoordinator.after_collection(db, scan.id)
    report = db.query(AgentTask).filter(AgentTask.scan_id == scan.id, AgentTask.task_key == "report").one()
    synthesis = db.query(AgentTask).filter(AgentTask.scan_id == scan.id, AgentTask.task_key == "synthesis").one()

    assert report.dependency_keys == ["synthesis"]
    assert report.event_requirements == [output_event_key("synthesis")]
    assert synthesis.dependency_keys == ["diagnosis"]


def test_failed_dependency_is_never_dispatch_ready(db, monkeypatch):
    dispatcher = FakeDispatcher()
    monkeypatch.setattr("app.services.tasks.get_dispatcher", lambda: dispatcher)
    scan = make_scan(db, "failed-release.example")
    scan.state = "ANALYZING"
    prerequisite = TaskGraphCoordinator._upsert_task(db, scan.id, "configuration", dependencies=[])
    dependent = TaskGraphCoordinator._upsert_task(db, scan.id, "vulnerability", dependencies=["configuration"])
    prerequisite.status = "FAILED"
    prerequisite.finished_at = datetime.now(UTC)
    prerequisite.error_reason = "fixture failure"
    db.commit()

    TaskGraphCoordinator.dispatch_ready(db, scan.id)
    db.refresh(dependent)

    assert dependent.status == "FAILED"
    assert dispatcher.dispatched == []


def test_failed_dependency_propagates_to_partial_failed_scan(db, monkeypatch):
    dispatcher = FakeDispatcher()
    monkeypatch.setattr("app.services.tasks.get_dispatcher", lambda: dispatcher)
    scan = make_scan(db, "dependency-failure.example")
    scan.state = "ANALYZING"
    configuration = TaskGraphCoordinator._upsert_task(db, scan.id, "configuration", dependencies=[])
    vulnerability = TaskGraphCoordinator._upsert_task(db, scan.id, "vulnerability", dependencies=["configuration"])
    evidence = TaskGraphCoordinator._upsert_task(db, scan.id, "evidence", dependencies=["vulnerability"])
    correlation = TaskGraphCoordinator._upsert_task(db, scan.id, "correlation", dependencies=["evidence"])
    configuration.status = "FAILED"
    configuration.finished_at = datetime.now(UTC)
    configuration.error_reason = "configuration fixture failure"
    db.commit()

    TaskGraphCoordinator.dispatch_ready(db, scan.id)
    for task in (vulnerability, evidence, correlation):
        db.refresh(task)
    TaskGraphCoordinator.finalize_if_complete(db, scan.id)
    db.refresh(scan)

    assert vulnerability.status == "FAILED"
    assert evidence.status == "FAILED"
    assert correlation.status == "FAILED"
    assert scan.state == "PARTIAL_FAILED"
    assert "configuration" in (vulnerability.error_reason or "")
