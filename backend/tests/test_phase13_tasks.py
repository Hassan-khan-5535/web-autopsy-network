from datetime import UTC, datetime, timedelta

from app.models.scan import AgentTask, Scan, Website
from app.api.routes.scans import ScanCreate, _progress_payload, create_scan
from app.services.tasks import TaskGraphCoordinator


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
