from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.scan import AgentEvent, AgentTask, Scan, Website
from app.services.accessibility import AccessibilityEngine
from app.services.assessment import append_audit_event
from app.services.admission import AdmissionService
from app.services.ai_synthesis import AISynthesisEngine
from app.services.api_intelligence import ApiIntelligenceAgent
from app.services.browser_client import BrowserWorkerClient
from app.services.content import ContentEngine
from app.services.crawler import CrawlerService
from app.services.diagnosis import CauseOfDeathEngine, CauseOfDeathNarrative
from app.services.network_intelligence import NetworkIntelligenceAgent
from app.services.performance import PerformanceEngine
from app.services.http_agent import HTTPAgent
from app.services.recon import ReconAgent
from app.services.queue import get_dispatcher
from app.services.security import SecurityAnalysisService
from app.services.structure import StructureAgent
from app.services.technology import TechnologyDetectionService

TERMINAL_TASK_STATES = {"SUCCEEDED", "FAILED", "CANCELLED"}
ACTIVE_SCAN_STATES = {"QUEUED", "VALIDATING", "COLLECTING", "ANALYZING", "SYNTHESIZING", "CANCELLING"}
PAUSABLE_SCAN_STATES = {"QUEUED", "COLLECTING", "ANALYZING", "SYNTHESIZING"}

TASK_DEFINITIONS = {
    "admission": {"queue": "crawl", "max_retries": 0, "dependencies": []},
    "collection": {"queue": "crawl", "max_retries": 3, "dependencies": ["admission"]},
    "technology": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection"]},
    "structure": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection"]},
    "api_intelligence": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection"]},
    "network_intelligence": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection"]},
    "http_agent": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection"]},
    "recon": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection"]},
    "security": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection"]},
    "content": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection"]},
    "performance": {"queue": "analysis", "max_retries": 2, "dependencies": []},
    "accessibility": {"queue": "analysis", "max_retries": 2, "dependencies": []},
    "diagnosis": {"queue": "analysis", "max_retries": 1, "dependencies": ["technology", "structure", "api_intelligence", "network_intelligence", "security", "performance", "accessibility", "content"]},
    "synthesis": {"queue": "ai", "max_retries": 1, "dependencies": ["diagnosis"]},
}


def utc_now() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def task_key(task_type: str, suffix: str | None = None) -> str:
    return f"{task_type}:{suffix}" if suffix else task_type


def check_scan_wall_clock_timeout(scan: Scan, timeout_seconds: int = 600) -> bool:
    """Enforce scan wall-clock expiry. If scan execution time exceeds threshold, mark as PARTIAL_FAILED."""
    if scan.state in {"COMPLETED", "FAILED", "CANCELLED", "PARTIAL_FAILED"}:
        return False

    created_at = as_utc(scan.created_at)
    if created_at is None:
        return False

    elapsed = (utc_now() - created_at).total_seconds()
    if elapsed > timeout_seconds:
        scan.state = "PARTIAL_FAILED"
        scan.error_reason = f"Scan wall-clock timeout exceeded ({int(elapsed)}s > {timeout_seconds}s)"
        return True
    return False



class TaskGraphCoordinator:
    """Persists task dependencies and schedules only dependency-ready work."""

    @classmethod
    def initialize_scan(cls, db: Session, scan_id: UUID) -> None:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        scan.state = "QUEUED"
        scan.pause_requested = False
        scan.queued_at = scan.queued_at or utc_now()
        cls._upsert_task(db, scan_id, "admission")
        cls._upsert_task(db, scan_id, "collection", dependencies=["admission"])
        db.commit()
        cls.release_queued_scans(db)

    @classmethod
    def _upsert_task(cls, db: Session, scan_id: UUID, task_type: str, *, key: str | None = None, dependencies: list[str] | None = None) -> AgentTask:
        definition = TASK_DEFINITIONS[task_type]
        task_key_value = key or task_key(task_type)
        existing = db.query(AgentTask).filter(AgentTask.scan_id == scan_id, AgentTask.task_key == task_key_value).first()
        if existing:
            return existing
        task = AgentTask(
            scan_id=scan_id,
            task_key=task_key_value,
            task_type=task_type,
            queue_name=definition["queue"],
            status="QUEUED",
            max_retries=definition["max_retries"],
            dependency_keys=dependencies if dependencies is not None else definition["dependencies"],
            available_at=utc_now(),
        )
        db.add(task)
        db.flush()
        cls._event(db, scan_id, task, "TASK_QUEUED", {"task_type": task_type, "dependencies": task.dependency_keys})
        return task

    @classmethod
    def after_collection(cls, db: Session, scan_id: UUID) -> None:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        page_tasks: list[str] = []
        for page in sorted(scan.pages, key=lambda item: (item.depth, item.canonical_url)):
            page_key = task_key("browser_analysis", str(page.id))
            task = db.query(AgentTask).filter(AgentTask.scan_id == scan_id, AgentTask.task_key == page_key).first()
            if not task:
                task = AgentTask(
                    scan_id=scan_id,
                    task_key=page_key,
                    task_type="browser_analysis",
                    queue_name="browser",
                    status="QUEUED",
                    max_retries=1,
                    dependency_keys=["collection"],
                    available_at=utc_now(),
                )
                db.add(task)
                db.flush()
                cls._event(db, scan_id, task, "TASK_QUEUED", {"task_type": "browser_analysis", "page_id": str(page.id)})
            page_tasks.append(page_key)
        analysis_types = ["technology", "structure", "api_intelligence", "network_intelligence", "http_agent", "security", "content"]
        if scan.recon_mode in {"passive_only", "active_safe"}:
            analysis_types.append("recon")
        for task_type in analysis_types:
            dependencies = ["collection"]
            if task_type == "security":
                dependencies = ["collection", "http_agent"]
            cls._upsert_task(db, scan_id, task_type, dependencies=dependencies)
        cls._upsert_task(db, scan_id, "performance", dependencies=page_tasks or ["collection"])
        cls._upsert_task(db, scan_id, "accessibility", dependencies=page_tasks or ["collection"])
        analysis_keys = ["technology", "structure", "api_intelligence", "network_intelligence", "http_agent", "security", "performance", "accessibility", "content"]
        if scan.recon_mode in {"passive_only", "active_safe"}:
            analysis_keys.append("recon")
        cls._upsert_task(db, scan_id, "diagnosis", dependencies=analysis_keys)
        cls._upsert_task(db, scan_id, "synthesis", dependencies=["diagnosis"])
        scan.state = "ANALYZING"
        db.commit()

    @classmethod
    def dispatch_ready(cls, db: Session, scan_id: UUID) -> None:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or scan.cancel_requested or scan.pause_requested or scan.state == "PAUSED":
            return
        now = utc_now()
        tasks = db.query(AgentTask).filter(AgentTask.scan_id == scan_id, AgentTask.status.in_(["QUEUED", "RETRYING"])).order_by(AgentTask.created_at, AgentTask.task_key).all()
        to_dispatch: list[AgentTask] = []
        task_map = {task.task_key: task for task in db.query(AgentTask).filter(AgentTask.scan_id == scan_id).all()}
        for task in tasks:
            available_at = as_utc(task.available_at)
            if available_at and available_at > now:
                continue
            deps = [task_map.get(key) for key in (task.dependency_keys or [])]
            if any(dep is None or dep.status not in TERMINAL_TASK_STATES for dep in deps):
                continue
            task.status = "DISPATCHED"
            task.updated_at = now
            cls._event(db, scan_id, task, "TASK_DISPATCHED", {"queue": task.queue_name})
            to_dispatch.append(task)
        db.commit()
        dispatcher = get_dispatcher()
        for task in to_dispatch:
            dispatcher.dispatch(task.id, task.queue_name)

    @classmethod
    def after_terminal(cls, db: Session, scan_id: UUID) -> None:
        tasks = db.query(AgentTask).filter(AgentTask.scan_id == scan_id).all()
        collection = next((task for task in tasks if task.task_key == "collection"), None)
        if collection and collection.status in TERMINAL_TASK_STATES:
            cls.after_collection(db, scan_id)
        cls.dispatch_ready(db, scan_id)
        cls.finalize_if_complete(db, scan_id)

    @classmethod
    def finalize_if_complete(cls, db: Session, scan_id: UUID) -> None:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        tasks = db.query(AgentTask).filter(AgentTask.scan_id == scan_id).all()
        if not tasks or any(task.status not in TERMINAL_TASK_STATES for task in tasks):
            return
        if scan.cancel_requested:
            scan.state = "CANCELLED"
            scan.error_reason = "Scan cancelled by user. Pending work was not started."
        elif any(task.status == "FAILED" for task in tasks):
            scan.state = "PARTIAL_FAILED"
            scan.error_reason = "One or more distributed tasks failed; completed findings remain available."
        else:
            scan.state = "COMPLETED"
            scan.error_reason = None
        scan.finished_at = utc_now()
        cls._event(db, scan_id, None, "SCAN_TERMINAL", {"state": scan.state})
        db.commit()
        cls.release_queued_scans(db)

    @classmethod
    def pause_scan(cls, db: Session, scan_id: UUID, actor_id: str) -> Scan | None:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        if scan.state not in PAUSABLE_SCAN_STATES or scan.cancel_requested:
            return scan
        scan.pause_requested = True
        scan.state = "PAUSED"
        for task in db.query(AgentTask).filter(
            AgentTask.scan_id == scan_id,
            AgentTask.status.in_(["QUEUED", "DISPATCHED", "RETRYING"]),
        ).all():
            task.status = "PAUSED"
            task.updated_at = utc_now()
            cls._event(db, scan_id, task, "TASK_PAUSED", {})
        append_audit_event(
            db,
            scan_id=scan_id,
            event_type="SCAN_PAUSED",
            actor_id=actor_id,
            payload={"state": scan.state},
        )
        db.commit()
        return scan

    @classmethod
    def resume_scan(cls, db: Session, scan_id: UUID, actor_id: str) -> Scan | None:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        if scan.state != "PAUSED":
            return scan
        scan.pause_requested = False
        scan.state = "QUEUED" if not scan.pages else "ANALYZING"
        for task in db.query(AgentTask).filter(
            AgentTask.scan_id == scan_id,
            AgentTask.status == "PAUSED",
        ).all():
            task.status = "QUEUED"
            task.available_at = utc_now()
            task.updated_at = utc_now()
            cls._event(db, scan_id, task, "TASK_RESUMED", {})
        append_audit_event(
            db,
            scan_id=scan_id,
            event_type="SCAN_RESUMED",
            actor_id=actor_id,
            payload={"state": scan.state},
        )
        db.commit()
        cls.release_queued_scans(db)
        return scan

    @classmethod
    def cancel_scan(cls, db: Session, scan_id: UUID) -> Scan | None:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        scan.cancel_requested = True
        scan.pause_requested = False
        running_tasks = db.query(AgentTask).filter(AgentTask.scan_id == scan_id, AgentTask.status == "RUNNING").count()
        if running_tasks:
            scan.state = "CANCELLING"
        else:
            scan.state = "CANCELLED"
            scan.finished_at = utc_now()
        for task in db.query(AgentTask).filter(AgentTask.scan_id == scan_id, AgentTask.status.in_(["QUEUED", "DISPATCHED", "RETRYING", "PAUSED"])).all():
            task.status = "CANCELLED"
            task.finished_at = utc_now()
            cls._event(db, scan_id, task, "TASK_CANCELLED", {})
        cls._event(db, scan_id, None, "SCAN_CANCEL_REQUESTED", {})
        append_audit_event(
            db,
            scan_id=scan_id,
            event_type="SCAN_CANCEL_REQUESTED",
            actor_id="system",
            payload={"state": scan.state},
        )
        db.commit()
        return scan

    @classmethod
    def release_queued_scans(cls, db: Session) -> None:
        settings = get_settings()
        active_scan_ids = {
            row[0] for row in db.query(AgentTask.scan_id)
            .filter(AgentTask.status.in_(["DISPATCHED", "RUNNING", "RETRYING"]))
            .distinct()
            .all()
        }
        slots = max(0, settings.max_concurrent_scans - len(active_scan_ids))
        if slots <= 0:
            return
        queued = db.query(Scan).filter(Scan.state == "QUEUED", Scan.cancel_requested.is_(False)).order_by(Scan.queued_at, Scan.created_at, Scan.id).limit(slots).all()
        for scan in queued:
            cls.dispatch_ready(db, scan.id)

    @classmethod
    def recover_stale_tasks(cls, db: Session) -> None:
        settings = get_settings()
        now = utc_now()
        stale_after = max(60, settings.task_heartbeat_seconds * 4)
        stale_cutoff = now - timedelta(seconds=stale_after)
        stale = db.query(AgentTask).filter(
            AgentTask.status.in_(["DISPATCHED", "RUNNING"]),
            AgentTask.updated_at < stale_cutoff,
        ).all()
        affected: set[UUID] = set()
        for task in stale:
            affected.add(task.scan_id)
            if task.attempt <= task.max_retries:
                task.status = "RETRYING"
                task.available_at = now
                task.error_reason = "Worker heartbeat expired; task returned to the retry queue."
                cls._event(db, task.scan_id, task, "TASK_ORPHAN_RECOVERED", {"attempt": task.attempt})
            else:
                task.status = "FAILED"
                task.finished_at = now
                task.error_reason = "Worker heartbeat expired after retry budget was exhausted."
                cls._event(db, task.scan_id, task, "TASK_ORPHAN_FAILED", {"attempt": task.attempt})
        for scan in db.query(Scan).filter(Scan.state.in_(ACTIVE_SCAN_STATES), Scan.queued_at < now - timedelta(seconds=settings.scan_timeout_seconds)).all():
            affected.add(scan.id)
            scan.cancel_requested = True
            scan.state = "PARTIAL_FAILED"
            scan.error_reason = "Scan wall-clock timeout exceeded; remaining tasks were stopped."
            scan.finished_at = now
            for task in db.query(AgentTask).filter(AgentTask.scan_id == scan.id, AgentTask.status.notin_(TERMINAL_TASK_STATES)).all():
                task.status = "FAILED"
                task.finished_at = now
                task.error_reason = scan.error_reason
        if stale or affected:
            db.commit()
            for scan_id in affected:
                cls.dispatch_ready(db, scan_id)
                cls.finalize_if_complete(db, scan_id)

    @staticmethod
    def _event(db: Session, scan_id: UUID, task: AgentTask | None, event_type: str, payload: dict[str, Any]) -> None:
        db.add(AgentEvent(scan_id=scan_id, task_id=task.id if task else None, event_type=event_type, payload=payload))


class TaskRunner:
    """Execute one persisted task with fresh DB scope and idempotent terminal handling."""

    @classmethod
    def run(cls, task_id: UUID) -> None:
        db = SessionLocal()
        try:
            task = db.query(AgentTask).filter(AgentTask.id == task_id).first()
            if not task or task.status == "SUCCEEDED" or task.status == "CANCELLED":
                return
            scan = db.query(Scan).filter(Scan.id == task.scan_id).first()
            if not scan:
                return
            if scan.cancel_requested:
                task.status = "CANCELLED"
                task.finished_at = utc_now()
                db.commit()
                TaskGraphCoordinator.after_terminal(db, task.scan_id)
                return
            if scan.pause_requested or scan.state == "PAUSED":
                task.status = "PAUSED"
                task.updated_at = utc_now()
                TaskGraphCoordinator._event(db, task.scan_id, task, "TASK_PAUSED", {})
                db.commit()
                return
            task.status = "RUNNING"
            task.attempt += 1
            task.started_at = task.started_at or utc_now()
            task.heartbeat_at = utc_now()
            task.updated_at = utc_now()
            db.commit()
            TaskGraphCoordinator._event(db, task.scan_id, task, "TASK_STARTED", {"attempt": task.attempt})
            db.commit()
            result = cls._execute(db, task, scan)
            db.refresh(scan)
            task.status = "CANCELLED" if scan.cancel_requested else "SUCCEEDED"
            task.progress = 100
            task.result = result or {}
            task.finished_at = utc_now()
            task.heartbeat_at = utc_now()
            task.updated_at = utc_now()
            TaskGraphCoordinator._event(db, task.scan_id, task, "TASK_CANCELLED" if task.status == "CANCELLED" else "TASK_SUCCEEDED", result or {})
            db.commit()
            TaskGraphCoordinator.after_terminal(db, task.scan_id)
        except Exception as exc:
            db.rollback()
            task = db.query(AgentTask).filter(AgentTask.id == task_id).first()
            if not task:
                return
            task.error_reason = str(exc)
            task.heartbeat_at = utc_now()
            if task.attempt <= task.max_retries:
                task.status = "RETRYING"
                task.available_at = utc_now() + timedelta(seconds=get_settings().task_retry_backoff_seconds * max(1, task.attempt))
                TaskGraphCoordinator._event(db, task.scan_id, task, "TASK_RETRYING", {"attempt": task.attempt, "error": str(exc)})
                db.commit()
                time.sleep(get_settings().task_retry_backoff_seconds * max(1, task.attempt))
                TaskGraphCoordinator.dispatch_ready(db, task.scan_id)
            else:
                task.status = "FAILED"
                task.finished_at = utc_now()
                TaskGraphCoordinator._event(db, task.scan_id, task, "TASK_FAILED", {"attempt": task.attempt, "error": str(exc)})
                db.commit()
                TaskGraphCoordinator.after_terminal(db, task.scan_id)
        finally:
            db.close()

    @classmethod
    def _execute(cls, db: Session, task: AgentTask, scan: Scan) -> dict[str, Any]:
        if scan.cancel_requested:
            raise RuntimeError("Scan cancellation requested")
        if task.task_type == "admission":
            canonical_url, _ = AdmissionService.validate_and_resolve(scan.requested_url)
            scan.requested_url = canonical_url
            scan.state = "COLLECTING"
            db.commit()
            return {"canonical_url": canonical_url}
        if task.task_type == "collection":
            scan.state = "COLLECTING"
            db.commit()
            CrawlerService(db, scan, scan.requested_url).crawl()
            db.refresh(scan)
            if scan.state == "FAILED":
                raise RuntimeError(scan.error_reason or "Collection failed")
            return {"pages": len(scan.pages)}
        if task.task_type == "browser_analysis":
            page_id = UUID(task.task_key.split(":", 1)[1])
            page = next((page for page in scan.pages if page.id == page_id), None)
            if page is None:
                return {"page_id": str(page_id), "status": "missing"}
            success = BrowserWorkerClient(db).analyze_page(scan.id, page.id, page.canonical_url)
            return {"page_id": str(page.id), "status": "succeeded" if success else "degraded"}
        if task.task_type == "technology":
            return {"findings": len(TechnologyDetectionService(db, scan.id).detect())}
        if task.task_type == "structure":
            return {"findings": len(StructureAgent(db, scan.id).analyze().get("site_tree", []))}
        if task.task_type == "api_intelligence":
            return {"findings": len(ApiIntelligenceAgent(db, scan.id).analyze())}
        if task.task_type == "network_intelligence":
            return {"findings": len(NetworkIntelligenceAgent(db, scan.id).analyze())}
        if task.task_type == "http_agent":
            return {"observations": len(HTTPAgent(db, scan.id).analyze())}
        if task.task_type == "recon":
            return ReconAgent(db, scan.id).run()
        if task.task_type == "security":
            return {"findings": len(SecurityAnalysisService(db, scan.id).analyze())}
        if task.task_type == "performance":
            return {"findings": len(PerformanceEngine(db, scan.id).analyze())}
        if task.task_type == "accessibility":
            AccessibilityEngine(db, scan.id).analyze()
            return {"status": "completed"}
        if task.task_type == "content":
            ContentEngine(db, scan.id).analyze()
            return {"status": "completed"}
        if task.task_type == "diagnosis":
            diagnosis = CauseOfDeathEngine(db, scan.id).compute(allow_in_progress=True)
            narrative = CauseOfDeathNarrative(db).generate(diagnosis)
            CauseOfDeathEngine(db, scan.id).persist(narrative=narrative, allow_in_progress=True)
            return {"primary_issue": diagnosis["primary_issue"]["subject"], "evidence_count": diagnosis["evidence_count"]}
        if task.task_type == "synthesis":
            scan.state = "SYNTHESIZING"
            db.commit()
            AISynthesisEngine(db, scan.id).synthesize()
            return {"status": "synthesized"}
        raise ValueError(f"Unknown task type: {task.task_type}")
