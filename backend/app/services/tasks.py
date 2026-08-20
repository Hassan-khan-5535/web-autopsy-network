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
from app.services.assessment import AssessmentPolicyError, append_audit_event, hostname_allowed, path_allowed, profile_policy
from app.services.admission import AdmissionService
from app.services.ai_synthesis import AISynthesisEngine
from app.services.api_intelligence import ApiIntelligenceAgent
from app.services.api_agent import APIAgent
from app.services.vulnerability import VulnerabilityAgent
from app.services.secrets import SecretsAgent
from app.services.cve_intelligence import CVEIntelligenceAgent
from app.services.evidence import EvidenceAgent
from app.services.browser_client import BrowserWorkerClient
from app.services.configuration import ConfigurationAgent
from app.services.correlation import CorrelationAgent
from app.services.risk import RiskAgent
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

TERMINAL_TASK_STATES = {"SUCCEEDED", "FAILED", "CANCELLED", "SKIPPED"}
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
    "configuration": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection", "http_agent"]},
    "api_agent": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection", "api_intelligence", "http_agent"]},
    "vulnerability": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection", "security", "configuration", "api_agent", "http_agent"]},
    "secrets": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection", "http_agent"]},
    "cve_intelligence": {"queue": "analysis", "max_retries": 2, "dependencies": ["technology"]},
    "evidence": {"queue": "analysis", "max_retries": 2, "dependencies": ["technology", "structure", "api_intelligence", "network_intelligence", "http_agent", "configuration", "api_agent", "security", "vulnerability", "secrets", "cve_intelligence", "performance", "accessibility", "content"]},
    "correlation": {"queue": "analysis", "max_retries": 2, "dependencies": ["evidence"]},
    "risk": {"queue": "analysis", "max_retries": 2, "dependencies": ["correlation", "evidence"]},
    "recon": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection"]},
    "security": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection"]},
    "content": {"queue": "analysis", "max_retries": 2, "dependencies": ["collection"]},
    "performance": {"queue": "analysis", "max_retries": 2, "dependencies": []},
    "accessibility": {"queue": "analysis", "max_retries": 2, "dependencies": []},
    "diagnosis": {"queue": "analysis", "max_retries": 1, "dependencies": ["technology", "structure", "api_intelligence", "network_intelligence", "http_agent", "configuration", "api_agent", "security", "vulnerability", "secrets", "cve_intelligence", "evidence", "correlation", "risk", "performance", "accessibility", "content"]},
    "synthesis": {"queue": "ai", "max_retries": 1, "dependencies": ["diagnosis"]},
    "report": {"queue": "analysis", "max_retries": 1, "dependencies": ["synthesis"]},
}

OUTPUT_READY = "AGENT_OUTPUT_READY"
EVENT_REQUIREMENTS: dict[str, list[str]] = {
    "configuration": ["event:http_agent:AGENT_OUTPUT_READY"],
    "security": ["event:http_agent:AGENT_OUTPUT_READY"],
    "secrets": ["event:http_agent:AGENT_OUTPUT_READY"],
    "api_agent": ["event:api_intelligence:AGENT_OUTPUT_READY", "event:http_agent:AGENT_OUTPUT_READY", "event:recon:AGENT_OUTPUT_READY"],
    "vulnerability": ["event:http_agent:AGENT_OUTPUT_READY", "event:security:AGENT_OUTPUT_READY", "event:configuration:AGENT_OUTPUT_READY", "event:api_agent:AGENT_OUTPUT_READY"],
    "cve_intelligence": ["event:technology:AGENT_OUTPUT_READY"],
    "evidence": ["event:technology:AGENT_OUTPUT_READY", "event:structure:AGENT_OUTPUT_READY", "event:api_intelligence:AGENT_OUTPUT_READY", "event:network_intelligence:AGENT_OUTPUT_READY", "event:http_agent:AGENT_OUTPUT_READY", "event:configuration:AGENT_OUTPUT_READY", "event:api_agent:AGENT_OUTPUT_READY", "event:security:AGENT_OUTPUT_READY", "event:vulnerability:AGENT_OUTPUT_READY", "event:secrets:AGENT_OUTPUT_READY", "event:cve_intelligence:AGENT_OUTPUT_READY"],
    "correlation": ["event:evidence:AGENT_OUTPUT_READY"],
    "risk": ["event:evidence:AGENT_OUTPUT_READY", "event:correlation:AGENT_OUTPUT_READY"],
    "diagnosis": ["event:risk:AGENT_OUTPUT_READY"],
    "report": ["event:synthesis:AGENT_OUTPUT_READY"],
}


class ScopePolicyViolation(RuntimeError):
    """Raised when a persisted agent action no longer satisfies authorization or policy."""


def utc_now() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def task_key(task_type: str, suffix: str | None = None) -> str:
    return f"{task_type}:{suffix}" if suffix else task_type


def output_event_key(task_key_value: str) -> str:
    return f"event:{task_key_value}:{OUTPUT_READY}"


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
    def _upsert_task(cls, db: Session, scan_id: UUID, task_type: str, *, key: str | None = None, dependencies: list[str] | None = None, event_requirements: list[str] | None = None) -> AgentTask:
        definition = TASK_DEFINITIONS[task_type]
        task_key_value = key or task_key(task_type)
        existing = db.query(AgentTask).filter(AgentTask.scan_id == scan_id, AgentTask.task_key == task_key_value).first()
        if existing:
            if not existing.event_requirements and (event_requirements or EVENT_REQUIREMENTS.get(task_type)):
                existing.event_requirements = event_requirements if event_requirements is not None else EVENT_REQUIREMENTS.get(task_type, [])
            return existing
        task = AgentTask(
            scan_id=scan_id,
            task_key=task_key_value,
            task_type=task_type,
            queue_name=definition["queue"],
            status="QUEUED",
            max_retries=definition["max_retries"],
            dependency_keys=dependencies if dependencies is not None else definition["dependencies"],
            event_requirements=event_requirements if event_requirements is not None else EVENT_REQUIREMENTS.get(task_type, []),
            available_at=utc_now(),
        )
        db.add(task)
        db.flush()
        cls._event(db, scan_id, task, "TASK_QUEUED", {"task_type": task_type, "dependencies": task.dependency_keys, "event_requirements": task.event_requirements})
        return task

    @classmethod
    def _budget(cls, scan: Scan) -> dict[str, int]:
        settings = get_settings()
        current = dict(scan.orchestration_budget or {})
        current.setdefault("task_dispatch_limit", max(settings.orchestration_min_task_dispatch_budget, int(scan.max_requests or scan.max_pages or 0)))
        current.setdefault("task_dispatches_used", 0)
        current.setdefault("per_queue_active_limit", max(1, min(int(scan.max_concurrency or 1), settings.max_concurrent_tasks_per_pool)))
        current.setdefault("task_timeout_seconds", settings.orchestration_task_timeout_seconds)
        scan.orchestration_budget = current
        return current

    @classmethod
    def _refresh_orchestration_state(cls, db: Session, scan: Scan) -> None:
        budget = cls._budget(scan)
        tasks = db.query(AgentTask).filter(AgentTask.scan_id == scan.id).all()
        event_count = db.query(AgentEvent).filter(AgentEvent.scan_id == scan.id).count()
        scan.orchestration_state = {
            "version": "extension13-v1",
            "scan_state": scan.state,
            "task_counts": dict(sorted({status: sum(item.status == status for item in tasks) for status in {item.status for item in tasks}}.items())),
            "event_count": event_count,
            "task_dispatches_used": budget["task_dispatches_used"],
            "task_dispatch_limit": budget["task_dispatch_limit"],
            "per_queue_active_limit": budget["per_queue_active_limit"],
            "task_timeout_seconds": budget["task_timeout_seconds"],
        }

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
        analysis_types = ["technology", "structure", "api_intelligence", "network_intelligence", "http_agent", "configuration", "api_agent", "security", "vulnerability", "secrets", "cve_intelligence", "evidence", "correlation", "risk", "content"]
        if scan.recon_mode in {"passive_only", "active_safe"}:
            analysis_types.append("recon")
        for task_type in analysis_types:
            dependencies = ["collection"]
            if task_type in {"configuration", "security"}:
                dependencies = ["collection", "http_agent"]
            if task_type == "api_agent":
                dependencies = ["collection", "api_intelligence", "http_agent"]
                if scan.recon_mode in {"passive_only", "active_safe"}:
                    dependencies.append("recon")
            if task_type == "vulnerability":
                dependencies = ["collection", "security", "configuration", "api_agent", "http_agent"]
            if task_type == "secrets":
                dependencies = ["collection", "http_agent"]
            if task_type == "cve_intelligence":
                dependencies = ["technology"]
            if task_type == "evidence":
                dependencies = ["technology", "structure", "api_intelligence", "network_intelligence", "http_agent", "configuration", "api_agent", "security", "vulnerability", "secrets", "cve_intelligence", "performance", "accessibility", "content"]
                if scan.recon_mode in {"passive_only", "active_safe"}:
                    dependencies.append("recon")
            if task_type == "correlation":
                dependencies = ["evidence"]
            if task_type == "risk":
                dependencies = ["correlation", "evidence"]
            cls._upsert_task(db, scan_id, task_type, dependencies=dependencies)
        cls._upsert_task(db, scan_id, "performance", dependencies=page_tasks or ["collection"])
        cls._upsert_task(db, scan_id, "accessibility", dependencies=page_tasks or ["collection"])
        analysis_keys = ["technology", "structure", "api_intelligence", "network_intelligence", "http_agent", "configuration", "api_agent", "security", "vulnerability", "secrets", "cve_intelligence", "evidence", "correlation", "risk", "performance", "accessibility", "content"]
        if scan.recon_mode in {"passive_only", "active_safe"}:
            analysis_keys.append("recon")
        cls._upsert_task(db, scan_id, "diagnosis", dependencies=analysis_keys)
        cls._upsert_task(db, scan_id, "synthesis", dependencies=["diagnosis"])
        cls._upsert_task(db, scan_id, "report", dependencies=["synthesis"])
        scan.state = "ANALYZING"
        cls._refresh_orchestration_state(db, scan)
        db.commit()

    @classmethod
    def _propagate_dependency_failures(cls, db: Session, scan_id: UUID) -> bool:
        """Terminalize queued work whose prerequisites failed, including transitive dependents."""
        changed_any = False
        while True:
            changed = False
            tasks = db.query(AgentTask).filter(AgentTask.scan_id == scan_id).all()
            task_map = {task.task_key: task for task in tasks}
            now = utc_now()
            for task in tasks:
                if task.status not in {"QUEUED", "RETRYING"}:
                    continue
                dependencies = [task_map.get(key) for key in (task.dependency_keys or [])]
                blockers = [dependency for dependency in dependencies if dependency and dependency.status in TERMINAL_TASK_STATES - {"SUCCEEDED"}]
                if not blockers:
                    continue
                task.status = "SKIPPED"
                task.progress = 100
                task.finished_at = now
                task.updated_at = now
                task.available_at = None
                task.error_reason = "Skipped because dependency did not produce usable output: " + ", ".join(dependency.task_key for dependency in blockers)
                cls._event(
                    db,
                    scan_id,
                    task,
                    "TASK_DEPENDENCY_BLOCKED",
                    {"dependencies": [dependency.task_key for dependency in blockers], "status": task.status},
                )
                changed = True
                changed_any = True
            if not changed:
                break
        return changed_any

    @classmethod
    def dispatch_ready(cls, db: Session, scan_id: UUID) -> None:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or scan.cancel_requested or scan.pause_requested or scan.state == "PAUSED":
            return
        cls._propagate_dependency_failures(db, scan_id)
        now = utc_now()
        budget = cls._budget(scan)
        tasks = db.query(AgentTask).filter(AgentTask.scan_id == scan_id, AgentTask.status.in_(["QUEUED", "RETRYING"])).order_by(AgentTask.created_at, AgentTask.task_key).all()
        to_dispatch: list[AgentTask] = []
        task_map = {task.task_key: task for task in db.query(AgentTask).filter(AgentTask.scan_id == scan_id).all()}
        event_keys = {item.event_key for item in db.query(AgentEvent).filter(AgentEvent.scan_id == scan_id, AgentEvent.event_type == OUTPUT_READY, AgentEvent.event_key.is_not(None)).all()}
        active_by_queue: dict[str, int] = {}
        for active in task_map.values():
            if active.status in {"DISPATCHED", "RUNNING"}:
                active_by_queue[active.queue_name] = active_by_queue.get(active.queue_name, 0) + 1
        for task in tasks:
            available_at = as_utc(task.available_at)
            if available_at and available_at > now:
                continue
            deps = [task_map.get(key) for key in (task.dependency_keys or [])]
            failed_deps = [dep for dep in deps if dep is not None and dep.status in {"FAILED", "CANCELLED", "SKIPPED"}]
            missing_deps = [key for key, dep in zip(task.dependency_keys or [], deps) if dep is None]
            if failed_deps or missing_deps:
                task.status = "SKIPPED"
                task.progress = 100
                task.finished_at = now
                task.updated_at = now
                reason = ", ".join(dep.task_key for dep in failed_deps) or ", ".join(missing_deps)
                task.error_reason = f"Skipped because dependency did not produce usable output: {reason}."
                cls._event(db, scan_id, task, "TASK_SKIPPED", {"reason": task.error_reason})
                continue
            if any(dep.status not in TERMINAL_TASK_STATES for dep in deps):
                continue
            if any(requirement not in event_keys for requirement in (task.event_requirements or [])):
                continue
            if active_by_queue.get(task.queue_name, 0) >= budget["per_queue_active_limit"]:
                continue
            if budget["task_dispatches_used"] >= budget["task_dispatch_limit"]:
                task.status = "FAILED"
                task.finished_at = now
                task.error_reason = "Per-scan task dispatch budget exhausted."
                cls._event(db, scan_id, task, "TASK_BUDGET_EXHAUSTED", {"budget": budget})
                continue
            task.status = "DISPATCHED"
            task.updated_at = now
            task.deadline_at = now + timedelta(seconds=budget["task_timeout_seconds"])
            budget["task_dispatches_used"] += 1
            active_by_queue[task.queue_name] = active_by_queue.get(task.queue_name, 0) + 1
            cls._event(db, scan_id, task, "TASK_DISPATCHED", {"queue": task.queue_name, "deadline_at": task.deadline_at.isoformat(), "event_requirements": task.event_requirements or []})
            to_dispatch.append(task)
        scan.orchestration_budget = budget
        cls._refresh_orchestration_state(db, scan)
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
        cls._refresh_orchestration_state(db, scan)
        cls._event(db, scan_id, None, "SCAN_TERMINAL", {"state": scan.state})
        db.commit()
        if scan.state == "COMPLETED":
            from app.services.continuous import PostureTimelineService
            PostureTimelineService(db).refresh_snapshot(scan_id)
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
        cls.dispatch_ready(db, scan_id)
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
        stale = [
            task for task in db.query(AgentTask).filter(AgentTask.status.in_(["DISPATCHED", "RUNNING"])).all()
            if (as_utc(task.updated_at) is not None and as_utc(task.updated_at) < stale_cutoff)
            or (as_utc(task.deadline_at) is not None and as_utc(task.deadline_at) <= now)
        ]
        affected: set[UUID] = set()
        for task in stale:
            affected.add(task.scan_id)
            deadline_expired = as_utc(task.deadline_at) is not None and as_utc(task.deadline_at) <= now
            if task.attempt <= task.max_retries:
                task.status = "RETRYING"
                task.available_at = now
                task.deadline_at = None
                task.error_reason = "Task deadline expired; task returned to the retry queue." if deadline_expired else "Worker heartbeat expired; task returned to the retry queue."
                cls._event(db, task.scan_id, task, "TASK_DEADLINE_RECOVERED" if deadline_expired else "TASK_ORPHAN_RECOVERED", {"attempt": task.attempt})
            else:
                task.status = "FAILED"
                task.finished_at = now
                task.error_reason = "Task deadline expired after retry budget was exhausted." if deadline_expired else "Worker heartbeat expired after retry budget was exhausted."
                cls._event(db, task.scan_id, task, "TASK_DEADLINE_FAILED" if deadline_expired else "TASK_ORPHAN_FAILED", {"attempt": task.attempt})
        for scan in db.query(Scan).filter(Scan.state.in_(ACTIVE_SCAN_STATES)).all():
            queued_at = as_utc(scan.queued_at)
            if queued_at is None or queued_at >= now - timedelta(seconds=settings.scan_timeout_seconds):
                continue
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
    def _event(db: Session, scan_id: UUID, task: AgentTask | None, event_type: str, payload: dict[str, Any], *, event_key: str | None = None) -> None:
        if event_key and db.query(AgentEvent).filter(AgentEvent.scan_id == scan_id, AgentEvent.event_key == event_key).first():
            return
        db.add(AgentEvent(scan_id=scan_id, task_id=task.id if task else None, event_type=event_type, event_key=event_key, payload=payload))


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
            cls._assert_action_authorized(scan)
            result = cls._execute(db, task, scan)
            db.refresh(scan)
            task.status = "CANCELLED" if scan.cancel_requested else "SUCCEEDED"
            task.progress = 100
            task.result = result or {}
            task.error_reason = None
            task.finished_at = utc_now()
            task.heartbeat_at = utc_now()
            task.updated_at = utc_now()
            TaskGraphCoordinator._event(db, task.scan_id, task, "TASK_CANCELLED" if task.status == "CANCELLED" else "TASK_SUCCEEDED", result or {})
            if task.status == "SUCCEEDED":
                TaskGraphCoordinator._event(db, task.scan_id, task, OUTPUT_READY, {"task_type": task.task_type, "task_key": task.task_key, "result_summary": result or {}}, event_key=output_event_key(task.task_key))
            TaskGraphCoordinator._refresh_orchestration_state(db, scan)
            db.commit()
            TaskGraphCoordinator.after_terminal(db, task.scan_id)
        except Exception as exc:
            db.rollback()
            task = db.query(AgentTask).filter(AgentTask.id == task_id).first()
            if not task:
                return
            task.error_reason = str(exc)
            task.heartbeat_at = utc_now()
            if isinstance(exc, ScopePolicyViolation):
                task.status = "FAILED"
                task.finished_at = utc_now()
                TaskGraphCoordinator._event(db, task.scan_id, task, "TASK_SCOPE_BLOCKED", {"error": str(exc)})
                scan = db.query(Scan).filter(Scan.id == task.scan_id).first()
                if scan:
                    TaskGraphCoordinator._refresh_orchestration_state(db, scan)
                db.commit()
                TaskGraphCoordinator.after_terminal(db, task.scan_id)
            elif task.attempt <= task.max_retries:
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

    @staticmethod
    def _assert_action_authorized(scan: Scan) -> None:
        authorization = scan.assessment_authorization
        if not authorization:
            raise ScopePolicyViolation("No persisted authorization is available for this agent action.")
        expires_at = as_utc(authorization.expires_at)
        if expires_at and expires_at <= utc_now():
            raise ScopePolicyViolation("Stored authorization has expired.")
        if authorization.assessment_profile != scan.assessment_profile:
            raise ScopePolicyViolation("Stored authorization profile does not match the scan profile.")
        try:
            profile_policy(
                authorization.assessment_profile,
                max_depth=authorization.max_depth,
                max_requests=authorization.max_requests,
                max_concurrency=authorization.max_concurrency,
                rate_limit_per_host_ms=authorization.rate_limit_per_host_ms,
            )
        except AssessmentPolicyError as exc:
            raise ScopePolicyViolation(f"Stored authorization no longer meets current policy: {exc}") from exc
        parsed = urlsplit(scan.requested_url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname or not hostname_allowed(hostname, authorization.allowed_domains) or not path_allowed(scan.requested_url, authorization.allowed_paths, authorization.excluded_paths):
            raise ScopePolicyViolation("Stored authorization does not permit the current target hostname or path.")

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
        if task.task_type == "api_agent":
            findings = APIAgent(db, scan.id).analyze()
            return {"findings": len(findings)}
        if task.task_type == "vulnerability":
            findings = VulnerabilityAgent(db, scan.id).analyze()
            return {"findings": len(findings)}
        if task.task_type == "secrets":
            findings = SecretsAgent(db, scan.id).analyze()
            return {"findings": len(findings)}
        if task.task_type == "cve_intelligence":
            matches = CVEIntelligenceAgent(db, scan.id).analyze()
            return {"matches": len(matches)}
        if task.task_type == "evidence":
            reviews = EvidenceAgent(db, scan.id).analyze()
            return {"reviews": len(reviews)}
        if task.task_type == "correlation":
            return CorrelationAgent(db, scan.id).analyze(source_event="task:correlation")
        if task.task_type == "risk":
            assessments = RiskAgent(db, scan.id).analyze()
            return {"assessments": len(assessments), "deterministic_version": "extension11-v1"}
        if task.task_type == "network_intelligence":
            return {"findings": len(NetworkIntelligenceAgent(db, scan.id).analyze())}
        if task.task_type == "http_agent":
            return {"observations": len(HTTPAgent(db, scan.id).analyze())}
        if task.task_type == "configuration":
            return {"findings": len(ConfigurationAgent(db, scan.id).analyze())}
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
        if task.task_type == "report":
            return {"status": "report_updated", "orchestration_version": "extension13-v1"}
        raise ValueError(f"Unknown task type: {task.task_type}")
