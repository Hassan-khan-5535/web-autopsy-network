from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from typing import Protocol
from uuid import UUID

from app.core.config import get_settings

try:
    from celery import Celery
except ImportError:  # pragma: no cover - local fallback when optional dependency is absent
    Celery = None  # type: ignore[assignment]


class TaskDispatcher(Protocol):
    def dispatch(self, task_id: UUID, queue_name: str) -> None: ...


class InlineTaskDispatcher:
    """Non-blocking local fallback used when Redis/Celery is unavailable.

    SQLite is intentionally serialized because it permits only one writer at a time;
    PostgreSQL-backed inline deployments retain bounded parallelism.
    """

    _executors: dict[int, ThreadPoolExecutor] = {}
    _executor_lock = Lock()

    def __init__(self) -> None:
        workers = 1 if get_settings().database_url.startswith("sqlite") else 8
        with self._executor_lock:
            self._executor = self._executors.setdefault(
                workers,
                ThreadPoolExecutor(max_workers=workers, thread_name_prefix="web-autopsy-task"),
            )

    def dispatch(self, task_id: UUID, queue_name: str) -> None:
        from app.services.tasks import TaskRunner
        self._executor.submit(TaskRunner.run, task_id)


class CeleryTaskDispatcher:
    def __init__(self, celery_app: "Celery"):
        self.celery_app = celery_app

    def dispatch(self, task_id: UUID, queue_name: str) -> None:
        self.celery_app.send_task(
            "web_autopsy.execute_task",
            args=[str(task_id)],
            queue=queue_name,
            task_id=str(task_id),
        )


def build_celery_app() -> "Celery | None":
    if Celery is None:
        return None
    settings = get_settings()
    app = Celery(
        "web_autopsy",
        broker=settings.queue_backend_url,
        backend=settings.queue_backend_url,
    )
    app.conf.update(
        task_default_retry_delay=settings.task_retry_backoff_seconds,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        task_track_started=True,
        task_routes={"web_autopsy.execute_task": {"queue": "analysis"}},
    )
    return app


def get_dispatcher() -> TaskDispatcher:
    settings = get_settings()
    if settings.queue_mode.lower() == "inline":
        return InlineTaskDispatcher()
    celery_app = build_celery_app()
    mode = settings.queue_mode.lower()
    if celery_app is not None and mode == "celery":
        return CeleryTaskDispatcher(celery_app)
    if celery_app is not None and mode == "auto":
        try:
            with celery_app.connection_for_read() as connection:
                connection.ensure_connection(max_retries=1)
            return CeleryTaskDispatcher(celery_app)
        except Exception:
            return InlineTaskDispatcher()
    return InlineTaskDispatcher()


celery_app = build_celery_app()

if celery_app is not None:
    @celery_app.task(name="web_autopsy.execute_task", bind=True, acks_late=True)
    def execute_task(_self, task_id: str) -> None:
        from app.services.tasks import TaskRunner
        TaskRunner.run(UUID(task_id))
