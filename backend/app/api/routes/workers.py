from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.config import get_settings
from app.models.scan import AgentTask
from app.services.tasks import TaskGraphCoordinator, as_utc

router = APIRouter()


@router.get("/workers/health")
def get_worker_health(db: Session = Depends(get_db)):
    TaskGraphCoordinator.recover_stale_tasks(db)
    now = datetime.now(UTC)
    pools = {}
    for queue in ("crawl", "browser", "analysis", "ai"):
        tasks = db.query(AgentTask).filter(AgentTask.queue_name == queue).all()
        active = [task for task in tasks if task.status in {"DISPATCHED", "RUNNING", "RETRYING"}]
        latest = max((task.heartbeat_at for task in tasks if task.heartbeat_at), default=None)
        latest_utc = as_utc(latest)
        pools[queue] = {
            "status": "active" if active else "idle",
            "active_tasks": len(active),
            "configured_concurrency": get_settings().max_concurrent_tasks_per_pool if queue != "ai" else 1,
            "latest_heartbeat": latest_utc.isoformat() if latest_utc else None,
            "heartbeat_fresh": bool(latest_utc and latest_utc >= now - timedelta(seconds=get_settings().task_heartbeat_seconds * 4)),
        }
    return {"status": "ok", "checked_at": now.isoformat(), "pools": pools}
