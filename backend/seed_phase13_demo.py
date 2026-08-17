from datetime import UTC, datetime, timedelta

from app.core.database import SessionLocal, engine
from app.models.base import Base
from app.models.scan import AgentEvent, AgentTask, Scan, Website

Base.metadata.create_all(engine)

with SessionLocal() as db:
    website = db.query(Website).filter(Website.canonical_origin == "phase13.example").first()
    if not website:
        website = Website(canonical_origin="phase13.example")
        db.add(website)
        db.flush()
    scan = db.query(Scan).filter(Scan.website_id == website.id, Scan.requested_url == "https://phase13.example", Scan.state == "ANALYZING").first()
    if not scan:
        scan = Scan(
            website_id=website.id,
            requested_url="https://phase13.example",
            state="ANALYZING",
            queued_at=datetime.now(UTC),
            max_depth=2,
            max_pages=20,
        )
        db.add(scan)
        db.flush()
        definitions = [
            ("admission", "crawl", "SUCCEEDED", 100, [], 1),
            ("collection", "crawl", "SUCCEEDED", 100, ["admission"], 1),
            ("browser_analysis:home", "browser", "SUCCEEDED", 100, ["collection"], 1),
            ("technology", "analysis", "RUNNING", 45, ["collection"], 1),
            ("structure", "analysis", "DISPATCHED", 0, ["collection"], 1),
            ("api_intelligence", "analysis", "QUEUED", 0, ["collection"], 0),
            ("network_intelligence", "analysis", "QUEUED", 0, ["collection"], 0),
            ("security", "analysis", "QUEUED", 0, ["collection"], 0),
            ("performance", "analysis", "QUEUED", 0, ["browser_analysis:home"], 0),
            ("accessibility", "analysis", "QUEUED", 0, ["browser_analysis:home"], 0),
            ("content", "analysis", "QUEUED", 0, ["collection"], 0),
            ("diagnosis", "analysis", "QUEUED", 0, ["technology", "structure", "api_intelligence", "network_intelligence", "security", "performance", "accessibility", "content"], 0),
            ("synthesis", "ai", "QUEUED", 0, ["diagnosis"], 0),
        ]
        for key, queue, status, progress, deps, attempt in definitions:
            task = AgentTask(
                scan_id=scan.id,
                task_key=key,
                task_type=key.split(":", 1)[0],
                queue_name=queue,
                status=status,
                progress=progress,
                attempt=attempt,
                max_retries=2,
                dependency_keys=deps,
                started_at=datetime.now(UTC) - timedelta(seconds=12) if status == "RUNNING" else None,
                heartbeat_at=datetime.now(UTC) if status in {"RUNNING", "DISPATCHED"} else None,
            )
            db.add(task)
            db.flush()
            db.add(AgentEvent(scan_id=scan.id, task_id=task.id, event_type="TASK_" + ("STARTED" if status == "RUNNING" else "QUEUED"), payload={"demo": True}))
        db.commit()
    print(scan.id)
