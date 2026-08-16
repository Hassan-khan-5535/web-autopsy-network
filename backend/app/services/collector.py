from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.scan import Scan
from app.services.crawler import CrawlerService


class HTTPCollectorService:
    """Backward-compatible Phase 2 entry point backed by the Phase 3 crawler."""

    @staticmethod
    def collect(db: Session, scan_id: UUID, initial_url: str) -> None:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        settings = get_settings()
        original_limits = (
            scan.max_depth,
            scan.max_pages,
            scan.max_concurrency,
            scan.request_delay_ms,
        )
        scan.max_depth = 0
        scan.max_pages = 1
        scan.max_concurrency = 1
        scan.request_delay_ms = settings.crawl_min_delay_ms
        db.commit()
        CrawlerService(db, scan, initial_url).crawl()
        scan.max_depth, scan.max_pages, scan.max_concurrency, scan.request_delay_ms = (
            original_limits
        )
        db.commit()
