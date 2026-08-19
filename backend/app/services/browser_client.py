import logging
from uuid import UUID

import httpx
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.scan import HTTPResponse, Observation, Resource

from app.services.admission import validate_admission_url
from app.services.assessment import credentials_headers, get_credentials

logger = logging.getLogger("web_autopsy.browser_client")


class BrowserWorkerClient:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.settings = get_settings()

    def analyze_page(self, scan_id: UUID, page_id: UUID, url: str) -> bool:
        valid, reason = validate_admission_url(url)
        if not valid:
            logger.warning(f"Browser rendering blocked by SSRF check: {reason}")
            obs = Observation(
                scan_id=scan_id,
                category="BROWSER_ANALYSIS",
                subject=url,
                observation=f"Browser analysis blocked by SSRF protection: {reason}",
                classification="OBSERVED",
            )
            self.db.add(obs)
            self.db.commit()
            return False

        try:
            response = httpx.post(
                f"{self.settings.browser_worker_url}/render",
                json={
                    "url": url,
                    "timeout_ms": 20000,
                    "headers": credentials_headers(get_credentials(self.db, scan_id)),
                },
                timeout=25.0,
            )
            if response.status_code != 200:
                logger.warning(f"Browser worker HTTP {response.status_code} for {url}")
                return False

            data = response.json()
            if data.get("status") != "success":
                logger.warning(f"Browser rendering failed: {data.get('error')}")
                obs = Observation(
                    scan_id=scan_id,
                    category="BROWSER_ANALYSIS",
                    subject=url,
                    observation=f"Browser analysis failed: {data.get('error')}",
                    classification="OBSERVED",
                )

                self.db.add(obs)
                self.db.commit()
                return False

            resp = (
                self.db.query(HTTPResponse)
                .filter(HTTPResponse.page_id == page_id)
                .first()
            )
            if resp:
                resp.rendered_body = data.get("rendered_html")
                resp.timing_data = data.get("timing_data")
                self.db.commit()

            for req in data.get("network_requests", []):
                res = Resource(
                    page_id=page_id,
                    url=req["url"],
                    type=req.get("resource_type", "other"),
                    capture_source="browser_runtime",
                )
                self.db.add(res)

            for log_item in data.get("console_logs", []):
                obs = Observation(
                    scan_id=scan_id,
                    category="BROWSER_CONSOLE",
                    subject=log_item.get("type", "log"),
                    observation=log_item.get("text", ""),
                    classification="OBSERVED",
                )
                self.db.add(obs)

            self.db.commit()
            return True
        except Exception as exc:
            logger.warning(f"BrowserWorkerClient exception for {url}: {exc}")
            obs = Observation(
                scan_id=scan_id,
                category="BROWSER_ANALYSIS",
                subject=url,
                observation=f"Browser analysis degraded: {str(exc)}",
                classification="OBSERVED",
            )
            self.db.add(obs)

            self.db.commit()
            return False
