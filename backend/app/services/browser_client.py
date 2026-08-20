import base64
import hashlib
import logging
from uuid import UUID

import httpx
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.scan import BrowserScreenshot, HTTPResponse, Observation, Page, Resource

from app.services.admission import validate_admission_url
from app.services.assessment import credentials_headers, get_authorization, get_credentials, hostname_allowed, path_allowed
from app.services.scanner_security import redact_sensitive_text
from urllib.parse import urlsplit

logger = logging.getLogger("web_autopsy.browser_client")


class BrowserWorkerClient:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.settings = get_settings()

    def analyze_page(self, scan_id: UUID, page_id: UUID, url: str) -> bool:
        page = self.db.query(Page).filter(Page.id == page_id, Page.scan_id == scan_id).first()
        if not page:
            logger.warning("Browser analysis blocked because page does not belong to the scan.")
            return False
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
            worker_host = (urlsplit(self.settings.browser_worker_url).hostname or "").lower()
            allowed_worker_hosts = {value.strip().lower() for value in self.settings.browser_worker_allowed_hosts.split(",") if value.strip()}
            if worker_host not in allowed_worker_hosts:
                raise ValueError("Browser worker endpoint is not in the configured internal allowlist.")
            authorization = get_authorization(self.db, scan_id)
            headers = credentials_headers(get_credentials(self.db, scan_id)) if self.settings.browser_worker_forward_credentials else {}
            scope_json = authorization.scope_json if authorization and isinstance(authorization.scope_json, dict) else {}
            allowed_ports = [int(port) for port in (scope_json.get("allowed_ports") or []) if 1 <= int(port) <= 65535]
            response = httpx.post(
                f"{self.settings.browser_worker_url}/render",
                json={
                    "url": url,
                    "scan_id": str(scan_id),
                    "page_id": str(page_id),
                    "timeout_ms": self.settings.browser_worker_timeout_ms,
                    "headers": headers,
                    "egress_policy": {"allowed_domains": (authorization.allowed_domains if authorization else []), "allowed_paths": (authorization.allowed_paths if authorization else []), "blocked_private_networks": True, "allowed_ports": allowed_ports},
                    "resource_limits": {
                        "max_cpu_seconds": self.settings.browser_worker_max_cpu_seconds,
                        "max_memory_mb": self.settings.browser_worker_max_memory_mb,
                        "max_rendered_bytes": self.settings.browser_worker_max_rendered_bytes,
                        "max_network_events": self.settings.browser_worker_max_network_events,
                        "max_console_events": self.settings.browser_worker_max_console_events,
                        "max_screenshot_bytes": 1024 * 1024,
                    },
                },
                timeout=(self.settings.browser_worker_timeout_ms / 1000) + 5,
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
                rendered = str(data.get("rendered_html") or "")
                resp.rendered_body = rendered[: self.settings.browser_worker_max_rendered_bytes]
                resp.timing_data = data.get("timing_data")
                self.db.commit()

            screenshot_b64 = data.get("screenshot_png_base64")
            if screenshot_b64 and not headers:
                try:
                    screenshot_bytes = base64.b64decode(str(screenshot_b64), validate=True)
                    if len(screenshot_bytes) <= 1024 * 1024:
                        self.db.add(BrowserScreenshot(
                            scan_id=scan_id,
                            page_id=page_id,
                            image_base64=str(screenshot_b64),
                            sha256=hashlib.sha256(screenshot_bytes).hexdigest(),
                            redaction_status="safe_public_page",
                        ))
                except (ValueError, TypeError):
                    logger.warning("Browser worker returned an invalid screenshot payload for %s", url)

            for req in data.get("network_requests", [])[: self.settings.browser_worker_max_network_events]:
                request_url = str(req.get("url") or "")
                if not self._browser_request_in_scope(request_url, authorization, page.canonical_url):
                    continue
                res = Resource(
                    page_id=page_id,
                    url=request_url,
                    type=req.get("resource_type", "other"),
                    capture_source="browser_runtime",
                )
                self.db.add(res)

            for log_item in data.get("console_logs", [])[: self.settings.browser_worker_max_console_events]:
                obs = Observation(
                    scan_id=scan_id,
                    category="BROWSER_CONSOLE",
                    subject=log_item.get("type", "log"),
                    observation=redact_sensitive_text(log_item.get("text", ""), 2048),
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
                observation=f"Browser analysis degraded: {redact_sensitive_text(exc)}",
                classification="OBSERVED",
            )
            self.db.add(obs)

            self.db.commit()
            return False

    @staticmethod
    def _browser_request_in_scope(url: str, authorization, page_url: str) -> bool:
        valid, _ = validate_admission_url(url)
        if not valid:
            return False
        if not authorization:
            return (urlsplit(url).hostname or "").lower().rstrip(".") == (urlsplit(page_url).hostname or "").lower().rstrip(".")
        hostname = (urlsplit(url).hostname or "").lower().rstrip(".")
        return hostname_allowed(hostname, authorization.allowed_domains or []) and path_allowed(url, authorization.allowed_paths or [], authorization.excluded_paths or [])
