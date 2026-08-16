from __future__ import annotations

import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from threading import Lock
from typing import Any
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser
from uuid import UUID

import httpx
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.scan import Header, HTTPResponse, Observation, Page, PageLink, Resource, Scan
from app.services.admission import AdmissionError, AdmissionService


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status_code: int | None
    content_type: str | None
    elapsed_ms: float | None
    headers: list[tuple[str, str]]
    body: str
    redirects: list[tuple[str, str]]
    error: str | None = None


class RequestRateLimiter:
    def __init__(self, delay_ms: int) -> None:
        self.delay_seconds = max(delay_ms, 0) / 1000
        self._lock = Lock()
        self._last_request_at = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            remaining = self.delay_seconds - (now - self._last_request_at)
            if remaining > 0:
                time.sleep(remaining)
            self._last_request_at = time.monotonic()


class CrawlerService:
    """Synchronous, bounded, static-HTML crawler for a single scan."""

    USER_AGENT = "WebAutopsyNetwork/0.3 (authorized passive analysis; educational project)"
    TIMEOUT = 10.0
    MAX_REDIRECTS = 5
    MAX_BODY_BYTES = 5 * 1024 * 1024

    def __init__(self, db: Session, scan: Scan, seed_url: str) -> None:
        settings = get_settings()
        self.db = db
        self.scan = scan
        self.seed_url = seed_url
        self.same_domain_mode = scan.same_domain_mode or settings.crawl_same_domain_mode
        self.rate_limiter = RequestRateLimiter(scan.request_delay_ms)
        self.robots: dict[str, RobotFileParser | None] = {}
        self.robots_errors: set[str] = set()

    def crawl(self) -> None:
        self.scan.state = "COLLECTING"
        self.db.commit()

        try:
            seed_url, _ = AdmissionService.validate_and_resolve(self.seed_url)
            domain_root = seed_url
            queue: deque[tuple[str, int, UUID | None]] = deque([(seed_url, 0, None)])
            visited: set[str] = {seed_url}
            scheduled_pages = 0

            while queue and scheduled_pages < self.scan.max_pages:
                batch: list[tuple[str, int, UUID | None, Page]] = []
                while (
                    queue
                    and len(batch) < self.scan.max_concurrency
                    and scheduled_pages < self.scan.max_pages
                ):
                    candidate_url, depth, parent_page_id = queue.popleft()
                    if depth > self.scan.max_depth:
                        continue
                    if not self._is_same_domain(domain_root, candidate_url):
                        self._observe(
                            "CRAWL_POLICY",
                            candidate_url,
                            "External-domain URL was recorded but not fetched.",
                        )
                        continue
                    if not self._robots_allowed(candidate_url):
                        self._observe(
                            "ROBOTS",
                            candidate_url,
                            "URL was not fetched because robots.txt disallows this user agent.",
                        )
                        continue

                    page = Page(
                        scan_id=self.scan.id,
                        canonical_url=candidate_url,
                        depth=depth,
                        discovered_from_page_id=parent_page_id,
                    )
                    self.db.add(page)
                    self.db.flush()
                    batch.append((candidate_url, depth, parent_page_id, page))
                    scheduled_pages += 1

                if not batch:
                    continue

                with ThreadPoolExecutor(max_workers=self.scan.max_concurrency) as executor:
                    futures = {
                        executor.submit(self._fetch_page, candidate_url, domain_root): (
                            candidate_url,
                            page,
                        )
                        for candidate_url, _, _, page in batch
                    }
                    for future in as_completed(futures):
                        requested_url, page = futures[future]
                        result = future.result()
                        discovered = self._persist_page_result(page, result, domain_root)
                        if result.error:
                            continue
                        next_depth = page.depth + 1
                        if next_depth > self.scan.max_depth:
                            continue
                        for target_url, is_external in discovered:
                            if is_external:
                                self._observe(
                                    "LINK",
                                    page.canonical_url,
                                    f"External link observed: {target_url}",
                                )
                                continue
                            if target_url in visited:
                                continue
                            visited.add(target_url)
                            if len(visited) > self.scan.max_pages * 4:
                                # Bound memory used by hostile link farms while preserving
                                # the server-enforced fetched-page ceiling.
                                continue
                            try:
                                admitted_url, _ = AdmissionService.validate_and_resolve(target_url)
                            except AdmissionError as exc:
                                self._observe(
                                    "CRAWL_ADMISSION",
                                    target_url,
                                    f"Discovered URL blocked before fetch: {exc}",
                                )
                                continue
                            if not self._is_same_domain(domain_root, admitted_url):
                                self._observe(
                                    "CRAWL_POLICY",
                                    admitted_url,
                                    "External-domain URL was recorded but not fetched.",
                                )
                                continue
                            queue.append((admitted_url, next_depth, page.id))

                self.db.commit()

            if queue and scheduled_pages >= self.scan.max_pages:
                self._observe(
                    "CRAWL_LIMIT",
                    self.seed_url,
                    f"Maximum page count reached: {self.scan.max_pages}.",
                )
            self._observe(
                "CRAWL_SUMMARY",
                self.seed_url,
                f"Fetched {scheduled_pages} page(s) with max depth {self.scan.max_depth}.",
            )
            self.scan.state = "COMPLETED"
            self.db.commit()
        except Exception as exc:
            self.scan.state = "FAILED"
            self.scan.error_reason = str(exc)
            self.db.commit()

    def _is_same_domain(self, domain_root: str, candidate_url: str) -> bool:
        return AdmissionService.same_domain(domain_root, candidate_url, self.same_domain_mode)

    def _robots_allowed(self, url: str) -> bool:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower()
        if hostname in self.robots:
            parser = self.robots[hostname]
            return parser is None or parser.can_fetch(self.USER_AGENT, url)

        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            admitted_robots_url, _ = AdmissionService.validate_and_resolve(robots_url)
            self.rate_limiter.wait()
            with httpx.Client(
                timeout=self.TIMEOUT,
                follow_redirects=False,
                headers={"User-Agent": self.USER_AGENT},
            ) as client:
                response = client.get(admitted_robots_url)
                if 300 <= response.status_code < 400 and response.headers.get("location"):
                    redirect_url = urljoin(admitted_robots_url, response.headers["location"])
                    redirect_url, _ = AdmissionService.validate_and_resolve(redirect_url)
                    if not self._is_same_domain(url, redirect_url):
                        raise AdmissionError("robots.txt redirect leaves the crawl domain")
                    response = client.get(redirect_url)
            parser = RobotFileParser()
            parser.set_url(admitted_robots_url)
            if response.status_code == 404:
                parser.parse([])
            elif 200 <= response.status_code < 300:
                parser.parse(response.text.splitlines())
            else:
                self.robots_errors.add(hostname)
                self._observe(
                    "ROBOTS",
                    robots_url,
                    f"robots.txt returned status {response.status_code}; crawl allowed.",
                )
                self.robots[hostname] = None
                return True
            self.robots[hostname] = parser
            self._observe(
                "ROBOTS", robots_url, f"robots.txt fetched with status {response.status_code}."
            )
            return parser.can_fetch(self.USER_AGENT, url)
        except (AdmissionError, httpx.RequestError) as exc:
            self.robots_errors.add(hostname)
            self.robots[hostname] = None
            self._observe("ROBOTS", robots_url, f"robots.txt unavailable; crawl allowed: {exc}")
            return True

    def _fetch_page(self, requested_url: str, domain_root: str) -> FetchResult:
        self.rate_limiter.wait()
        current_url = requested_url
        redirects: list[tuple[str, str]] = []
        started_at = time.perf_counter()

        try:
            with httpx.Client(
                timeout=self.TIMEOUT,
                follow_redirects=False,
                headers={
                    "User-Agent": self.USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml",
                },
            ) as client:
                for _ in range(self.MAX_REDIRECTS + 1):
                    response = client.get(current_url)
                    if 300 <= response.status_code < 400 and response.headers.get("location"):
                        redirect_url = urljoin(current_url, response.headers["location"])
                        redirect_url, _ = AdmissionService.validate_and_resolve(redirect_url)
                        if not self._is_same_domain(domain_root, redirect_url):
                            raise AdmissionError(
                                "Redirect leaves the crawl domain and was not fetched."
                            )
                        redirects.append((current_url, redirect_url))
                        current_url = redirect_url
                        continue

                    content_type = response.headers.get("content-type")
                    body = response.text if content_type and "html" in content_type.lower() else ""
                    if len(body.encode("utf-8", errors="ignore")) > self.MAX_BODY_BYTES:
                        body = body.encode("utf-8", errors="ignore")[: self.MAX_BODY_BYTES].decode(
                            "utf-8", errors="ignore"
                        )
                    return FetchResult(
                        requested_url=requested_url,
                        final_url=AdmissionService.normalize_url(str(response.url)),
                        status_code=response.status_code,
                        content_type=content_type,
                        elapsed_ms=(time.perf_counter() - started_at) * 1000,
                        headers=list(response.headers.multi_items()),
                        body=body,
                        redirects=redirects,
                    )
            raise AdmissionError(f"Exceeded maximum redirects ({self.MAX_REDIRECTS})")
        except (AdmissionError, httpx.RequestError, UnicodeError) as exc:
            return FetchResult(
                requested_url=requested_url,
                final_url=current_url,
                status_code=None,
                content_type=None,
                elapsed_ms=(time.perf_counter() - started_at) * 1000,
                headers=[],
                body="",
                redirects=redirects,
                error=str(exc),
            )

    def _persist_page_result(
        self, page: Page, result: FetchResult, domain_root: str
    ) -> list[tuple[str, bool]]:
        if result.error:
            self._observe("HTTP", result.requested_url, f"Page fetch failed: {result.error}")
            return []

        page.canonical_url = result.final_url
        page.status_code = result.status_code
        response = HTTPResponse(
            page_id=page.id,
            status_code=result.status_code or 0,
            final_url=result.final_url,
            content_type=result.content_type,
            timings_ms=result.elapsed_ms,
            raw_body=result.body or None,
        )
        self.db.add(response)
        self.db.flush()
        for name, value in result.headers:
            self.db.add(Header(http_response_id=response.id, name=name.lower(), value=value))
        for source_url, target_url in result.redirects:
            self._observe("HTTP", source_url, f"Redirects to {target_url}")
        self._observe("HTTP", page.canonical_url, f"Returned status code {result.status_code}")

        if not result.body:
            return []

        soup = BeautifulSoup(result.body, "html.parser")
        title = soup.title.string.strip() if soup.title and soup.title.string else None
        page.title = title[:2048] if title else None
        resources, page_links = self._extract_html(page, soup, result.final_url, domain_root)
        for resource in resources:
            self.db.add(resource)
        for target_url, is_external in page_links:
            self.db.add(
                PageLink(source_page_id=page.id, target_url=target_url, is_external=is_external)
            )
        return page_links

    def _extract_html(
        self, page: Page, soup: BeautifulSoup, base_url: str, domain_root: str
    ) -> tuple[list[Resource], list[tuple[str, bool]]]:
        resources: list[Resource] = []
        page_links: list[tuple[str, bool]] = []
        selectors = {
            "link": "href",
            "script": "src",
            "img": "src",
            "form": "action",
            "iframe": "src",
            "source": "src",
        }
        counts: dict[str, int] = {}
        for tag_name, attr_name in selectors.items():
            elements = soup.find_all(tag_name)
            counts[tag_name] = len(elements)
            for element in elements:
                raw_value = element.get(attr_name)
                resolved = urljoin(base_url, raw_value) if raw_value else None
                attributes: dict[str, Any] = dict(element.attrs)
                resource_type = tag_name
                if tag_name == "link":
                    rel = [str(value).lower() for value in element.get("rel", [])]
                    if str(element.get("as", "")).lower() == "font" or "font" in rel:
                        resource_type = "font"
                resources.append(
                    Resource(
                        page_id=page.id, url=resolved, type=resource_type, attributes=attributes
                    )
                )

        for anchor in soup.find_all("a", href=True):
            raw_target = str(anchor["href"])
            target = urljoin(base_url, raw_target)
            try:
                normalized = AdmissionService.normalize_url(target)
            except AdmissionError:
                self._observe("LINK", base_url, f"Unsupported or malformed link observed: {target}")
                continue
            is_external = not self._is_same_domain(domain_root, normalized)
            page_links.append((normalized, is_external))

        for tag_name, count in counts.items():
            self._observe("HTML_STRUCTURE", base_url, f"Found {count} <{tag_name}> elements")
        self._observe("HTML_STRUCTURE", base_url, f"Found {len(page_links)} navigational links")
        return resources, list(dict.fromkeys(page_links))

    def _observe(self, category: str, subject: str, observation: str) -> None:
        self.db.add(
            Observation(
                scan_id=self.scan.id,
                category=category,
                subject=subject,
                observation=observation,
                classification="OBSERVED",
            )
        )


__all__ = ["CrawlerService", "FetchResult"]
