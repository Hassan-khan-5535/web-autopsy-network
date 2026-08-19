from __future__ import annotations

import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from threading import Lock
from typing import Any

from app.services.assessment import credentials_headers, get_authorization, get_credentials, hostname_allowed, path_allowed
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser
from uuid import UUID

import httpx
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.scan import Header, HTTPResponse, Observation, Page, PageLink, Resource, Scan
from app.services.admission import AdmissionError, AdmissionService
from app.services.scanner_security import ScannerSecurityError, bounded_headers, bounded_html_body, revalidate_egress, redact_sensitive_text


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
    body_truncated: bool = False
    error: str | None = None


class RequestRateLimiter:
    def __init__(self, delay_ms: int) -> None:
        self.delay_seconds = max(delay_ms, 0) / 1000
        self._lock = Lock()
        self._last_request_at: dict[str, float] = {}

    def wait(self, hostname: str) -> None:
        host = hostname.lower().rstrip(".")
        with self._lock:
            now = time.monotonic()
            remaining = self.delay_seconds - (now - self._last_request_at.get(host, 0.0))
            if remaining > 0:
                time.sleep(remaining)
            self._last_request_at[host] = time.monotonic()


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
        self.authorization = get_authorization(db, scan.id)
        self.assessment_profile = (self.authorization.assessment_profile if self.authorization else None) or scan.assessment_profile or "legacy_passive"
        self.allowed_domains = list(self.authorization.allowed_domains or []) if self.authorization else []
        self.allowed_paths = list(self.authorization.allowed_paths or []) if self.authorization else []
        self.excluded_paths = list(self.authorization.excluded_paths or []) if self.authorization else []
        self.max_requests = int((self.authorization.max_requests if self.authorization else None) or scan.max_requests or scan.max_pages)
        self.request_count = min(int(scan.requests_used or 0), self.max_requests)
        self.request_count_lock = Lock()
        self.auth_headers = credentials_headers(get_credentials(db, scan.id))
        self.rate_limiter = RequestRateLimiter(
            self.authorization.rate_limit_per_host_ms if self.authorization else scan.request_delay_ms
        )
        settings = get_settings()
        allowed_override_profiles = {item.strip() for item in settings.assessment_robots_override_profiles.split(",") if item.strip()}
        self.robots_override = bool(
            self.authorization
            and self.authorization.robots_override
            and self.assessment_profile in allowed_override_profiles
        )
        self.robots: dict[str, RobotFileParser | None] = {}
        self.robots_errors: set[str] = set()
        self.timeout = httpx.Timeout(settings.scanner_read_timeout_seconds, connect=settings.scanner_connect_timeout_seconds)
        self.max_redirects = min(self.MAX_REDIRECTS, settings.scanner_max_redirects)
        self.max_body_bytes = min(self.MAX_BODY_BYTES, settings.scanner_max_response_bytes)

    def crawl(self) -> None:
        self.scan.state = "COLLECTING"
        self.db.commit()

        try:
            seed_url, _ = self._validate_and_resolve(self.seed_url)
            domain_root = seed_url
            if not self._in_scope(seed_url):
                raise AdmissionError("Seed URL is outside the recorded assessment scope.")
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
                    if not self._in_scope(candidate_url):
                        self._observe(
                            "CRAWL_POLICY",
                            candidate_url,
                            "URL was outside the recorded allowed-domain/path scope and was not fetched.",
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
                                admitted_url, _ = self._validate_and_resolve(target_url)
                            except AdmissionError as exc:
                                self._observe(
                                    "CRAWL_ADMISSION",
                                    target_url,
                                    f"Discovered URL blocked before fetch: {exc}",
                                )
                                continue
                            if not self._in_scope(admitted_url):
                                self._observe(
                                    "CRAWL_POLICY",
                                    admitted_url,
                                    "Discovered URL was outside the recorded allowed-domain/path scope and was not fetched.",
                                )
                                continue
                            queue.append((admitted_url, next_depth, page.id))

                self.scan.requests_used = self.request_count
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
                f"Fetched {scheduled_pages} page(s), consumed {self.request_count} request slot(s), with max depth {self.scan.max_depth}.",
            )
            self.scan.state = "COMPLETED"
            self.scan.requests_used = self.request_count
            self.db.commit()
        except Exception as exc:
            self.scan.state = "FAILED"
            self.scan.error_reason = str(exc)
            self.scan.requests_used = self.request_count
            self.db.commit()

    def _validate_and_resolve(self, url: str) -> tuple[str, str]:
        kwargs = {
            "assessment_profile": self.assessment_profile if self.assessment_profile in {"safe", "normal", "aggressive"} else None,
            "explicit_allowlist": bool(self.allowed_domains),
        }
        try:
            return AdmissionService.validate_and_resolve(url, **kwargs)
        except TypeError as exc:
            if "unexpected keyword argument" not in str(exc):
                raise
            return AdmissionService.validate_and_resolve(url)

    def _is_same_domain(self, domain_root: str, candidate_url: str) -> bool:
        return AdmissionService.same_domain(domain_root, candidate_url, self.same_domain_mode)

    def _in_scope(self, url: str) -> bool:
        if self.allowed_domains:
            hostname = (urlsplit(url).hostname or "").lower().rstrip(".")
            if not hostname_allowed(hostname, self.allowed_domains):
                return False
        return path_allowed(url, self.allowed_paths, self.excluded_paths)

    def _try_consume_request(self, url: str) -> bool:
        with self.request_count_lock:
            if self.request_count >= self.max_requests:
                self._observe(
                    "CRAWL_LIMIT",
                    url,
                    f"Maximum request budget reached: {self.max_requests}.",
                )
                return False
            self.request_count += 1
            return True

    def _robots_allowed(self, url: str) -> bool:
        if self.robots_override:
            self._observe("ROBOTS", url, "robots.txt override was explicitly authorized by deployment policy.")
            return True
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower()
        if hostname in self.robots:
            parser = self.robots[hostname]
            return parser is None or parser.can_fetch(self.USER_AGENT, url)

        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            admitted_robots_url, _ = self._validate_and_resolve(robots_url)
            if not self._try_consume_request(admitted_robots_url):
                return False
            self.rate_limiter.wait(hostname)
            with httpx.Client(
                timeout=self.TIMEOUT,
                follow_redirects=False,
                headers={"User-Agent": self.USER_AGENT, **self.auth_headers},
            ) as client:
                response = client.get(admitted_robots_url)
                if 300 <= response.status_code < 400 and response.headers.get("location"):
                    redirect_url = urljoin(admitted_robots_url, response.headers["location"])
                    redirect_url, _ = self._validate_and_resolve(redirect_url)
                    if not self._is_same_domain(url, redirect_url):
                        raise AdmissionError("robots.txt redirect leaves the crawl domain")
                    if not self._try_consume_request(redirect_url):
                        return False
                    self.rate_limiter.wait(hostname)
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
        if not self._try_consume_request(requested_url):
            return FetchResult(
                requested_url=requested_url,
                final_url=requested_url,
                status_code=None,
                content_type=None,
                elapsed_ms=0.0,
                headers=[],
                body="",
                redirects=[],
                error=f"Maximum request budget reached: {self.max_requests}",
            )
        self.rate_limiter.wait(urlsplit(requested_url).hostname or "")
        current_url = requested_url
        redirects: list[tuple[str, str]] = []
        started_at = time.perf_counter()
        try:
            for _ in range(self.max_redirects + 1):
                current_url = revalidate_egress(
                    current_url, assessment_profile=self.assessment_profile if self.assessment_profile in {"safe", "normal", "aggressive"} else None,
                    explicit_allowlist=bool(self.allowed_domains),
                )
                with httpx.Client(
                    timeout=self.timeout,
                    follow_redirects=False,
                    headers={
                        "User-Agent": self.USER_AGENT,
                        "Accept": "text/html,application/xhtml+xml",
                        **self.auth_headers,
                    },
                ) as request_client, request_client.stream("GET", current_url) as response:
                    headers = bounded_headers(response, get_settings().scanner_max_response_header_bytes)
                    if 300 <= response.status_code < 400 and response.headers.get("location"):
                        redirect_url = urljoin(current_url, response.headers["location"])
                        redirect_url = revalidate_egress(
                            redirect_url, assessment_profile=self.assessment_profile if self.assessment_profile in {"safe", "normal", "aggressive"} else None,
                            explicit_allowlist=bool(self.allowed_domains),
                        )
                        if not self._is_same_domain(domain_root, redirect_url) or not self._in_scope(redirect_url):
                            raise AdmissionError("Redirect leaves the allowed crawl scope and was not fetched.")
                        if not self._try_consume_request(redirect_url):
                            raise AdmissionError("Maximum request budget reached.")
                        self.rate_limiter.wait(urlsplit(redirect_url).hostname or "")
                        redirects.append((current_url, redirect_url))
                        current_url = redirect_url
                        continue
                    content_type = response.headers.get("content-type")
                    body, body_truncated = bounded_html_body(response, self.max_body_bytes)
                    final_url = AdmissionService.normalize_url(str(response.url))
                    final_url = revalidate_egress(
                        final_url, assessment_profile=self.assessment_profile if self.assessment_profile in {"safe", "normal", "aggressive"} else None,
                        explicit_allowlist=bool(self.allowed_domains),
                    )
                    if not self._in_scope(final_url):
                        raise AdmissionError("Response final URL is outside the allowed crawl scope.")
                    return FetchResult(
                        requested_url=requested_url, final_url=final_url, status_code=response.status_code,
                        content_type=content_type, elapsed_ms=(time.perf_counter() - started_at) * 1000,
                        headers=headers, body=body, redirects=redirects, body_truncated=body_truncated,
                    )
            raise AdmissionError(f"Exceeded maximum redirects ({self.max_redirects})")
        except (AdmissionError, ScannerSecurityError, httpx.RequestError, UnicodeError) as exc:
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
            body_truncated=result.body_truncated,
            redirect_chain=[[source_url, target_url] for source_url, target_url in result.redirects],
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
        self.db.commit()

        try:
            from app.services.browser_client import BrowserWorkerClient

            BrowserWorkerClient(self.db).analyze_page(self.scan.id, page.id, result.final_url)
        except Exception as exc:
            self._observe(
                "BROWSER_ANALYSIS",
                page.canonical_url,
                f"Browser worker integration degraded: {exc}",
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
            elements = soup.find_all(tag_name, limit=get_settings().scanner_max_html_elements)
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

        for anchor in soup.find_all("a", href=True, limit=get_settings().scanner_max_html_elements):
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
                observation=redact_sensitive_text(observation),
                classification="OBSERVED",
            )
        )


__all__ = ["CrawlerService", "FetchResult"]
