from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from uuid import UUID

import httpx
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.scan import (
    ApiEndpoint,
    HTTPResponse,
    Observation,
    Page,
    PageLink,
    ReconAsset,
    ReconEndpoint,
    ReconParameter,
    Resource,
    Scan,
)
from app.services.admission import AdmissionError, AdmissionService
from app.services.assessment import (
    credentials_headers,
    get_authorization,
    get_credentials,
    hostname_allowed,
    path_allowed,
)
from app.services.crawler import CrawlerService


class ReconAgent:
    """Normalize existing discovery evidence and perform bounded recon extensions.

    Passive mode reads public CT/DNS data and stored crawl artifacts. Active-safe mode
    adds only scope-checked, GET-only requests for robots/sitemaps and a small
    maintainable path list. It never submits forms, mutates state, or probes ports.
    """

    USER_AGENT = "WebAutopsyNetwork/0.4 (authorized recon; non-destructive)"
    CT_PRIMARY_URL = "https://api.certspotter.com/v1/issuances"
    CT_FALLBACK_URL = "https://crt.sh/"
    DNS_URL = "https://dns.google/resolve"
    URL_LITERAL_RE = re.compile(
        r"[\"'`](?P<url>(?:https?://|/)(?:[^\"'`\s<>\\]|\\.){1,2047})[\"'`]",
        re.IGNORECASE,
    )
    FETCH_RE = re.compile(
        r"(?:fetch|axios\.(?:get|post|put|patch|delete)|open)\s*\(\s*[\"'`](?P<url>[^\"'`]+)",
        re.IGNORECASE,
    )
    CLOUD_PATTERNS = (
        ("s3", re.compile(r"(?:https?://)?(?:[a-z0-9.-]+\.)?s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/[^\s\"'<>]*)?", re.IGNORECASE)),
        ("s3", re.compile(r"https?://s3\.amazonaws\.com/[a-z0-9._-]+(?:/[^\s\"'<>]*)?", re.IGNORECASE)),
        ("azure_blob", re.compile(r"https?://[a-z0-9-]+\.blob\.core\.windows\.net(?:/[^\s\"'<>]*)?", re.IGNORECASE)),
        ("gcs", re.compile(r"https?://(?:storage\.googleapis\.com/[a-z0-9._-]+|[a-z0-9._-]+\.storage\.googleapis\.com)(?:/[^\s\"'<>]*)?", re.IGNORECASE)),
    )
    SENSITIVE_PATH_RE = re.compile(
        r"/(?:\.env(?:\.|/|$)|\.git(?:/|$)|(?:config|configuration|backup|backups|debug|internal|private|secret|secrets|actuator|server-status|phpinfo|metrics)(?:/|\.|$))",
        re.IGNORECASE,
    )
    LOGIN_PATH_RE = re.compile(r"/(?:login|signin|sign-in|auth|oauth|sso|register|signup)(?:/|$)", re.IGNORECASE)
    ADMIN_PATH_RE = re.compile(r"/(?:admin|dashboard|manage|backend|control|wp-admin)(?:/|$)", re.IGNORECASE)

    def __init__(self, db: Session, scan_id: UUID) -> None:
        self.db = db
        self.scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if self.scan is None:
            raise ValueError(f"Scan {scan_id} not found")
        self.scan_id = scan_id
        self.settings = get_settings()
        self.authorization = get_authorization(db, scan_id)
        self.allowed_domains = list(self.authorization.allowed_domains or []) if self.authorization else []
        self.allowed_paths = list(self.authorization.allowed_paths or []) if self.authorization else []
        self.excluded_paths = list(self.authorization.excluded_paths or []) if self.authorization else []
        self.profile = self.scan.assessment_profile or "legacy_passive"
        self.mode = self.scan.recon_mode or "passive_only"
        self.max_requests = int((self.authorization.max_requests if self.authorization else None) or self.scan.max_requests or self.scan.max_pages)
        self.public_calls = 0
        self.max_public_calls = 12
        self.auth_headers = credentials_headers(get_credentials(db, scan_id))
        self.crawler = CrawlerService(self.db, self.scan, self.scan.requested_url)
        self._asset_cache: dict[str, ReconAsset] = {}
        self._endpoint_cache: dict[str, ReconEndpoint] = {}

    def run(self) -> dict[str, Any]:
        self._clear_previous_results()
        self._observe(
            "RECON_MODE",
            self.scan.requested_url,
            f"Recon Agent running in {self.mode} mode. Existing crawler and evidence services are reused; no destructive requests are performed.",
        )
        self._index_existing_crawl_evidence()
        self._passive_certificate_transparency()
        self._passive_dns(self._seed_hostname())
        if self.mode == "active_safe":
            self._active_safe_discovery()
        self.db.commit()
        return {
            "mode": self.mode,
            "assets": self.db.query(ReconAsset).filter(ReconAsset.scan_id == self.scan_id).count(),
            "endpoints": self.db.query(ReconEndpoint).filter(ReconEndpoint.scan_id == self.scan_id).count(),
            "parameters": self.db.query(ReconParameter).filter(ReconParameter.scan_id == self.scan_id).count(),
            "requests_used": int(self.scan.requests_used or 0),
            "max_requests": self.max_requests,
        }

    def _clear_previous_results(self) -> None:
        self.db.query(ReconParameter).filter(ReconParameter.scan_id == self.scan_id).delete(synchronize_session=False)
        self.db.query(ReconEndpoint).filter(ReconEndpoint.scan_id == self.scan_id).delete(synchronize_session=False)
        self.db.query(ReconAsset).filter(ReconAsset.scan_id == self.scan_id).delete(synchronize_session=False)
        self.db.query(Observation).filter(
            Observation.scan_id == self.scan_id,
            Observation.category.in_({"RECON_MODE", "RECON_SOURCE", "RECON_DNS", "RECON_CLASSIFICATION", "RECON_SCOPE", "RECON_CLOUD"}),
        ).delete(synchronize_session=False)
        self.db.flush()

    def _index_existing_crawl_evidence(self) -> None:
        pages = self.db.query(Page).filter(Page.scan_id == self.scan_id).all()
        responses = (
            self.db.query(HTTPResponse)
            .join(Page, HTTPResponse.page_id == Page.id)
            .filter(Page.scan_id == self.scan_id)
            .all()
        )
        response_by_page = {item.page_id: item for item in responses}
        for page in pages:
            self._record_asset(
                "page",
                page.canonical_url,
                "crawler",
                classification=self._classify_url(page.canonical_url),
                confidence=1.0,
                attributes={"page_id": str(page.id), "depth": page.depth, "status_code": page.status_code},
                evidence=["Stored Page record"],
            )
            self._record_endpoint(
                "page",
                page.canonical_url,
                "GET",
                "crawler",
                classification=self._classify_url(page.canonical_url),
                confidence=1.0,
                status_code=page.status_code,
                content_type=response_by_page.get(page.id).content_type if response_by_page.get(page.id) else None,
                page_id=page.id,
                evidence=["Stored Page and HTTPResponse records"],
            )
            response = response_by_page.get(page.id)
            if response and response.raw_body:
                self._extract_page_parameters(page, response.raw_body)
                self._extract_javascript(page, response.raw_body)
                self._detect_cloud_assets(response.raw_body, f"HTML/JavaScript on {page.canonical_url}")

        resources = (
            self.db.query(Resource)
            .join(Page, Resource.page_id == Page.id)
            .filter(Page.scan_id == self.scan_id)
            .all()
        )
        for resource in resources:
            if not resource.url:
                continue
            self._record_asset(
                "resource",
                resource.url,
                "crawler.resource",
                classification="OBSERVED",
                confidence=1.0,
                attributes={"resource_type": resource.type, "page_id": str(resource.page_id)},
                evidence=["Stored Resource record"],
            )
            self._detect_cloud_assets(resource.url, f"Resource URL observed on page {resource.page_id}")
            self._extract_query_parameters(resource.url, resource.page_id, "resource_url")

        links = (
            self.db.query(PageLink)
            .join(Page, PageLink.source_page_id == Page.id)
            .filter(Page.scan_id == self.scan_id)
            .all()
        )
        for link in links:
            self._record_asset(
                "link",
                link.target_url,
                "crawler.link",
                classification="EXTERNAL_LINK" if link.is_external else "INTERNAL_LINK",
                confidence=1.0,
                attributes={"source_page_id": str(link.source_page_id), "is_external": link.is_external},
                evidence=["Stored PageLink record"],
            )
            self._extract_query_parameters(link.target_url, link.source_page_id, "link_url")
            self._detect_cloud_assets(link.target_url, f"Link observed from page {link.source_page_id}")

        for endpoint in self.db.query(ApiEndpoint).filter(ApiEndpoint.scan_id == self.scan_id).all():
            self._record_endpoint(
                "api",
                endpoint.url_or_path,
                endpoint.http_method,
                "api_intelligence",
                classification=endpoint.classification.upper(),
                confidence=endpoint.confidence,
                content_type=endpoint.content_type,
                evidence=[endpoint.discovered_from_source],
            )
            self._extract_query_parameters(endpoint.url_or_path, None, "api_endpoint")

    def _passive_certificate_transparency(self) -> None:
        hostname = self._seed_hostname()
        if not hostname:
            return
        records: list[dict[str, Any]] = []
        primary = self._public_get(
            self.CT_PRIMARY_URL,
            params={"domain": hostname, "include_subdomains": "true", "expand": "dns_names"},
        )
        if isinstance(primary, list):
            records = primary
        else:
            fallback = self._public_get(
                self.CT_FALLBACK_URL,
                params={"q": f"%.{hostname}", "output": "json"},
            )
            if isinstance(fallback, list):
                records = fallback

        names: set[str] = set()
        for record in records[: self.settings.recon_ct_max_records]:
            raw_names = record.get("dns_names") or record.get("name_value") or []
            if isinstance(raw_names, str):
                raw_names = raw_names.splitlines()
            for raw_name in raw_names:
                name = str(raw_name).strip().lower().rstrip(".")
                if name.startswith("*."):
                    name = name[2:]
                if not name or "." not in name or not hostname_allowed(name, self.allowed_domains or [hostname]):
                    continue
                names.add(name)
        for name in sorted(names):
            self._record_asset(
                "subdomain",
                name,
                "certificate_transparency",
                classification="OBSERVED",
                confidence=0.90,
                attributes={"source_type": "certificate_transparency", "passive": True},
                evidence=["Public CT issuance DNS name"],
            )
            self._observe("RECON_SOURCE", name, "Subdomain observed in a public Certificate Transparency source.")
        self._observe(
            "RECON_SOURCE",
            hostname,
            f"Certificate Transparency returned {len(records)} bounded issuance record(s) and {len(names)} in-scope hostname(s).",
        )

    def _passive_dns(self, hostname: str | None) -> None:
        if not hostname:
            return
        types = [item.strip().upper() for item in self.settings.recon_dns_record_types.split(",") if item.strip()]
        for record_type in types:
            payload = self._public_get(self.DNS_URL, params={"name": hostname, "type": record_type})
            if not isinstance(payload, dict):
                continue
            for answer in payload.get("Answer") or []:
                data = str(answer.get("data", "")).strip()
                if not data:
                    continue
                self._record_asset(
                    "dns_record",
                    data,
                    "google_dns_over_https",
                    classification="OBSERVED",
                    confidence=1.0,
                    attributes={
                        "record_type": record_type,
                        "name": answer.get("name"),
                        "ttl": answer.get("TTL"),
                        "dns_status": payload.get("Status"),
                    },
                    evidence=["Google Public DNS JSON response"],
                    hostname=hostname,
                    scope_status="in_scope",
                )
                self._observe("RECON_DNS", hostname, f"Observed {record_type} DNS answer: {data}.")
        self._observe("RECON_SOURCE", hostname, "DNS observations collected through a public DNS-over-HTTPS source.")

    def _active_safe_discovery(self) -> None:
        candidates: list[tuple[str, str]] = []
        configured = [item.strip() for item in self.settings.recon_active_safe_path_wordlist.split(",") if item.strip()]
        for path in configured:
            candidates.append((urljoin(self.scan.requested_url, path), "safe_path_wordlist"))

        robots_url = urljoin(self.scan.requested_url, "/robots.txt")
        robots_result = self._safe_get(robots_url, "robots")
        if robots_result is not None:
            from urllib.robotparser import RobotFileParser
            robots_parser = RobotFileParser()
            robots_parser.set_url(robots_url)
            robots_parser.parse(str(robots_result.get("text") or "").splitlines())
            self.crawler.robots[(urlsplit(robots_url).hostname or "").lower().rstrip(".")] = robots_parser
        if robots_result and robots_result.get("text"):
            for line in str(robots_result["text"]).splitlines():
                if line.lower().startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    candidates.append((urljoin(robots_url, sitemap_url), "robots_sitemap"))

        seen: set[str] = set()
        for url, source in candidates[: self.settings.recon_active_safe_max_candidates]:
            normalized = self._normalize_target_url(url)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            result = self._safe_get(normalized, source)
            self._record_endpoint(
                "active_safe_candidate",
                normalized,
                "GET",
                source,
                classification=self._classify_url(normalized, result.get("status_code") if result else None),
                confidence=0.70,
                status_code=result.get("status_code") if result else None,
                content_type=result.get("content_type") if result else None,
                attributes={"request_mode": "GET-only", "destructive_action": False},
                evidence=["Bounded active-safe candidate request"],
            )
            if result and result.get("text") and self._looks_like_sitemap(normalized, result.get("content_type"), result["text"]):
                self._ingest_sitemap(normalized, result["text"], seen)

        self._observe(
            "RECON_SOURCE",
            self.scan.requested_url,
            f"Active-safe mode evaluated {len(seen)} bounded candidate URL(s); only GET requests within the recorded scope were permitted.",
        )

    def _ingest_sitemap(self, source_url: str, body: str, seen: set[str]) -> None:
        soup = BeautifulSoup(body[: self.settings.recon_active_safe_max_body_bytes], "html.parser")
        urls = [str(tag.get_text(strip=True)) for tag in soup.find_all("loc") if tag.get_text(strip=True)]
        for raw_url in urls[: self.settings.recon_active_safe_max_sitemap_urls]:
            normalized = self._normalize_target_url(raw_url)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            self._record_endpoint(
                "sitemap_url",
                normalized,
                "GET",
                source_url,
                classification=self._classify_url(normalized),
                confidence=0.85,
                attributes={"sitemap_source": source_url, "request_mode": "candidate_only"},
                evidence=["Sitemap loc element"],
            )

    def _safe_get(self, url: str, source: str) -> dict[str, Any] | None:
        normalized = self._normalize_target_url(url)
        if not normalized or not self._consume_target_request(normalized):
            return None
        if source != "robots" and urlsplit(normalized).path != "/robots.txt" and not self.crawler._robots_allowed(normalized):
            self._observe("RECON_SCOPE", normalized, "Active-safe candidate skipped because robots.txt disallowed the request.")
            return None
        hostname = (urlsplit(normalized).hostname or "").lower()
        try:
            delay_ms = self.authorization.rate_limit_per_host_ms if self.authorization else self.scan.request_delay_ms
            # A local limiter keeps active-safe requests paced even though the main crawler has finished.
            if not hasattr(self, "_active_last_request"):
                self._active_last_request: dict[str, float] = {}
            import time
            now = time.monotonic()
            wait_for = max(0.0, (int(delay_ms or 1000) / 1000) - (now - self._active_last_request.get(hostname, 0.0)))
            if wait_for:
                time.sleep(wait_for)
            self._active_last_request[hostname] = time.monotonic()
            with httpx.Client(
                timeout=self.settings.recon_passive_timeout_seconds,
                follow_redirects=False,
                headers={"User-Agent": self.USER_AGENT, "Accept": "text/html,application/xml,application/json,*/*", **self.auth_headers},
            ) as client:
                response = client.get(normalized)
            content_type = response.headers.get("content-type")
            body = response.content[: self.settings.recon_active_safe_max_body_bytes]
            text = body.decode(response.encoding or "utf-8", errors="replace")
            return {"status_code": response.status_code, "content_type": content_type, "text": text, "source": source}
        except (httpx.HTTPError, UnicodeError) as exc:
            self._observe("RECON_SOURCE", normalized, f"Active-safe request failed without retrying outside scope: {exc}")
            return {"status_code": None, "content_type": None, "text": "", "source": source, "error": str(exc)}

    def _public_get(self, url: str, params: dict[str, str]) -> Any:
        if self.public_calls >= self.max_public_calls:
            self._observe("RECON_SOURCE", url, "Public-source request cap reached; remaining passive sources were skipped.")
            return None
        self.public_calls += 1
        try:
            with httpx.Client(
                timeout=self.settings.recon_passive_timeout_seconds,
                follow_redirects=False,
                headers={"User-Agent": self.USER_AGENT, "Accept": "application/json"},
            ) as client:
                response = client.get(url, params=params)
            if response.status_code < 200 or response.status_code >= 300:
                self._observe("RECON_SOURCE", str(response.url), f"Public source returned HTTP {response.status_code}; no source data was inferred.")
                return None
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            self._observe("RECON_SOURCE", url, f"Public source unavailable; no source data was inferred: {exc}")
            return None

    def _consume_target_request(self, url: str) -> bool:
        current = int(self.scan.requests_used or 0)
        if current >= self.max_requests:
            self._observe("RECON_SCOPE", url, f"Recon request skipped because the shared maximum request budget ({self.max_requests}) was reached.")
            return False
        self.scan.requests_used = current + 1
        return True

    def _normalize_target_url(self, url: str) -> str | None:
        try:
            normalized = AdmissionService.normalize_url(url)
            parsed = urlsplit(normalized)
            hostname = (parsed.hostname or "").lower().rstrip(".")
            if not hostname_allowed(hostname, self.allowed_domains or [self._seed_hostname() or hostname]):
                self._observe("RECON_SCOPE", normalized, "Candidate was excluded because its hostname is outside the explicit allowed-domain scope.")
                return None
            if not path_allowed(normalized, self.allowed_paths, self.excluded_paths):
                self._observe("RECON_SCOPE", normalized, "Candidate was excluded because its path is outside the explicit allowed/excluded path scope.")
                return None
            AdmissionService.validate_and_resolve(
                normalized,
                assessment_profile=self.profile if self.profile in {"safe", "normal", "aggressive"} else None,
                explicit_allowlist=bool(self.allowed_domains),
            )
            return normalized
        except (AdmissionError, ValueError, TypeError) as exc:
            self._observe("RECON_SCOPE", url, f"Candidate was blocked by admission policy: {exc}")
            return None

    def _seed_hostname(self) -> str | None:
        return (urlsplit(self.scan.requested_url).hostname or "").lower().rstrip(".") or None

    def _extract_page_parameters(self, page: Page, body: str) -> None:
        self._extract_query_parameters(page.canonical_url, page.id, "page_url")
        soup = BeautifulSoup(body[: self.settings.recon_active_safe_max_body_bytes], "html.parser")
        for form in soup.find_all("form"):
            action = urljoin(page.canonical_url, str(form.get("action") or page.canonical_url))
            endpoint = self._record_endpoint(
                "form",
                action,
                str(form.get("method") or "GET").upper(),
                f"form on {page.canonical_url}",
                classification=self._classify_url(action),
                confidence=0.95,
                page_id=page.id,
                evidence=["Stored HTML form action"],
            )
            for field in form.find_all(["input", "textarea", "select"]):
                name = str(field.get("name") or "").strip()
                if name:
                    self._record_parameter(name, "form", f"form on {page.canonical_url}", endpoint, page.id, field.get("value"), 0.95, ["Stored HTML form field"])

    def _extract_javascript(self, page: Page, body: str) -> None:
        for match in self.URL_LITERAL_RE.finditer(body[: self.settings.recon_active_safe_max_body_bytes]):
            raw_url = match.group("url").replace("\\/", "/")
            if not self._looks_like_endpoint(raw_url):
                continue
            resolved = self._normalize_target_url(urljoin(page.canonical_url, raw_url))
            if not resolved:
                continue
            endpoint = self._record_endpoint(
                "javascript",
                resolved,
                "GET",
                f"JavaScript on {page.canonical_url}",
                classification=self._classify_url(resolved),
                confidence=0.75,
                page_id=page.id,
                evidence=["Quoted URL literal in stored page body"],
            )
            self._extract_query_parameters(resolved, page.id, "javascript_url", endpoint)

    def _extract_query_parameters(self, url: str, page_id: UUID | None, source: str, endpoint: ReconEndpoint | None = None) -> None:
        try:
            query = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        except ValueError:
            return
        for name, value in query:
            if name.strip():
                self._record_parameter(name, "query", source, endpoint, page_id, value, 0.90, [f"Observed query string in {url}"], identity=url)

    def _record_parameter(self, name: str, location: str, source: str, endpoint: ReconEndpoint | None, page_id: UUID | None, example_value: Any, confidence: float, evidence: list[str], identity: str | None = None) -> ReconParameter:
        endpoint_key = str(endpoint.id) if endpoint else "-"
        dedupe = self._hash_key("parameter", name.lower(), location, endpoint_key, str(page_id or "-"), identity or source)
        existing = self.db.query(ReconParameter).filter(ReconParameter.scan_id == self.scan_id, ReconParameter.dedupe_key == dedupe).first()
        if existing:
            return existing
        parameter = ReconParameter(
            scan_id=self.scan_id,
            endpoint_id=endpoint.id if endpoint else None,
            page_id=page_id,
            name=name[:255],
            location=location,
            source=source,
            discovery_mode=self.mode,
            classification="INFERRED",
            confidence=confidence,
            scope_status="in_scope",
            example_value=str(example_value)[:1024] if example_value is not None else None,
            evidence=evidence,
            dedupe_key=dedupe,
        )
        self.db.add(parameter)
        return parameter

    def _record_asset(self, asset_type: str, value: str, source: str, *, classification: str, confidence: float, attributes: dict[str, Any] | None = None, evidence: list[str] | None = None, hostname: str | None = None, scope_status: str | None = None) -> ReconAsset:
        value = str(value)[:2048]
        dedupe = self._hash_key("asset", asset_type, value.lower())
        scope_status = scope_status or self._scope_status(value)
        existing = self._asset_cache.get(dedupe) or self.db.query(ReconAsset).filter(ReconAsset.scan_id == self.scan_id, ReconAsset.dedupe_key == dedupe).first()
        merged_attributes = dict(existing.attributes or {}) if existing else {}
        merged_attributes.update(attributes or {})
        sources = list(merged_attributes.get("sources") or [])
        if source not in sources:
            sources.append(source)
        merged_attributes["sources"] = sources[:10]
        if existing:
            existing.confidence = max(existing.confidence, confidence)
            existing.attributes = merged_attributes
            existing.evidence = list(dict.fromkeys([*(existing.evidence or []), *(evidence or [])]))
            self._asset_cache[dedupe] = existing
            return existing
        asset = ReconAsset(
            scan_id=self.scan_id,
            asset_type=asset_type,
            value=value,
            hostname=hostname or self._asset_hostname(value),
            source=source,
            discovery_mode=self.mode,
            classification=classification,
            scope_status=scope_status,
            confidence=confidence,
            attributes=merged_attributes,
            evidence=evidence or [],
            dedupe_key=dedupe,
        )
        self.db.add(asset)
        self._asset_cache[dedupe] = asset
        if scope_status != "in_scope":
            self._observe("RECON_SCOPE", value, f"Observed asset retained as {scope_status}; no active request will be made outside scope.")
        return asset

    def _record_endpoint(self, endpoint_kind: str, url: str, method: str, source: str, *, classification: str, confidence: float, status_code: int | None = None, content_type: str | None = None, page_id: UUID | None = None, attributes: dict[str, Any] | None = None, evidence: list[str] | None = None) -> ReconEndpoint:
        url = str(url)[:2048]
        dedupe = self._hash_key("endpoint", endpoint_kind, url.lower(), method.upper())
        existing = self._endpoint_cache.get(dedupe) or self.db.query(ReconEndpoint).filter(ReconEndpoint.scan_id == self.scan_id, ReconEndpoint.dedupe_key == dedupe).first()
        scope_status = self._scope_status(url)
        if existing:
            existing.confidence = max(existing.confidence, confidence)
            existing.status_code = status_code if status_code is not None else existing.status_code
            existing.content_type = content_type or existing.content_type
            existing.evidence = list(dict.fromkeys([*(existing.evidence or []), *(evidence or [])]))
            self._endpoint_cache[dedupe] = existing
            return existing
        endpoint = ReconEndpoint(
            scan_id=self.scan_id,
            endpoint_kind=endpoint_kind,
            url_or_path=url,
            http_method=method.upper(),
            source=source,
            discovery_mode=self.mode,
            classification=classification,
            confidence=confidence,
            scope_status=scope_status,
            status_code=status_code,
            content_type=content_type,
            page_id=page_id,
            attributes=attributes or {},
            evidence=evidence or [],
            dedupe_key=dedupe,
        )
        self.db.add(endpoint)
        self.db.flush()
        self._endpoint_cache[dedupe] = endpoint
        return endpoint

    def _detect_cloud_assets(self, text: str, source: str) -> None:
        for asset_type, pattern in self.CLOUD_PATTERNS:
            for match in pattern.finditer(text[: self.settings.recon_active_safe_max_body_bytes]):
                value = match.group(0).rstrip(".,);]")
                self._record_asset(
                    "cloud_public_asset",
                    value,
                    "cloud_signature",
                    classification="PUBLIC_ASSET_CANDIDATE",
                    confidence=0.90,
                    attributes={"provider_style": asset_type, "limitation": "Observed URL pattern is not proof of public read access."},
                    evidence=[source, f"Maintainable cloud signature matched: {asset_type}"],
                )
                self._observe("RECON_CLOUD", value, f"Observed a {asset_type} style public-cloud asset URL; access was not tested.")

    def _classify_url(self, url: str, status_code: int | None = None) -> str:
        path = urlsplit(url).path.lower()
        if self.SENSITIVE_PATH_RE.search(path):
            return "SENSITIVE_PATH"
        if self.ADMIN_PATH_RE.search(path):
            return "ADMIN_PATH"
        if self.LOGIN_PATH_RE.search(path):
            return "LOGIN_PATH"
        if status_code is not None and status_code == 404:
            return "NOT_FOUND"
        if status_code is not None and 200 <= status_code < 400:
            return "OBSERVED_AVAILABLE"
        return "OBSERVED"

    def _looks_like_endpoint(self, raw_url: str) -> bool:
        value = raw_url.lower()
        return value.startswith(("http://", "https://", "/")) and (
            "/api" in value or "/v1" in value or "/v2" in value or "/graphql" in value or "/rpc" in value or "openapi" in value or "swagger" in value or "?" in value
        )

    @staticmethod
    def _looks_like_sitemap(url: str, content_type: str | None, text: str) -> bool:
        return "sitemap" in url.lower() or "xml" in (content_type or "").lower() or "<urlset" in text.lower() or "<sitemapindex" in text.lower()

    def _scope_status(self, value: str) -> str:
        hostname = self._asset_hostname(value)
        if hostname and self.allowed_domains and not hostname_allowed(hostname, self.allowed_domains):
            return "out_of_scope"
        if value.startswith(("http://", "https://")) and not path_allowed(value, self.allowed_paths, self.excluded_paths):
            return "excluded_path"
        return "in_scope"

    @staticmethod
    def _asset_hostname(value: str) -> str | None:
        parsed = urlsplit(value if "://" in value else f"https://{value}")
        return (parsed.hostname or "").lower().rstrip(".") or None

    @staticmethod
    def _hash_key(*parts: str) -> str:
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

    def _observe(self, category: str, subject: str, observation: str) -> None:
        self.db.add(
            Observation(
                scan_id=self.scan_id,
                category=category,
                subject=subject[:2048],
                observation=observation,
                classification="OBSERVED",
            )
        )


__all__ = ["ReconAgent"]
