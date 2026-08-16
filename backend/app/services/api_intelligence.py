from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin
from uuid import UUID

from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.models.scan import ApiEndpoint, HTTPResponse, Observation, Page, Resource


class ApiIntelligenceAgent:
    """Agent that statically analyzes stored evidence to identify candidate API endpoints."""

    CLASSIFICATION = "inferred"

    API_PATH_PATTERNS = [
        re.compile(
            r"/(?:api|v1|v2|v3|v4|graphql|rest|endpoints|services|json|rpc)/",
            re.IGNORECASE,
        ),
        re.compile(r"\.(?:json|xml|graphql)$", re.IGNORECASE),
        re.compile(r"/(?:api|v1|v2|v3|v4|graphql|rest|endpoints|services)$", re.IGNORECASE),
    ]

    FETCH_RE = re.compile(
        r"""fetch\s*\(\s*['"`]([^'"`]+)['"`](?:\s*,\s*\{[^}]*?method\s*:\s*['"`](GET|POST|PUT|DELETE|PATCH)['"`])?""",
        re.IGNORECASE | re.DOTALL,
    )
    AXIOS_RE = re.compile(
        r"""axios(?:\.(get|post|put|delete|patch))?\s*\(\s*['"`]([^'"`]+)['"`]""",
        re.IGNORECASE,
    )
    AJAX_RE = re.compile(
        r"""\$\.(?:ajax|get|post)\s*\(\s*(?:['"`]([^'"`]+)['"`]|\{[^}]*?url\s*:\s*['"`]([^'"`]+)['"`])""",
        re.IGNORECASE | re.DOTALL,
    )
    XHR_RE = re.compile(
        r"""open\s*\(\s*['"`](GET|POST|PUT|DELETE|PATCH)['"`]\s*,\s*['"`]([^'"`]+)['"`]""",
        re.IGNORECASE,
    )

    def __init__(self, db: Session, scan_id: UUID) -> None:
        self.db = db
        self.scan_id = scan_id

    def analyze(self) -> list[ApiEndpoint]:
        pages = self.db.query(Page).filter(Page.scan_id == self.scan_id).all()
        page_urls = {page.id: page.canonical_url for page in pages}

        resources = (
            self.db.query(Resource)
            .join(Page, Resource.page_id == Page.id)
            .filter(Page.scan_id == self.scan_id)
            .all()
        )

        http_responses = (
            self.db.query(HTTPResponse)
            .join(Page, HTTPResponse.page_id == Page.id)
            .filter(Page.scan_id == self.scan_id)
            .all()
        )

        candidates: dict[tuple[str, str], dict[str, Any]] = {}

        # 1. Analyze HTML Form Actions
        for resp in http_responses:
            base_url = resp.final_url or page_urls.get(resp.page_id, "")
            if not resp.raw_body:
                continue
            if (
                resp.content_type
                and "html" not in resp.content_type.lower()
                and "<form" not in resp.raw_body.lower()
            ):
                continue
            soup = BeautifulSoup(resp.raw_body, "html.parser")

            for form in soup.find_all("form"):
                raw_action = form.get("action")
                if not raw_action:
                    continue
                action_url = urljoin(base_url, str(raw_action))
                if self._is_api_candidate(action_url):
                    method = str(form.get("method", "GET")).upper()
                    key = (action_url, method)
                    if key not in candidates or candidates[key]["confidence"] < 0.95:
                        candidates[key] = {
                            "url_or_path": action_url,
                            "http_method": method,
                            "content_type": "application/x-www-form-urlencoded",
                            "confidence": 0.95,
                            "source": f"Form action on {base_url}",
                        }

        # 2. Analyze Resources (Scripts / Assets)
        for res in resources:
            if not res.url:
                continue
            if self._is_api_candidate(res.url):
                content_type = "application/json" if res.url.endswith(".json") else None
                key = (res.url, "GET")
                if key not in candidates:
                    candidates[key] = {
                        "url_or_path": res.url,
                        "http_method": "GET",
                        "content_type": content_type,
                        "confidence": 0.85,
                        "source": f"Resource tag <{res.type}> on page",
                    }

        # 3. Analyze Body Text / Script Content for Fetch / Axios / Ajax / XHR
        for resp in http_responses:
            base_url = resp.final_url or page_urls.get(resp.page_id, "")
            body = resp.raw_body or ""
            if not body:
                continue

            # Fetch regex
            for match in self.FETCH_RE.finditer(body):
                path, method = match.group(1), match.group(2)
                resolved = urljoin(base_url, path)
                if self._is_api_candidate(resolved):
                    http_method = (method or "GET").upper()
                    key = (resolved, http_method)
                    if key not in candidates:
                        candidates[key] = {
                            "url_or_path": resolved,
                            "http_method": http_method,
                            "content_type": "application/json",
                            "confidence": 0.85,
                            "source": f"Fetch API call pattern in {base_url}",
                        }

            # Axios regex
            for match in self.AXIOS_RE.finditer(body):
                method, path = match.group(1), match.group(2)
                resolved = urljoin(base_url, path)
                if self._is_api_candidate(resolved):
                    http_method = (method or "GET").upper()
                    key = (resolved, http_method)
                    if key not in candidates:
                        candidates[key] = {
                            "url_or_path": resolved,
                            "http_method": http_method,
                            "content_type": "application/json",
                            "confidence": 0.85,
                            "source": f"Axios request pattern in {base_url}",
                        }

            # XHR regex
            for match in self.XHR_RE.finditer(body):
                method, path = match.group(1), match.group(2)
                resolved = urljoin(base_url, path)
                if self._is_api_candidate(resolved):
                    http_method = method.upper()
                    key = (resolved, http_method)
                    if key not in candidates:
                        candidates[key] = {
                            "url_or_path": resolved,
                            "http_method": http_method,
                            "content_type": "application/json",
                            "confidence": 0.80,
                            "source": f"XMLHttpRequest pattern in {base_url}",
                        }

        # Clear existing ApiEndpoint and Observation records for this scan
        self.db.query(ApiEndpoint).filter(ApiEndpoint.scan_id == self.scan_id).delete(
            synchronize_session=False
        )
        self.db.query(Observation).filter(
            Observation.scan_id == self.scan_id,
            Observation.category == "API_INTELLIGENCE",
        ).delete(synchronize_session=False)
        self.db.flush()

        results: list[ApiEndpoint] = []
        for candidate in sorted(
            candidates.values(), key=lambda c: (c["url_or_path"], c["http_method"])
        ):
            endpoint = ApiEndpoint(
                scan_id=self.scan_id,
                url_or_path=candidate["url_or_path"],
                http_method=candidate["http_method"],
                content_type=candidate["content_type"],
                classification=self.CLASSIFICATION,
                confidence=candidate["confidence"],
                discovered_from_source=candidate["source"],
            )
            self.db.add(endpoint)
            results.append(endpoint)

            self.db.add(
                Observation(
                    scan_id=self.scan_id,
                    category="API_INTELLIGENCE",
                    subject=candidate["url_or_path"],
                    observation=(
                        f"Discovered candidate API endpoint '{candidate['url_or_path']}' "
                        f"[{candidate['http_method']}] via {candidate['source']}."
                    ),
                    classification="INFERRED",
                )
            )

        self.db.commit()
        return results

    def _is_api_candidate(self, url_or_path: str) -> bool:
        if (
            not url_or_path
            or url_or_path.startswith("data:")
            or url_or_path.startswith("javascript:")
        ):
            return False
        return any(pattern.search(url_or_path) for pattern in self.API_PATH_PATTERNS)


__all__ = ["ApiIntelligenceAgent"]
