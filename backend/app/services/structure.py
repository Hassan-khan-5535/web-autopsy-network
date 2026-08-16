from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlsplit
from uuid import UUID

from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.models.scan import HTTPResponse, Observation, Page, PageLink, Scan


class StructureAgent:
    """Analyze page hierarchy, link structures, forms, and inferred page types."""

    def __init__(self, db: Session, scan_id: UUID) -> None:
        self.db = db
        self.scan_id = scan_id

    def analyze(self) -> dict[str, Any]:
        pages = (
            self.db.query(Page)
            .filter(Page.scan_id == self.scan_id)
            .order_by(Page.depth, Page.canonical_url)
            .all()
        )

        page_links = (
            self.db.query(PageLink)
            .join(Page, PageLink.source_page_id == Page.id)
            .filter(Page.scan_id == self.scan_id)
            .all()
        )

        # 1. Aggregate Link Summary
        internal_links = [link for link in page_links if not link.is_external]
        external_links = [link for link in page_links if link.is_external]

        link_summary = {
            "total_internal_links": len(internal_links),
            "total_external_links": len(external_links),
            "total_links": len(page_links),
        }

        # 2. Build Site Tree Hierarchy
        children_by_parent_id: dict[UUID | None, list[Page]] = {}
        for page in pages:
            children_by_parent_id.setdefault(page.discovered_from_page_id, []).append(page)

        def build_tree_node(page: Page) -> dict[str, Any]:
            children = children_by_parent_id.get(page.id, [])
            return {
                "id": str(page.id),
                "url": page.canonical_url,
                "title": page.title,
                "depth": page.depth,
                "status_code": page.status_code,
                "children": [build_tree_node(child) for child in children],
            }

        root_pages = [
            page for page in pages if page.depth == 0 or page.discovered_from_page_id is None
        ]
        site_tree = [build_tree_node(root) for root in root_pages]

        # 3. Process HTTP Responses for Form Inventory and Page Type Signals
        http_responses = (
            self.db.query(HTTPResponse)
            .join(Page, HTTPResponse.page_id == Page.id)
            .filter(Page.scan_id == self.scan_id)
            .all()
        )
        responses_by_page_id = {resp.page_id: resp for resp in http_responses}

        form_inventory: list[dict[str, Any]] = []
        page_types: list[dict[str, Any]] = []

        for page in pages:
            resp = responses_by_page_id.get(page.id)
            body = resp.raw_body if resp and resp.raw_body else ""
            soup = BeautifulSoup(body, "html.parser") if body else None

            # Process forms
            page_forms: list[dict[str, Any]] = []
            if soup:
                for form in soup.find_all("form"):
                    raw_action = form.get("action", "")
                    action_url = (
                        urljoin(page.canonical_url, str(raw_action))
                        if raw_action
                        else page.canonical_url
                    )
                    method = str(form.get("method", "GET")).upper()

                    fields: list[dict[str, Any]] = []
                    for input_tag in form.find_all(["input", "textarea", "select", "button"]):
                        fields.append(
                            {
                                "tag": input_tag.name,
                                "name": input_tag.get("name"),
                                "type": input_tag.get(
                                    "type",
                                    "text" if input_tag.name == "input" else input_tag.name,
                                ),
                                "required": input_tag.has_attr("required"),
                                "placeholder": input_tag.get("placeholder"),
                            }
                        )

                    form_data = {
                        "page_id": str(page.id),
                        "page_url": page.canonical_url,
                        "action": action_url,
                        "method": method,
                        "name": form.get("name"),
                        "id": form.get("id"),
                        "fields": fields,
                    }
                    form_inventory.append(form_data)
                    page_forms.append(form_data)

            # Infer page type
            inferred_type, confidence, reason = self._infer_page_type(page, soup, page_forms)
            page_types.append(
                {
                    "page_id": str(page.id),
                    "url": page.canonical_url,
                    "inferred_type": inferred_type,
                    "classification": "inferred",
                    "confidence": confidence,
                    "reason": reason,
                }
            )

            # Record Observation for inferred page type
            self._observe(
                category="STRUCTURE",
                subject=page.canonical_url,
                observation=(
                    f"Inferred page type '{inferred_type}' with confidence "
                    f"{confidence}: {reason}"
                ),
                classification="INFERRED",
            )

        # Record Link Summary Observation
        self._observe(
            category="STRUCTURE",
            subject=self.scan_id_subject(),
            observation=(
                f"Site link summary: {link_summary['total_internal_links']} internal links, "
                f"{link_summary['total_external_links']} external links across "
                f"{len(pages)} crawled pages."
            ),
            classification="OBSERVED",
        )

        return {
            "site_tree": site_tree,
            "link_summary": link_summary,
            "form_inventory": form_inventory,
            "page_types": page_types,
        }

    def _infer_page_type(
        self, page: Page, soup: BeautifulSoup | None, page_forms: list[dict[str, Any]]
    ) -> tuple[str, float, str]:
        path = urlsplit(page.canonical_url).path.lower().rstrip("/")

        if page.depth == 0 or path in ("", "/", "/index.html", "/index.php"):
            return "homepage", 0.95, "Root domain URL or depth 0 entry point."

        if re.search(
            r"/(contact|support|help|feedback|inquire|reach-us|login|signin|register|signup)",
            path,
        ):
            return (
                "contact_or_form",
                0.90,
                f"URL path '{path}' matches contact or authentication keyword pattern.",
            )

        if any(
            any(
                f.get("type") in ("password", "email")
                or f.get("name") in ("email", "username", "message")
                for f in form.get("fields", [])
            )
            for form in page_forms
        ):
            return (
                "contact_or_form",
                0.90,
                "Observed input fields matching contact/login form attributes.",
            )

        if re.search(r"/(blog|article|news|posts|story|p/|entry|read)/", path) or re.search(
            r"/\d{4}/\d{2}/", path
        ):
            return (
                "article_or_content",
                0.85,
                f"URL path '{path}' matches article or blog pattern.",
            )

        if re.search(r"/(products|shop|catalog|category|store|items|collection)/", path):
            return (
                "catalog_or_listing",
                0.85,
                f"URL path '{path}' matches product/catalog listing pattern.",
            )

        if re.search(r"/(docs|api|developer|sdk|reference|swagger|openapi)/", path):
            return (
                "documentation_or_api",
                0.90,
                f"URL path '{path}' matches documentation or API endpoint pattern.",
            )

        return "generic_page", 0.50, "No specialized page type pattern matched."

    def scan_id_subject(self) -> str:
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        return scan.requested_url if scan else str(self.scan_id)

    def _observe(
        self,
        category: str,
        subject: str,
        observation: str,
        classification: str = "OBSERVED",
    ) -> None:
        self.db.add(
            Observation(
                scan_id=self.scan_id,
                category=category,
                subject=subject,
                observation=observation,
                classification=classification,
            )
        )


__all__ = ["StructureAgent"]
