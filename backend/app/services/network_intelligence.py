from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.scan import Dependency, Observation, Page, PageLink, Resource, Scan, Technology, Website


class NetworkIntelligenceAgent:
    """Agent that builds external domain relationship graph and maps categories using Phase 4 tech detections."""

    CLASSIFICATION = "inferred"

    DOMAIN_CATEGORY_KEYWORDS = {
        "google-analytics": "Analytics",
        "googletagmanager": "Analytics",
        "analytics": "Analytics",
        "mixpanel": "Analytics",
        "segment": "Analytics",
        "hotjar": "Analytics",
        "clarity.ms": "Analytics",
        "fonts.googleapis": "Fonts",
        "use.typekit": "Fonts",
        "fontawesome": "Fonts",
        "cdnjs": "CDN",
        "jsdelivr": "CDN",
        "unpkg": "CDN",
        "cloudflare": "CDN",
        "fastly": "CDN",
        "akamai": "CDN",
        "doubleclick": "Advertising",
        "googlesyndication": "Advertising",
        "facebook.net": "Advertising",
        "auth0": "Authentication",
        "clerk": "Authentication",
        "stripe": "Payments",
        "paypal": "Payments",
    }

    def __init__(self, db: Session, scan_id: UUID) -> None:
        self.db = db
        self.scan_id = scan_id

    def analyze(self) -> list[Dependency]:
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            return []

        website = self.db.query(Website).filter(Website.id == scan.website_id).first()
        seed_hostname = (website.canonical_origin if website else "").lower()
        if not seed_hostname and scan.requested_url:
            seed_hostname = (urlsplit(scan.requested_url).hostname or "").lower()

        # Fetch Phase 4 detected technologies
        technologies = (
            self.db.query(Technology)
            .filter(Technology.scan_id == self.scan_id)
            .all()
        )
        tech_categories = {tech.canonical_name.lower(): tech.category for tech in technologies}

        # Gather external resource URLs
        resources = (
            self.db.query(Resource)
            .join(Page, Resource.page_id == Page.id)
            .filter(Page.scan_id == self.scan_id)
            .all()
        )

        # Gather external page links
        page_links = (
            self.db.query(PageLink)
            .join(Page, PageLink.source_page_id == Page.id)
            .filter(Page.scan_id == self.scan_id)
            .filter(PageLink.is_external == True)
            .all()
        )

        domain_samples: dict[str, set[str]] = {}
        domain_counts: dict[str, int] = {}

        def record_external_url(url: str | None) -> None:
            if not url or url.startswith("data:") or url.startswith("javascript:"):
                return
            parsed = urlsplit(url)
            hostname = (parsed.hostname or "").lower()
            if not hostname or hostname == seed_hostname:
                return
            domain_counts[hostname] = domain_counts.get(hostname, 0) + 1
            domain_samples.setdefault(hostname, set()).add(url)

        for res in resources:
            record_external_url(res.url)

        for link in page_links:
            record_external_url(link.target_url)

        # Delete old Dependency & Observation records for this scan
        self.db.query(Dependency).filter(Dependency.scan_id == self.scan_id).delete(synchronize_session=False)
        self.db.query(Observation).filter(
            Observation.scan_id == self.scan_id,
            Observation.category == "NETWORK_INTELLIGENCE",
        ).delete(synchronize_session=False)
        self.db.flush()

        results: list[Dependency] = []
        for domain, count in sorted(domain_counts.items()):
            category, confidence = self._categorize_domain(domain, tech_categories)
            sample_urls = sorted(list(domain_samples.get(domain, set())))[:5]

            dep = Dependency(
                scan_id=self.scan_id,
                domain=domain,
                category=category,
                classification=self.CLASSIFICATION,
                confidence=confidence,
                reference_count=count,
                sample_resource_urls=sample_urls,
            )
            self.db.add(dep)
            results.append(dep)

            self.db.add(
                Observation(
                    scan_id=self.scan_id,
                    category="NETWORK_INTELLIGENCE",
                    subject=domain,
                    observation=f"External domain '{domain}' observed ({count} references, category: {category}, confidence: {confidence}).",
                    classification="INFERRED",
                )
            )

        self.db.commit()
        return results

    def _categorize_domain(
        self, domain: str, tech_categories: dict[str, str]
    ) -> tuple[str, float]:
        # 1. Match against Phase 4 Technology detections
        for tech_name, category in tech_categories.items():
            if tech_name in domain or domain.replace("www.", "") in tech_name:
                return category, 0.95

        # 2. Match against built-in keyword rules
        for keyword, category in self.DOMAIN_CATEGORY_KEYWORDS.items():
            if keyword in domain:
                return category, 0.85

        # 3. Default fallback
        return "Unclassified External Dependency", 0.50


__all__ = ["NetworkIntelligenceAgent"]
