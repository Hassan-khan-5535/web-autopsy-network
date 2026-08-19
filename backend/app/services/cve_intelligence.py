from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.parse import quote
from urllib.request import Request, urlopen
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.scan import CVEFeedRun, CVEIntelligence, SecurityFinding, Technology, TechnologyCVEMatch, TechnologyEvidence

RULE_VERSION = "phase8-cve-v1"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FEED_STALE_SECONDS = 86400

PRODUCT_ALIASES: dict[str, tuple[str, str]] = {
    "wordpress": ("wordpress", "wordpress"),
    "bootstrap": ("getbootstrap", "bootstrap"),
    "auth0": ("auth0", "auth0"),
    "next.js": ("vercel", "next.js"),
    "react": ("facebook", "react"),
    "nginx": ("f5", "nginx"),
    "apache": ("apache", "http_server"),
    "django": ("djangoproject", "django"),
    "jquery": ("jquery", "jquery"),
}
VERSION_RE = re.compile(r"(?<!\d)(\d+\.\d+(?:\.\d+){0,3})(?!\d)")
CPE_RE = re.compile(r"^cpe:2\.3:[aho]:([^:]+):([^:]+):([^:]+):")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def normalize_name(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()


def version_tuple(value: str) -> tuple[int, ...] | None:
    match = VERSION_RE.search(value or "")
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def compare_versions(left: str, right: str) -> int:
    left_parts = version_tuple(left) or ()
    right_parts = version_tuple(right) or ()
    size = max(len(left_parts), len(right_parts))
    left_parts += (0,) * (size - len(left_parts))
    right_parts += (0,) * (size - len(right_parts))
    return (left_parts > right_parts) - (left_parts < right_parts)


def in_range(version: str, item: dict[str, Any]) -> bool:
    if not item.get("vulnerable", True):
        return False
    target = item.get("version") or "*"
    if target not in {"*", "-"} and compare_versions(version, target) != 0:
        return False
    if item.get("versionStartIncluding") and compare_versions(version, item["versionStartIncluding"]) < 0:
        return False
    if item.get("versionStartExcluding") and compare_versions(version, item["versionStartExcluding"]) <= 0:
        return False
    if item.get("versionEndIncluding") and compare_versions(version, item["versionEndIncluding"]) > 0:
        return False
    if item.get("versionEndExcluding") and compare_versions(version, item["versionEndExcluding"]) >= 0:
        return False
    return True


def extract_cpe_ranges(node: dict[str, Any]) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    for match in node.get("cpeMatch", []) or []:
        criteria = str(match.get("criteria") or match.get("cpe22Uri") or "")
        parsed = CPE_RE.match(criteria)
        vendor = parsed.group(1) if parsed else None
        product = parsed.group(2) if parsed else None
        version = parsed.group(3) if parsed else None
        ranges.append({
            "cpe": criteria,
            "vendor": vendor,
            "product": product,
            "version": version,
            "versionStartIncluding": match.get("versionStartIncluding"),
            "versionStartExcluding": match.get("versionStartExcluding"),
            "versionEndIncluding": match.get("versionEndIncluding"),
            "versionEndExcluding": match.get("versionEndExcluding"),
            "vulnerable": bool(match.get("vulnerable", True)),
        })
    for child in (node.get("children", []) or []) + (node.get("nodes", []) or []):
        ranges.extend(extract_cpe_ranges(child))
    return ranges


class CVEIntelligenceAgent:
    """Normalize public CVE feeds and match only technologies with explicit version evidence."""

    def __init__(self, db: Session, scan_id: UUID, *, fetch_feeds: bool = True, feed_payloads: dict[str, dict] | None = None) -> None:
        self.db = db
        self.scan_id = scan_id
        self.fetch_feeds = fetch_feeds
        self.feed_payloads = feed_payloads or {}
        self.feed_status: dict[str, str] = {}

    def analyze(self) -> list[TechnologyCVEMatch]:
        technologies = self.db.query(Technology).filter(Technology.scan_id == self.scan_id).order_by(Technology.canonical_name).all()
        self.db.query(TechnologyCVEMatch).filter(TechnologyCVEMatch.scan_id == self.scan_id).delete(synchronize_session=False)
        self.db.query(SecurityFinding).filter(SecurityFinding.scan_id == self.scan_id, SecurityFinding.category == "cve").delete(synchronize_session=False)
        self.db.flush()
        versioned: list[tuple[Technology, str, float, str, str, str]] = []
        for technology in technologies:
            version, version_confidence, source, vendor, product = self._technology_version(technology)
            versioned.append((technology, version or "", version_confidence, source, vendor, product))
        products = {(vendor, product) for _, version, _, _, vendor, product in versioned if version}
        if self.fetch_feeds:
            for vendor, product in sorted(products):
                self._fetch_nvd(vendor, product)
            self._fetch_kev()
        matches: list[TechnologyCVEMatch] = []
        for technology, version, version_confidence, source, vendor, product in versioned:
            candidates = self._candidates(vendor, product) if version else []
            if not version:
                matches.append(self._persist_match(technology, vendor, product, None, None, 0.0, version_confidence, 0.0, "version_insufficient", "Technology family detected without explicit version evidence.", {"technology_confidence": technology.confidence, "technology_confidence_band": technology.confidence_band}))
                continue
            if not candidates:
                matches.append(self._persist_match(technology, vendor, product, version, source, technology.confidence, version_confidence, 0.0, "no_match", "Explicit version evidence was available, but no normalized feed record matched the detected product/version.", {"technology_confidence": technology.confidence, "technology_confidence_band": technology.confidence_band}))
                continue
            matched_any = False
            for cve in candidates:
                if cve.feed_is_stale:
                    matches.append(self._persist_match(technology, vendor, product, version, source, technology.confidence, version_confidence, 0.0, "stale_feed", "A feed record exists, but its timestamp exceeded the configured freshness threshold.", self._provenance(cve)))
                    continue
                if not self._cve_applies(cve, vendor, product, version):
                    continue
                matched_any = True
                applicability = min(100.0, round((version_confidence * 0.55) + (technology.confidence * 0.25) + 20.0, 2))
                match = self._persist_match(technology, vendor, product, version, source, technology.confidence, version_confidence, applicability, "matched", "Normalized product, explicit version evidence, and source CPE affected-version range matched.", self._provenance(cve), cve)
                matches.append(match)
                self._persist_finding(technology, match, cve)
            if not matched_any and not any(item.technology_id == technology.id for item in matches):
                matches.append(self._persist_match(technology, vendor, product, version, source, technology.confidence, version_confidence, 0.0, "no_match", "Explicit version evidence was available, but no affected-version range matched.", {"technology_confidence": technology.confidence, "technology_confidence_band": technology.confidence_band}))
        self.db.commit()
        return matches

    def report(self) -> dict[str, Any]:
        matches = self.db.query(TechnologyCVEMatch).filter(TechnologyCVEMatch.scan_id == self.scan_id).order_by(TechnologyCVEMatch.applicability_state, TechnologyCVEMatch.product).all()
        cve_ids = {item.cve_intelligence_id for item in matches if item.cve_intelligence_id}
        cves = {item.id: item for item in self.db.query(CVEIntelligence).filter(CVEIntelligence.id.in_(cve_ids)).all()} if cve_ids else {}
        feed_runs = self.db.query(CVEFeedRun).order_by(CVEFeedRun.retrieved_at.desc()).limit(20).all()
        return {
            "scan_id": str(self.scan_id),
            "rule_version": RULE_VERSION,
            "matches": [self._match_dict(item, cves.get(item.cve_intelligence_id)) for item in matches],
            "feed_runs": [self._feed_dict(item) for item in feed_runs],
            "summary": {
                "technology_count": len(matches),
                "matched_count": sum(1 for item in matches if item.applicability_state == "matched"),
                "version_insufficient_count": sum(1 for item in matches if item.applicability_state == "version_insufficient"),
                "no_match_count": sum(1 for item in matches if item.applicability_state == "no_match"),
                "stale_feed_count": sum(1 for item in matches if item.applicability_state == "stale_feed"),
                "kev_count": sum(1 for item in matches if item.cve_intelligence_id and cves.get(item.cve_intelligence_id) and cves[item.cve_intelligence_id].kev_listed),
                "feed_count": len(feed_runs),
            },
            "confidence_contract": {"detected_version_confidence_is_separate": True, "cve_applicability_requires_explicit_version": True, "family_only_detection_is_not_applicable": True},
        }

    def ingest_nvd_payload(self, payload: dict[str, Any], *, retrieved_at: datetime | None = None) -> int:
        retrieved_at = retrieved_at or utc_now()
        records = payload.get("vulnerabilities") or []
        count = 0
        for wrapper in records:
            cve = wrapper.get("cve") or {}
            cve_id = str(cve.get("id") or "")
            if not CVE_RE.match(cve_id):
                continue
            configurations = cve.get("configurations") or []
            ranges: list[dict[str, Any]] = []
            for config in configurations:
                ranges.extend(extract_cpe_ranges(config))
            vendor = next((item.get("vendor") for item in ranges if item.get("vendor")), None)
            product = next((item.get("product") for item in ranges if item.get("product")), None)
            description = next((item.get("value") for item in cve.get("descriptions", []) if item.get("lang") == "en"), "")
            cvss_score, cvss_vector = self._cvss(cve.get("metrics") or {})
            record = self._upsert_cve("nvd", cve_id, vendor, product, description, self._cwes(cve), cvss_score, cvss_vector, ranges, parse_timestamp(cve.get("published")), parse_timestamp(cve.get("lastModified")), NVD_URL, retrieved_at, {"source": "NVD CVE API 2.0", "api_url": NVD_URL, "raw_record_id": cve_id})
            count += 1 if record else 0
        self._record_feed_run("nvd", NVD_URL, retrieved_at, parse_timestamp(payload.get("lastModified")), count, "succeeded")
        self.db.commit()
        return count

    def ingest_kev_payload(self, payload: dict[str, Any], *, retrieved_at: datetime | None = None) -> int:
        retrieved_at = retrieved_at or utc_now()
        count = 0
        for item in payload.get("vulnerabilities", []) or []:
            cve_id = str(item.get("cveID") or "")
            if not CVE_RE.match(cve_id):
                continue
            date_added = parse_timestamp(item.get("dateAdded"))
            due_date = parse_timestamp(item.get("dueDate"))
            existing = self.db.query(CVEIntelligence).filter(CVEIntelligence.cve_id == cve_id).all()
            if existing:
                for record in existing:
                    record.kev_listed = True
                    record.kev_date_added = date_added
                    record.kev_due_date = due_date
                    record.provenance = {**(record.provenance or {}), "cisa_kev": {"source_url": KEV_URL, "date_added": item.get("dateAdded"), "due_date": item.get("dueDate"), "notes": item.get("notes"), "required_action": item.get("requiredAction")}}
                count += 1
            else:
                self._upsert_cve("cisa_kev", cve_id, item.get("vendorProject"), item.get("product"), item.get("shortDescription") or "", [item.get("knownRansomwareCampaignUse")] if item.get("knownRansomwareCampaignUse") else [], None, None, [], None, None, KEV_URL, retrieved_at, {"source": "CISA KEV Catalog", "source_url": KEV_URL, "date_added": item.get("dateAdded"), "due_date": item.get("dueDate"), "required_action": item.get("requiredAction"), "notes": item.get("notes")}, kev_listed=True, kev_date_added=date_added, kev_due_date=due_date)
            count += 1
        self._record_feed_run("cisa_kev", KEV_URL, retrieved_at, parse_timestamp(payload.get("dateReleased")), count, "succeeded")
        self.db.commit()
        return count

    def _fetch_nvd(self, vendor: str, product: str) -> None:
        params = f"keywordSearch={quote(product)}&resultsPerPage=100"
        payload = self.feed_payloads.get("nvd")
        try:
            if payload is None:
                payload = self._get_json(f"{NVD_URL}?{params}")
            self.ingest_nvd_payload(payload)
            self.feed_status["nvd"] = "succeeded"
        except Exception as exc:  # bounded feed failure is reported, not fatal to scan
            self._record_feed_run("nvd", NVD_URL, utc_now(), None, 0, "failed", str(exc))
            self.feed_status["nvd"] = "failed"
            self.db.commit()

    def _fetch_kev(self) -> None:
        payload = self.feed_payloads.get("cisa_kev")
        try:
            if payload is None:
                payload = self._get_json(KEV_URL)
            self.ingest_kev_payload(payload)
            self.feed_status["cisa_kev"] = "succeeded"
        except Exception as exc:
            self._record_feed_run("cisa_kev", KEV_URL, utc_now(), None, 0, "failed", str(exc))
            self.feed_status["cisa_kev"] = "failed"
            self.db.commit()

    @staticmethod
    def _get_json(url: str) -> dict[str, Any]:
        request = Request(url, headers={"Accept": "application/json", "User-Agent": "Web-Autopsy-Network/phase8"})
        with urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))

    def _technology_version(self, technology: Technology) -> tuple[str | None, float, str | None, str, str]:
        canonical = technology.canonical_name
        vendor, product = PRODUCT_ALIASES.get(canonical.lower(), (normalize_name(canonical).replace(" ", "_"), normalize_name(canonical).replace(" ", "_")))
        evidence = self.db.query(TechnologyEvidence).filter(TechnologyEvidence.technology_id == technology.id).order_by(TechnologyEvidence.created_at).all()
        explicit: list[tuple[str, str]] = []
        for item in evidence:
            text = f"{item.observation} {item.source}"
            match = VERSION_RE.search(text)
            if match:
                explicit.append((match.group(1), item.source))
        if not explicit:
            return None, 0.0, None, vendor, product
        version, source = explicit[0]
        version_confidence = 90.0 if re.search(rf"{re.escape(canonical.split('.')[0])}[^\n]{{0,30}}{re.escape(version)}", " ".join(item.observation for item in evidence), re.IGNORECASE) else 70.0
        return version, version_confidence, source[:2048], vendor, product

    def _candidates(self, vendor: str, product: str) -> list[CVEIntelligence]:
        all_items = self.db.query(CVEIntelligence).filter(CVEIntelligence.source_name == "nvd").all()
        target_vendor, target_product = normalize_name(vendor), normalize_name(product)
        return [item for item in all_items if normalize_name(item.vendor) == target_vendor and normalize_name(item.product) == target_product]

    @staticmethod
    def _cve_applies(cve: CVEIntelligence, vendor: str, product: str, version: str) -> bool:
        if normalize_name(cve.vendor) != normalize_name(vendor) or normalize_name(cve.product) != normalize_name(product):
            return False
        return any(in_range(version, item) for item in (cve.affected_ranges or []))

    def _persist_match(self, technology: Technology, vendor: str, product: str, version: str | None, version_source: str | None, detection_confidence: float, version_confidence: float, applicability_confidence: float, state: str, reason: str, provenance: dict[str, Any], cve: CVEIntelligence | None = None) -> TechnologyCVEMatch:
        match = TechnologyCVEMatch(scan_id=self.scan_id, technology_id=technology.id, cve_intelligence_id=cve.id if cve else None, vendor=vendor, product=product, detected_version=version or None, version_source=version_source, detection_confidence=detection_confidence, version_evidence_confidence=version_confidence, applicability_confidence=applicability_confidence, applicability_state=state, match_reason=reason, provenance=provenance)
        self.db.add(match)
        self.db.flush()
        return match

    def _persist_finding(self, technology: Technology, match: TechnologyCVEMatch, cve: CVEIntelligence) -> None:
        self.db.add(SecurityFinding(scan_id=self.scan_id, page_id=None, category="cve", subject=f"{cve.cve_id} may affect {technology.canonical_name} {match.detected_version}", statement=f"CVE applicability matched an explicit detected version for {technology.canonical_name}.", classification="INFERRED", confidence=match.applicability_confidence, confidence_band="high" if match.applicability_confidence >= 80 else "medium", severity="high" if (cve.cvss_score or 0) >= 7 else "medium", rule_id="CVE-MATCH-001", rule_version=RULE_VERSION, evidence=[{"cve_id": cve.cve_id, "vendor": cve.vendor, "product": cve.product, "detected_version": match.detected_version, "source": cve.source_url, "feed_retrieved_at": cve.feed_retrieved_at.isoformat(), "cve_applicability_confidence": match.applicability_confidence, "technology_detection_confidence": match.detection_confidence}], limitations="CVE applicability is based on normalized product/version evidence and public feed ranges; it is not an exploitability confirmation."))

    def _upsert_cve(self, source_name: str, cve_id: str, vendor: str | None, product: str | None, description: str, cwe: list[str], cvss_score: float | None, cvss_vector: str | None, ranges: list[dict[str, Any]], published: datetime | None, modified: datetime | None, source_url: str, retrieved_at: datetime, provenance: dict[str, Any], kev_listed: bool = False, kev_date_added: datetime | None = None, kev_due_date: datetime | None = None) -> CVEIntelligence:
        dedupe_key = f"{source_name}:{cve_id}"
        record = self.db.query(CVEIntelligence).filter(CVEIntelligence.source_name == source_name, CVEIntelligence.cve_id == cve_id).first()
        stale = retrieved_at < utc_now() - timedelta(seconds=FEED_STALE_SECONDS)
        if record is None:
            record = CVEIntelligence(source_name=source_name, cve_id=cve_id, vendor=vendor, product=product, description=description[:20000], cwe=cwe, cvss_score=cvss_score, cvss_vector=cvss_vector, affected_ranges=ranges, published_at=published, last_modified_at=modified, source_url=source_url, feed_retrieved_at=retrieved_at, feed_stale_after_seconds=FEED_STALE_SECONDS, feed_is_stale=stale, kev_listed=kev_listed, kev_date_added=kev_date_added, kev_due_date=kev_due_date, provenance=provenance, dedupe_key=dedupe_key)
            self.db.add(record)
        else:
            record.vendor, record.product, record.description, record.cwe, record.cvss_score, record.cvss_vector, record.affected_ranges = vendor, product, description[:20000], cwe, cvss_score, cvss_vector, ranges
            record.published_at, record.last_modified_at, record.source_url, record.feed_retrieved_at, record.feed_is_stale, record.provenance = published, modified, source_url, retrieved_at, stale, provenance
            record.kev_listed = record.kev_listed or kev_listed
            record.kev_date_added, record.kev_due_date = kev_date_added or record.kev_date_added, kev_due_date or record.kev_due_date
        self.db.flush()
        return record

    def _record_feed_run(self, source_name: str, source_url: str, retrieved: datetime, modified: datetime | None, count: int, status: str, error: str | None = None) -> None:
        self.db.add(CVEFeedRun(source_name=source_name, source_url=source_url, retrieved_at=retrieved, source_last_modified_at=modified, record_count=count, stale_after_seconds=FEED_STALE_SECONDS, is_stale=retrieved < utc_now() - timedelta(seconds=FEED_STALE_SECONDS), status=status, error=error))
        self.db.flush()

    @staticmethod
    def _cwes(cve: dict[str, Any]) -> list[str]:
        result: list[str] = []
        for weakness in cve.get("weaknesses", []) or []:
            for description in weakness.get("description", []) or []:
                value = description.get("value")
                if value and value not in result:
                    result.append(value)
        return result[:20]

    @staticmethod
    def _cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                cvss = entries[0].get("cvssData") or {}
                return cvss.get("baseScore"), cvss.get("vectorString")
        return None, None

    @staticmethod
    def _provenance(cve: CVEIntelligence) -> dict[str, Any]:
        return {"source_name": cve.source_name, "source_url": cve.source_url, "feed_retrieved_at": cve.feed_retrieved_at.isoformat(), "feed_is_stale": cve.feed_is_stale, "cve_id": cve.cve_id, "kev_listed": cve.kev_listed}

    @staticmethod
    def _match_dict(match: TechnologyCVEMatch, cve: CVEIntelligence | None) -> dict[str, Any]:
        return {"id": str(match.id), "technology_id": str(match.technology_id), "cve_id": cve.cve_id if cve else None, "vendor": match.vendor, "product": match.product, "detected_version": match.detected_version, "version_source": match.version_source, "detection_confidence": match.detection_confidence, "version_evidence_confidence": match.version_evidence_confidence, "applicability_confidence": match.applicability_confidence, "applicability_state": match.applicability_state, "match_reason": match.match_reason, "provenance": match.provenance, "cwe": cve.cwe if cve else [], "cvss_score": cve.cvss_score if cve else None, "cvss_vector": cve.cvss_vector if cve else None, "description": cve.description if cve else None, "kev_listed": cve.kev_listed if cve else False, "source_url": cve.source_url if cve else None, "feed_retrieved_at": cve.feed_retrieved_at.isoformat() if cve else None, "feed_is_stale": cve.feed_is_stale if cve else None, "created_at": match.created_at.isoformat()}

    @staticmethod
    def _feed_dict(feed: CVEFeedRun) -> dict[str, Any]:
        return {"id": str(feed.id), "source_name": feed.source_name, "source_url": feed.source_url, "retrieved_at": feed.retrieved_at.isoformat(), "source_last_modified_at": feed.source_last_modified_at.isoformat() if feed.source_last_modified_at else None, "record_count": feed.record_count, "stale_after_seconds": feed.stale_after_seconds, "is_stale": feed.is_stale, "status": feed.status, "error": feed.error}


__all__ = ["CVEIntelligenceAgent", "FEED_STALE_SECONDS", "KEV_URL", "NVD_URL", "RULE_VERSION", "compare_versions", "in_range", "normalize_name", "version_tuple"]
