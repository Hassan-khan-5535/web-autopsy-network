"""Deterministic, evidence-linked comparisons between two persisted scans."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy.orm import Session

from app.models.scan import (
    AccessibilityFinding,
    ApiEndpoint,
    ContentFinding,
    Dependency,
    HTTPObservation,
    PerformanceMetric,
    ReconAsset,
    ReconEndpoint,
    Scan,
    ScanDifference,
    SecurityFinding,
    Technology,
)

PERFORMANCE_REGRESSION_THRESHOLD = 0.20
DIFF_NAMESPACE = "https://web-autopsy.network/scan-difference"


class DiffValidationError(ValueError):
    """Raised when two scans cannot be compared."""


class DiffEngine:
    """Compare two completed scans without issuing any target-site requests."""

    def __init__(self, db: Session):
        self.db = db

    def compare(self, scan_a_id: UUID, scan_b_id: UUID, *, persist: bool = True) -> dict[str, Any]:
        scan_a = self.db.query(Scan).filter(Scan.id == scan_a_id).first()
        scan_b = self.db.query(Scan).filter(Scan.id == scan_b_id).first()
        if not scan_a or not scan_b:
            raise DiffValidationError("Both scan IDs must refer to existing scans.")
        if scan_a.website_id != scan_b.website_id:
            raise DiffValidationError("Scans must belong to the same website.")
        if scan_a.state != "COMPLETED" or scan_b.state != "COMPLETED":
            raise DiffValidationError("Only completed scans can be compared.")
        if scan_a.id == scan_b.id:
            raise DiffValidationError("A scan cannot be compared with itself.")

        categories = {
            "structure": self._structure(scan_a, scan_b),
            "assets": self._assets(scan_a, scan_b),
            "endpoints": self._endpoints(scan_a, scan_b),
            "technology": self._technologies(scan_a, scan_b),
            "dependencies": self._dependencies(scan_a, scan_b),
            "security": self._security(scan_a, scan_b),
            "security_headers": self._security_headers(scan_a, scan_b),
            "vulnerabilities": self._finding_subset(scan_a, scan_b, "vulnerability", ("vulnerability", "cve")),
            "configuration": self._finding_subset(scan_a, scan_b, "configuration", ("configuration", "config")),
            "secrets": self._finding_subset(scan_a, scan_b, "secret", ("secret",)),
            "risk": self._risk(scan_a, scan_b),
            "performance": self._performance(scan_a, scan_b),
            "content": self._content(scan_a, scan_b),
        }
        items = [item for category in categories.values() for item in category["items"]]
        result: dict[str, Any] = {
            "scan_a": self._scan_meta(scan_a),
            "scan_b": self._scan_meta(scan_b),
            "categories": categories,
            "items": items,
            "item_count": len(items),
            "performance_threshold": PERFORMANCE_REGRESSION_THRESHOLD,
        }
        if persist:
            existing = (
                self.db.query(ScanDifference)
                .filter(
                    ScanDifference.scan_a_id == scan_a.id,
                    ScanDifference.scan_b_id == scan_b.id,
                )
                .first()
            )
            if existing:
                existing.diff_data = result
                existing.created_at = datetime.now(UTC)
                self.db.commit()
                self.db.refresh(existing)
            else:
                existing = ScanDifference(
                    website_id=scan_a.website_id,
                    scan_a_id=scan_a.id,
                    scan_b_id=scan_b.id,
                    diff_data=result,
                    ai_evidence=[],
                )
                self.db.add(existing)
                self.db.commit()
                self.db.refresh(existing)
            result["difference_id"] = str(existing.id)
        return result

    @staticmethod
    def _scan_meta(scan: Scan) -> dict[str, Any]:
        return {
            "id": str(scan.id),
            "website_id": str(scan.website_id),
            "requested_url": scan.requested_url,
            "state": scan.state,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
        }

    @staticmethod
    def _item(category: str, key: str, *, change: str, before: Any = None, after: Any = None,
              classification: str = "OBSERVED", evidence: list[str] | None = None,
              note: str | None = None) -> dict[str, Any]:
        item_id = str(uuid5(NAMESPACE_URL, f"{DIFF_NAMESPACE}/{category}/{key}"))
        return {
            "id": item_id,
            "category": category,
            "change": change,
            "before": before,
            "after": after,
            "classification": classification,
            "evidence": evidence or [],
            "note": note,
        }

    def _structure(self, scan_a: Scan, scan_b: Scan) -> dict[str, Any]:
        before = {p.canonical_url: p for p in scan_a.pages}
        after = {p.canonical_url: p for p in scan_b.pages}
        items: list[dict[str, Any]] = []
        for url in sorted(after.keys() - before.keys()):
            page = after[url]
            items.append(self._item("structure", f"page-added:{url}", change="page_added", after={"url": url, "depth": page.depth, "status_code": page.status_code}, evidence=[str(page.id)]))
        for url in sorted(before.keys() - after.keys()):
            page = before[url]
            items.append(self._item("structure", f"page-removed:{url}", change="page_removed", before={"url": url, "depth": page.depth, "status_code": page.status_code}, classification="INFERRED", evidence=[str(page.id)], note="The page was not present in scan B; external absence is not proof that the route was deleted."))
        for url in sorted(before.keys() & after.keys()):
            left, right = before[url], after[url]
            if left.status_code != right.status_code:
                items.append(self._item("structure", f"status:{url}", change="status_changed", before={"url": url, "status_code": left.status_code}, after={"url": url, "status_code": right.status_code}, evidence=[str(left.id), str(right.id)]))
            if left.depth != right.depth:
                items.append(self._item("structure", f"depth:{url}", change="depth_changed", before=left.depth, after=right.depth, evidence=[str(left.id), str(right.id)]))
        return {"page_count": {"before": len(before), "after": len(after), "delta": len(after) - len(before)}, "max_depth": {"before": max((p.depth for p in before.values()), default=0), "after": max((p.depth for p in after.values()), default=0)}, "items": items}

    def _assets(self, scan_a: Scan, scan_b: Scan) -> dict[str, Any]:
        before = {(item.asset_type, item.value): item for item in self.db.query(ReconAsset).filter(ReconAsset.scan_id == scan_a.id).all()}
        after = {(item.asset_type, item.value): item for item in self.db.query(ReconAsset).filter(ReconAsset.scan_id == scan_b.id).all()}
        items: list[dict[str, Any]] = []
        for key in sorted(after.keys() - before.keys()):
            item = after[key]
            items.append(self._item("assets", f"added:{key}", change="asset_added", after={"asset_type": item.asset_type, "value": item.value, "scope_status": item.scope_status}, evidence=[str(item.id)]))
        for key in sorted(before.keys() - after.keys()):
            item = before[key]
            items.append(self._item("assets", f"removed:{key}", change="asset_no_longer_observed", before={"asset_type": item.asset_type, "value": item.value, "scope_status": item.scope_status}, classification="INFERRED", evidence=[str(item.id)], note="The asset was not observed in scan B; this is not proof that it was removed or decommissioned."))
        return {"asset_count": {"before": len(before), "after": len(after), "delta": len(after) - len(before)}, "items": items}

    def _endpoints(self, scan_a: Scan, scan_b: Scan) -> dict[str, Any]:
        def records(scan_id: UUID) -> dict[tuple[str, str, str], Any]:
            recon = {("recon", item.http_method, item.url_or_path): item for item in self.db.query(ReconEndpoint).filter(ReconEndpoint.scan_id == scan_id).all()}
            api = {("api", item.http_method, item.url_or_path): item for item in self.db.query(ApiEndpoint).filter(ApiEndpoint.scan_id == scan_id).all()}
            return {**recon, **api}
        before, after = records(scan_a.id), records(scan_b.id)
        items: list[dict[str, Any]] = []
        for key in sorted(after.keys() - before.keys()):
            source, method, path = key
            item = after[key]
            items.append(self._item("endpoints", f"added:{key}", change="endpoint_added", after={"source": source, "method": method, "url_or_path": path, "status_code": getattr(item, "status_code", None)}, evidence=[str(item.id)]))
        for key in sorted(before.keys() - after.keys()):
            source, method, path = key
            item = before[key]
            items.append(self._item("endpoints", f"removed:{key}", change="endpoint_no_longer_observed", before={"source": source, "method": method, "url_or_path": path, "status_code": getattr(item, "status_code", None)}, classification="INFERRED", evidence=[str(item.id)], note="The endpoint was not observed in scan B; this is not proof it was removed or access-controlled."))
        return {"endpoint_count": {"before": len(before), "after": len(after), "delta": len(after) - len(before)}, "items": items}

    def _technologies(self, scan_a: Scan, scan_b: Scan) -> dict[str, Any]:
        before = {t.canonical_name: t for t in scan_a.technologies}
        after = {t.canonical_name: t for t in scan_b.technologies}
        items: list[dict[str, Any]] = []
        for name in sorted(after.keys() - before.keys()):
            tech = after[name]
            evidence = [str(ev.id) for ev in tech.evidence]
            items.append(self._item("technology", f"added:{name}", change="technology_added", after={"name": name, "confidence": tech.confidence, "classification": tech.classification}, evidence=evidence or [str(tech.id)]))
        for name in sorted(before.keys() - after.keys()):
            tech = before[name]
            evidence = [str(ev.id) for ev in tech.evidence]
            items.append(self._item("technology", f"removed:{name}", change="technology_no_longer_detected", before={"name": name, "confidence": tech.confidence, "classification": tech.classification}, classification="INFERRED", evidence=evidence or [str(tech.id)], note="No detection in scan B is not proof that the underlying technology was removed."))
        for name in sorted(before.keys() & after.keys()):
            left, right = before[name], after[name]
            if left.confidence != right.confidence:
                left_ev = [str(ev.id) for ev in left.evidence]
                right_ev = [str(ev.id) for ev in right.evidence]
                items.append(self._item("technology", f"confidence:{name}", change="confidence_changed", before=left.confidence, after=right.confidence, evidence=(left_ev + right_ev) or [str(left.id), str(right.id)]))
        return {"technology_count": {"before": len(before), "after": len(after), "delta": len(after) - len(before)}, "items": items}

    def _dependencies(self, scan_a: Scan, scan_b: Scan) -> dict[str, Any]:
        before = {d.domain: d for d in scan_a.dependencies}
        after = {d.domain: d for d in scan_b.dependencies}
        items: list[dict[str, Any]] = []
        for domain in sorted(after.keys() - before.keys()):
            dep = after[domain]
            items.append(self._item("dependencies", f"added:{domain}", change="dependency_added", after={"domain": domain, "category": dep.category, "confidence": dep.confidence}, evidence=[str(dep.id)]))
        for domain in sorted(before.keys() - after.keys()):
            dep = before[domain]
            items.append(self._item("dependencies", f"removed:{domain}", change="dependency_removed", before={"domain": domain, "category": dep.category, "confidence": dep.confidence}, classification="INFERRED", evidence=[str(dep.id)], note="The dependency was not observed in scan B; this does not prove the service was removed."))
        for domain in sorted(before.keys() & after.keys()):
            left, right = before[domain], after[domain]
            if left.category != right.category:
                items.append(self._item("dependencies", f"category:{domain}", change="dependency_category_changed", before={"domain": domain, "category": left.category}, after={"domain": domain, "category": right.category}, classification="INFERRED", evidence=[str(left.id), str(right.id)]))
        return {"domain_count": {"before": len(before), "after": len(after), "delta": len(after) - len(before)}, "items": items}

    def _security(self, scan_a: Scan, scan_b: Scan) -> dict[str, Any]:
        key = lambda f: (f.rule_id, f.subject)
        before = {key(f): f for f in scan_a.security_findings}
        after = {key(f): f for f in scan_b.security_findings}
        items: list[dict[str, Any]] = []
        for finding_key in sorted(after.keys() - before.keys(), key=str):
            finding = after[finding_key]
            items.append(self._item("security", f"added:{finding_key}", change="security_finding_added", after={"subject": finding.subject, "statement": finding.statement, "severity": finding.severity}, evidence=[str(finding.id)]))
        for finding_key in sorted(before.keys() - after.keys(), key=str):
            finding = before[finding_key]
            items.append(self._item("security", f"removed:{finding_key}", change="security_finding_no_longer_observed", before={"subject": finding.subject, "statement": finding.statement, "severity": finding.severity}, classification="INFERRED", evidence=[str(finding.id)], note="The prior finding was not observed in scan B."))
        for finding_key in sorted(before.keys() & after.keys(), key=str):
            left, right = before[finding_key], after[finding_key]
            if left.severity != right.severity:
                items.append(self._item("security", f"severity:{finding_key}", change="severity_changed", before={"subject": left.subject, "severity": left.severity}, after={"subject": right.subject, "severity": right.severity}, evidence=[str(left.id), str(right.id)]))
            if (left.statement, left.classification) != (right.statement, right.classification):
                items.append(self._item("security", f"changed:{finding_key}", change="security_finding_changed", before={"statement": left.statement, "classification": left.classification}, after={"statement": right.statement, "classification": right.classification}, evidence=[str(left.id), str(right.id)]))
        return {"finding_count": {"before": len(before), "after": len(after), "delta": len(after) - len(before)}, "items": items}

    def _security_headers(self, scan_a: Scan, scan_b: Scan) -> dict[str, Any]:
        def records(scan_id: UUID) -> dict[str, HTTPObservation]:
            return {item.subject.lower(): item for item in self.db.query(HTTPObservation).filter(HTTPObservation.scan_id == scan_id, HTTPObservation.observation_type == "header").all()}
        before, after = records(scan_a.id), records(scan_b.id)
        items: list[dict[str, Any]] = []
        for key in sorted(after.keys() - before.keys()):
            item = after[key]
            items.append(self._item("security_headers", f"added:{key}", change="security_header_observed", after={"header": item.subject, "redacted": item.redacted}, evidence=[str(item.id)]))
        for key in sorted(before.keys() - after.keys()):
            item = before[key]
            items.append(self._item("security_headers", f"removed:{key}", change="security_header_no_longer_observed", before={"header": item.subject, "redacted": item.redacted}, classification="INFERRED", evidence=[str(item.id)], note="The header observation was not reproduced in scan B; this is not proof that the header was removed."))
        for key in sorted(before.keys() & after.keys()):
            left, right = before[key], after[key]
            if left.value != right.value:
                items.append(self._item("security_headers", f"changed:{key}", change="security_header_changed", before={"header": left.subject, "redacted": left.redacted}, after={"header": right.subject, "redacted": right.redacted}, evidence=[str(left.id), str(right.id)], note="Header values are not included in the diff summary."))
        return {"header_count": {"before": len(before), "after": len(after), "delta": len(after) - len(before)}, "items": items}

    def _finding_subset(self, scan_a: Scan, scan_b: Scan, category: str, tokens: tuple[str, ...]) -> dict[str, Any]:
        select = lambda scan: { (item.rule_id, item.subject): item for item in scan.security_findings if any(token in (item.category or "").lower() for token in tokens) }
        before, after = select(scan_a), select(scan_b)
        items: list[dict[str, Any]] = []
        for key in sorted(after.keys() - before.keys(), key=str):
            item = after[key]
            change = "newly_exposed_secret" if category == "secret" else f"{category}_added"
            items.append(self._item(category, f"added:{key}", change=change, after={"subject": item.subject, "severity": item.severity, "rule_id": item.rule_id}, evidence=[str(item.id)]))
        for key in sorted(before.keys() - after.keys(), key=str):
            item = before[key]
            change = "secret_no_longer_observed" if category == "secret" else f"{category}_no_longer_observed"
            items.append(self._item(category, f"removed:{key}", change=change, before={"subject": item.subject, "severity": item.severity, "rule_id": item.rule_id}, classification="INFERRED", evidence=[str(item.id)], note="No current observation is not proof that this finding has been resolved."))
        for key in sorted(before.keys() & after.keys(), key=str):
            left, right = before[key], after[key]
            if left.severity != right.severity:
                change = "configuration_regression" if category == "configuration" and str(right.severity).lower() > str(left.severity).lower() else f"{category}_severity_changed"
                items.append(self._item(category, f"severity:{key}", change=change, before={"subject": left.subject, "severity": left.severity}, after={"subject": right.subject, "severity": right.severity}, evidence=[str(left.id), str(right.id)]))
        return {"finding_count": {"before": len(before), "after": len(after), "delta": len(after) - len(before)}, "items": items}

    def _risk(self, scan_a: Scan, scan_b: Scan) -> dict[str, Any]:
        left, right = scan_a.risk_summary, scan_b.risk_summary
        if not left or not right:
            return {"available": False, "items": [], "limitation": "Risk summary is unavailable for one or both scans."}
        if left.overall_score == right.overall_score and left.risk_band == right.risk_band:
            return {"available": True, "items": []}
        return {"available": True, "items": [self._item("risk", f"overall:{scan_a.id}:{scan_b.id}", change="risk_score_changed", before={"overall_score": left.overall_score, "risk_band": left.risk_band}, after={"overall_score": right.overall_score, "risk_band": right.risk_band}, evidence=[str(left.id), str(right.id)])]}

    def _performance(self, scan_a: Scan, scan_b: Scan) -> dict[str, Any]:
        def metric_key(metric: PerformanceMetric) -> tuple[str, str, str | None]:
            return metric.scope, metric.metric_name, str(metric.page_id) if metric.page_id else None
        before = {metric_key(m): m for m in scan_a.performance_metrics}
        after = {metric_key(m): m for m in scan_b.performance_metrics}
        items: list[dict[str, Any]] = []
        for metric_key_value in sorted(before.keys() & after.keys(), key=str):
            left, right = before[metric_key_value], after[metric_key_value]
            if left.value == right.value:
                continue
            delta = None if left.value is None or right.value is None else right.value - left.value
            percent = None if left.value in (None, 0) or right.value is None else delta / abs(left.value)
            regression = percent is not None and percent > PERFORMANCE_REGRESSION_THRESHOLD
            items.append(self._item("performance", f"changed:{metric_key_value}", change="performance_metric_changed", before={"metric_name": left.metric_name, "value": left.value, "unit": left.unit}, after={"metric_name": right.metric_name, "value": right.value, "unit": right.unit}, classification="INFERRED" if regression else "OBSERVED", evidence=[str(left.id), str(right.id)], note=f"Regression framing uses the documented {PERFORMANCE_REGRESSION_THRESHOLD:.0%} increase threshold." if regression else None))
        return {"metric_count": {"before": len(before), "after": len(after), "delta": len(after) - len(before)}, "items": items}

    def _content(self, scan_a: Scan, scan_b: Scan) -> dict[str, Any]:
        def content_key(finding: ContentFinding) -> tuple[str, str]:
            return finding.category, finding.subject
        before = {content_key(f): f for f in scan_a.content_findings}
        after = {content_key(f): f for f in scan_b.content_findings}
        items: list[dict[str, Any]] = []
        for finding_key in sorted(after.keys() - before.keys(), key=str):
            finding = after[finding_key]
            items.append(self._item("content", f"added:{finding_key}", change="content_finding_added", after={"subject": finding.subject, "statement": finding.statement}, evidence=[str(finding.id)]))
        for finding_key in sorted(before.keys() - after.keys(), key=str):
            finding = before[finding_key]
            items.append(self._item("content", f"removed:{finding_key}", change="content_finding_no_longer_observed", before={"subject": finding.subject, "statement": finding.statement}, classification="INFERRED", evidence=[str(finding.id)]))
        for finding_key in sorted(before.keys() & after.keys(), key=str):
            left, right = before[finding_key], after[finding_key]
            if left.statement != right.statement:
                items.append(self._item("content", f"changed:{finding_key}", change="content_finding_changed", before=left.statement, after=right.statement, evidence=[str(left.id), str(right.id)]))
        return {"finding_count": {"before": len(before), "after": len(after), "delta": len(after) - len(before)}, "items": items}

    @staticmethod
    def diff_item_ids(diff_data: dict[str, Any]) -> set[str]:
        return {item["id"] for item in diff_data.get("items", []) if item.get("id")}
