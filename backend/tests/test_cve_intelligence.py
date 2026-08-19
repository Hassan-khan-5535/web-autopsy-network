from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.scan import CVEFeedRun, CVEIntelligence, Page, Scan, SecurityFinding, Technology, TechnologyEvidence, TechnologyCVEMatch, Website
from app.services.cve_intelligence import CVEIntelligenceAgent, KEV_URL, NVD_URL, RULE_VERSION, compare_versions, in_range
from app.services.tasks import TaskGraphCoordinator


def _scan(db: Session) -> Scan:
    website = Website(id=uuid4(), tenant_id="default", canonical_origin="example.com")
    db.add(website)
    db.flush()
    scan = Scan(id=uuid4(), website_id=website.id, state="COMPLETED", requested_url="https://example.com/", max_depth=1, max_pages=5, max_concurrency=1, request_delay_ms=100, same_domain_mode="hostname")
    db.add(scan)
    db.commit()
    return scan


def _technology(db: Session, scan: Scan, name: str, observation: str, confidence: float = 85.0) -> Technology:
    page = Page(scan_id=scan.id, canonical_url="https://example.com/", depth=0)
    db.add(page)
    db.flush()
    technology = Technology(scan_id=scan.id, canonical_name=name, category="framework", classification="inferred", confidence=confidence, confidence_band="high" if confidence >= 70 else "medium", rule_version="phase4-v2")
    db.add(technology)
    db.flush()
    db.add(TechnologyEvidence(technology_id=technology.id, scan_id=scan.id, page_id=page.id, signal_type="metadata", match_rule="test", source=page.canonical_url, observation=observation, match_weight=80))
    db.commit()
    return technology


def _nvd_payload():
    return {
        "lastModified": "2026-08-19T00:00:00.000Z",
        "vulnerabilities": [{"cve": {
            "id": "CVE-2024-12345",
            "published": "2024-01-01T00:00:00.000Z",
            "lastModified": "2024-02-01T00:00:00.000Z",
            "descriptions": [{"lang": "en", "value": "WordPress vulnerability for versions before 6.0.2."}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"}}]},
            "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:wordpress:wordpress:6.0:*:*:*:*:*:*:*", "versionEndExcluding": "6.0.2"}]}]}],
        }}],
    }


def _kev_payload():
    return {"dateReleased": "2026-08-19T00:00:00.000Z", "vulnerabilities": [{"cveID": "CVE-2024-12345", "vendorProject": "WordPress", "product": "WordPress", "shortDescription": "Known exploited issue", "dateAdded": "2024-02-02", "dueDate": "2024-02-22", "knownRansomwareCampaignUse": "Unknown", "requiredAction": "Apply update", "notes": "CISA note"}]}


def test_version_helpers_and_cpe_range_matching():
    assert compare_versions("6.0", "6.0.2") < 0
    assert compare_versions("6.0.2", "6.0.2") == 0
    assert in_range("6.0", {"versionEndExcluding": "6.0.2", "vulnerable": True})
    assert not in_range("6.0.2", {"versionEndExcluding": "6.0.2", "vulnerable": True})


def test_nvd_and_kev_normalization_match_explicit_version_with_separate_confidence(db: Session):
    scan = _scan(db)
    technology = _technology(db, scan, "WordPress", "Detected WordPress 6.0 from generator metadata.")
    agent = CVEIntelligenceAgent(db, scan.id, fetch_feeds=True, feed_payloads={"nvd": _nvd_payload(), "cisa_kev": _kev_payload()})
    matches = agent.analyze()
    match = next(item for item in matches if item.technology_id == technology.id)
    assert match.applicability_state == "matched"
    assert match.detected_version == "6.0"
    assert match.detection_confidence == 85.0
    assert match.version_evidence_confidence >= 70
    assert match.applicability_confidence > 0
    cve = db.query(CVEIntelligence).filter(CVEIntelligence.cve_id == "CVE-2024-12345", CVEIntelligence.source_name == "nvd").one()
    assert cve.cvss_score == 8.1
    assert cve.cwe == ["CWE-79"]
    assert cve.kev_listed is True
    assert cve.source_url == NVD_URL
    assert db.query(SecurityFinding).filter_by(scan_id=scan.id, category="cve").count() == 1
    report = agent.report()
    assert report["confidence_contract"]["family_only_detection_is_not_applicable"] is True
    assert report["summary"]["kev_count"] == 1
    assert {feed.source_name for feed in db.query(CVEFeedRun).all()} == {"nvd", "cisa_kev"}


def test_family_detection_without_version_never_becomes_cve_applicable(db: Session):
    scan = _scan(db)
    technology = _technology(db, scan, "WordPress", "Detected WordPress generator family only.")
    agent = CVEIntelligenceAgent(db, scan.id, fetch_feeds=True, feed_payloads={"nvd": _nvd_payload(), "cisa_kev": _kev_payload()})
    match = next(item for item in agent.analyze() if item.technology_id == technology.id)
    assert match.applicability_state == "version_insufficient"
    assert match.cve_intelligence_id is None
    assert match.applicability_confidence == 0
    assert db.query(SecurityFinding).filter_by(scan_id=scan.id, category="cve").count() == 0


def test_stale_feed_is_explicit_and_deduplicated(db: Session):
    scan = _scan(db)
    technology = _technology(db, scan, "WordPress", "WordPress 6.0")
    agent = CVEIntelligenceAgent(db, scan.id, fetch_feeds=False)
    old = datetime.now(timezone.utc) - timedelta(days=3)
    agent.ingest_nvd_payload(_nvd_payload(), retrieved_at=old)
    agent.ingest_nvd_payload(_nvd_payload(), retrieved_at=old)
    matches = agent.analyze()
    match = next(item for item in matches if item.technology_id == technology.id)
    assert match.applicability_state == "stale_feed"
    assert db.query(CVEIntelligence).filter_by(source_name="nvd", cve_id="CVE-2024-12345").count() == 1


def test_task_dependencies_and_route_contract(db: Session):
    scan = _scan(db)
    TaskGraphCoordinator.initialize_scan(db, scan.id)
    TaskGraphCoordinator.after_collection(db, scan.id)
    task_map = {task.task_type: task for task in scan.agent_tasks}
    assert task_map["cve_intelligence"].dependency_keys == ["technology"]
    assert "cve_intelligence" in task_map["diagnosis"].dependency_keys
