from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.models.scan import (
    ContentFinding,
    Dependency,
    Page,
    PerformanceMetric,
    Scan,
    SecurityFinding,
    Technology,
    TechnologyEvidence,
    Website,
)
from app.services.diff import DiffEngine
from app.services.evidence import EvidenceAgent, EvidenceValidationError


def seed_scans(db):
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.flush()
    first = Scan(website_id=website.id, requested_url="https://example.com", state="COMPLETED", created_at=datetime.now(UTC) - timedelta(days=1))
    second = Scan(website_id=website.id, requested_url="https://example.com", state="COMPLETED", created_at=datetime.now(UTC))
    db.add_all([first, second])
    db.flush()
    old_home = Page(scan_id=first.id, canonical_url="https://example.com/", depth=0, status_code=200)
    old_about = Page(scan_id=first.id, canonical_url="https://example.com/about", depth=1, status_code=200)
    new_home = Page(scan_id=second.id, canonical_url="https://example.com/", depth=0, status_code=304)
    new_contact = Page(scan_id=second.id, canonical_url="https://example.com/contact", depth=1, status_code=200)
    db.add_all([old_home, old_about, new_home, new_contact])
    db.flush()
    old_tech = Technology(scan_id=first.id, canonical_name="React", category="frontend", classification="inferred", confidence=0.8, confidence_band="high", rule_version="test")
    new_tech = Technology(scan_id=second.id, canonical_name="Next.js", category="frontend", classification="inferred", confidence=0.95, confidence_band="high", rule_version="test")
    db.add_all([old_tech, new_tech])
    db.flush()
    old_ev = TechnologyEvidence(technology_id=old_tech.id, scan_id=first.id, page_id=old_home.id, signal_type="script", match_rule="react", source="https://example.com/", observation="react bundle", match_weight=0.8)
    new_ev = TechnologyEvidence(technology_id=new_tech.id, scan_id=second.id, page_id=new_home.id, signal_type="script", match_rule="next", source="https://example.com/", observation="__NEXT_DATA__", match_weight=0.95)
    db.add_all([old_ev, new_ev])
    old_dep = Dependency(scan_id=first.id, domain="analytics.example", category="Analytics", classification="inferred", confidence=0.8)
    new_dep = Dependency(scan_id=second.id, domain="cdn.example", category="CDN", classification="inferred", confidence=0.9)
    db.add_all([old_dep, new_dep])
    old_perf = PerformanceMetric(scan_id=first.id, scope="site", metric_name="site_total_document_size_bytes", value=1000, unit="bytes", classification="OBSERVED", confidence=100, confidence_band="high", capture_mode="test", statement="1000 bytes", evidence=[{"id": "old"}])
    new_perf = PerformanceMetric(scan_id=second.id, scope="site", metric_name="site_total_document_size_bytes", value=1300, unit="bytes", classification="OBSERVED", confidence=100, confidence_band="high", capture_mode="test", statement="1300 bytes", evidence=[{"id": "new"}])
    db.add_all([old_perf, new_perf])
    old_content = ContentFinding(scan_id=first.id, page_id=old_home.id, category="metadata", subject="title", statement="Old title", classification="OBSERVED", evidence=[{"id": "old-title"}])
    new_content = ContentFinding(scan_id=second.id, page_id=new_home.id, category="metadata", subject="title", statement="New title", classification="OBSERVED", evidence=[{"id": "new-title"}])
    db.add_all([old_content, new_content])
    old_security = SecurityFinding(scan_id=first.id, page_id=old_home.id, category="security", subject="Content-Security-Policy", statement="Header missing", classification="OBSERVED", confidence=100, confidence_band="high", severity="medium", rule_id="csp", rule_version="test", evidence=[{"id": "old-csp"}])
    new_security = SecurityFinding(scan_id=second.id, page_id=new_home.id, category="security", subject="Content-Security-Policy", statement="Header present", classification="OBSERVED", confidence=100, confidence_band="high", severity="info", rule_id="csp", rule_version="test", evidence=[{"id": "new-csp"}])
    db.add_all([old_security, new_security])
    db.commit()
    return first, second


def test_phase11_diff_is_deterministic_and_covers_categories(db):
    first, second = seed_scans(db)
    engine = DiffEngine(db)
    first_result = engine.compare(first.id, second.id, persist=False)
    second_result = engine.compare(first.id, second.id, persist=False)
    assert first_result == second_result
    assert first_result["categories"]["structure"]["page_count"]["delta"] == 0
    changes = {item["change"] for item in first_result["items"]}
    assert "page_added" in changes
    assert "page_removed" in changes
    assert "technology_added" in changes
    assert "technology_no_longer_detected" in changes
    assert "performance_metric_changed" in changes
    assert "content_finding_changed" in changes
    assert "security_finding_changed" in changes
    assert all(item["evidence"] for item in first_result["items"])


def test_phase11_absence_is_inferred_and_fabricated_diff_citations_rejected(db):
    first, second = seed_scans(db)
    result = DiffEngine(db).compare(first.id, second.id, persist=True)
    missing_tech = next(item for item in result["items"] if item["change"] == "technology_no_longer_detected")
    assert missing_tech["classification"] == "INFERRED"
    assert "not proof" in missing_tech["note"]
    with pytest.raises(EvidenceValidationError):
        EvidenceAgent(db, second.id).validate_difference_citations(result["difference_id"], [str(uuid4())])
