from argparse import Namespace

import pytest

from app.api.routes.platform import get_capabilities, get_dashboard_snapshot, list_platform_findings
from app.models.scan import RiskAssessment, Scan, ScanRiskSummary, SecurityFinding, Website
from scripts.web_autopsy_cli import create_payload


def make_platform_scan(db):
    website = Website(canonical_origin="platform.example")
    db.add(website)
    db.flush()
    scan = Scan(website_id=website.id, requested_url="https://platform.example/", state="COMPLETED", assessment_profile="safe")
    db.add(scan)
    db.flush()
    finding = SecurityFinding(
        scan_id=scan.id, category="security", subject="https://platform.example/", statement="A persisted high confidence test finding.",
        classification="OBSERVED", confidence=91.0, confidence_band="high", severity="high", rule_id="TEST-PLATFORM-001", rule_version="test-v1", evidence=[{"safe": "evidence"}],
    )
    db.add(finding)
    db.flush()
    db.add(RiskAssessment(scan_id=scan.id, security_finding_id=finding.id, deterministic_version="extension11-v1", risk_score=82.0, risk_band="high", eligible_for_prioritization=True, evidence_state="validated", score_components={}, decision_notes=[], evidence_snapshot={}))
    db.add(ScanRiskSummary(scan_id=scan.id, website_id=website.id, deterministic_version="extension11-v1", overall_score=82.0, risk_band="high", eligible_assessment_count=1, assessment_count=1, summary={}))
    db.commit()
    return scan


def cli_args(**overrides):
    values = {
        "authorized": True, "profile": "safe", "url": "https://platform.example/", "recon_mode": "passive_only",
        "allowed_domain": "platform.example", "allowed_path": "/", "excluded_path": "", "max_depth": 1,
        "max_pages": 3, "max_requests": 3, "max_concurrency": 1, "rate_limit_ms": 1000,
        "robots_override": False, "auth_json_file": None, "test_account_ref": None,
    }
    values.update(overrides)
    return Namespace(**values)


def test_capability_catalog_describes_scope_safe_public_operations():
    catalog = get_capabilities()

    assert catalog["version"] == "extension15-v1"
    assert catalog["safety"]["authorization_required_for_scan_creation"] is True
    assert {item["id"] for item in catalog["capabilities"]} >= {"create_scan", "progress_stream", "assets", "evidence", "findings", "graph", "compare", "report", "exports"}


def test_dashboard_and_filtered_findings_read_persisted_platform_data(db):
    scan = make_platform_scan(db)

    dashboard = get_dashboard_snapshot(limit=20, db=db)
    findings = list_platform_findings(scan.id, severity="high", min_confidence=90, db=db)

    assert dashboard["summary"]["scan_count"] == 1
    assert dashboard["scans"][0]["risk_score"] == 82.0
    assert findings["count"] == 1
    assert findings["findings"][0]["rule_id"] == "TEST-PLATFORM-001"


def test_cli_create_requires_explicit_authorization_and_preserves_scope_values():
    with pytest.raises(ValueError, match="--authorized"):
        create_payload(cli_args(authorized=False))

    payload = create_payload(cli_args())

    assert payload["authorization_acknowledged"] is True
    assert payload["allowed_domains"] == ["platform.example"]
    assert payload["allowed_paths"] == ["/"]
