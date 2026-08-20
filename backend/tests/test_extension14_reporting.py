from app.models.scan import BrowserScreenshot, EvidenceReview, RiskAssessment, Scan, ScanRiskSummary, SecurityFinding, Website
from app.services.reporting import MinimalPdfRenderer, SecurityReportService


def make_reportable_scan(db):
    website = Website(canonical_origin="report.example")
    db.add(website)
    db.flush()
    scan = Scan(
        website_id=website.id,
        requested_url="https://report.example/",
        state="COMPLETED",
        assessment_profile="safe",
        recon_mode="passive_only",
    )
    db.add(scan)
    db.flush()
    finding = SecurityFinding(
        scan_id=scan.id,
        category="security",
        subject="https://report.example/account?token=visible-name-only",
        statement="Sensitive-looking client-visible value was observed in the approved response evidence.",
        classification="OBSERVED",
        confidence=91.0,
        confidence_band="high",
        severity="high",
        rule_id="VULN-DATA-001",
        rule_version="test-v1",
        evidence=[{"response_note": "api_key=should-not-export", "safe": "approved observation"}],
    )
    db.add(finding)
    db.flush()
    db.add(RiskAssessment(
        scan_id=scan.id,
        security_finding_id=finding.id,
        deterministic_version="extension11-v1",
        risk_score=82.5,
        risk_band="high",
        eligible_for_prioritization=True,
        evidence_state="validated",
        score_components={"severity": 30},
        decision_notes=["test"],
        evidence_snapshot={"reviewed": True},
    ))
    db.add(EvidenceReview(
        scan_id=scan.id,
        security_finding_id=finding.id,
        candidate_key="reporting-test",
        target=scan.requested_url,
        endpoint_or_asset="/account",
        source_agent="test",
        rule_id=finding.rule_id,
        finding_state="validated",
        evidence_quality="high",
        confidence=91.0,
        prerequisites_valid=True,
        reproducibility_state="not_run",
        observations=["approved observation"],
        safe_request_metadata={"method": "GET"},
        provenance=[{"source": "test"}],
        redacted=True,
    ))
    db.add(ScanRiskSummary(
        scan_id=scan.id,
        website_id=website.id,
        deterministic_version="extension11-v1",
        overall_score=82.5,
        risk_band="high",
        eligible_assessment_count=1,
        assessment_count=1,
        summary={"high": 1},
    ))
    db.commit()
    return scan


def test_unified_report_preserves_redaction_and_safe_breakpoint_boundary(db):
    scan = make_reportable_scan(db)

    report = SecurityReportService(db).build(scan.id)

    assert report["report_version"] == "extension14-v1"
    assert report["executive_summary"]["overall_risk_score"] == 82.5
    assert report["technical_findings"][0]["affected_parameter"] == "token"
    assert report["technical_findings"][0]["evidence"][0]["response_note"] == "[REDACTED]"
    breakpoint = report["exploitation_breakpoints"][0]
    assert breakpoint["entry_point"].startswith("https://report.example/")
    assert "omits exploit code" in breakpoint["safety_note"]
    assert report["safe_screenshot_summary"]["status"] == "not_available"


def test_sarif_and_pdf_exports_are_portable_and_evidence_backed(db):
    scan = make_reportable_scan(db)
    service = SecurityReportService(db)

    sarif = service.sarif(scan.id)
    pdf = service.pdf(scan.id)

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "VULN-DATA-001"
    assert sarif["runs"][0]["results"][0]["properties"]["redacted"] is True
    assert pdf.startswith(b"%PDF-1.4")
    assert b"xref" in pdf and pdf.rstrip().endswith(b"%%EOF")


def test_minimal_pdf_renderer_supports_multiple_pages_without_external_dependencies():
    pdf = MinimalPdfRenderer.render([f"Line {index}" for index in range(100)])

    assert pdf.startswith(b"%PDF-1.4")
    assert b"/Count 3" in pdf


def test_unavailable_analysis_is_not_reported_as_medium_or_high_risk(db):
    scan = make_reportable_scan(db)
    finding = scan.security_findings[0]
    finding.rule_id = "security_analysis_unavailable"
    finding.severity = "info"
    summary = scan.risk_summary
    summary.overall_score = 57.0
    summary.risk_band = "medium"
    db.commit()

    report = SecurityReportService(db).build(scan.id)

    assert report["executive_summary"]["coverage_state"] == "analysis_unavailable"
    assert report["executive_summary"]["overall_risk_score"] == 0.0
    assert report["executive_summary"]["risk_band"] == "not_analyzed"
    assert "No vulnerability conclusion" in report["executive_summary"]["summary"]


def test_report_counts_persisted_safe_screenshots(db):
    scan = make_reportable_scan(db)
    page = scan.pages[0] if scan.pages else None
    if page is None:
        from app.models.scan import Page
        page = Page(scan_id=scan.id, canonical_url=scan.requested_url, depth=0)
        db.add(page)
        db.flush()
    db.add(BrowserScreenshot(scan_id=scan.id, page_id=page.id, image_base64="iVBORw0KGgo=", sha256="a" * 64))
    db.commit()

    report = SecurityReportService(db).build(scan.id)
    assert report["safe_screenshot_summary"]["captured_screenshot_count"] == 1
    assert report["safe_screenshot_summary"]["status"] == "available"


def test_completed_analyzed_report_has_no_generic_limitation_text(db):
    scan = make_reportable_scan(db)
    report = SecurityReportService(db).build(scan.id)
    assert report["executive_summary"]["limitations"] == []


def test_incomplete_report_has_only_state_specific_coverage_note(db):
    scan = make_reportable_scan(db)
    scan.state = "ANALYZING"
    db.commit()
    report = SecurityReportService(db).build(scan.id)
    assert report["executive_summary"]["limitations"] == ["Coverage is incomplete because the scan ended in analyzing state."]


def test_report_posture_counts_match_deduplicated_findings(db):
    scan = make_reportable_scan(db)
    report = SecurityReportService(db).build(scan.id)
    findings = report["technical_findings"]
    posture = report["security_posture"]["summary"]
    assert posture["security_finding_count"] == len(findings)
    assert posture["severity_counts"] == {"high": 1}
