from app.core.database import SessionLocal
from app.models.scan import ContentFinding, Dependency, PerformanceMetric, Scan, SecurityFinding

with SessionLocal() as db:
    scan = db.query(Scan).filter(Scan.requested_url == "https://demo.example", Scan.state == "COMPLETED").order_by(Scan.created_at.desc()).first()
    if not scan:
        raise SystemExit("No completed demo scan found")
    if not db.query(PerformanceMetric).filter(PerformanceMetric.scan_id == scan.id, PerformanceMetric.metric_name == "diagnosis:large_js_payload").first():
        db.add(PerformanceMetric(
            scan_id=scan.id,
            scope="site",
            metric_name="diagnosis:large_js_payload",
            value=9000000,
            unit="bytes",
            classification="OBSERVED",
            confidence=100,
            confidence_band="high",
            capture_mode="demo_fixture",
            statement="JavaScript payload is the largest captured contributor at 9 MB.",
            evidence=[{"id": "phase12-js-payload", "type": "resource", "observation": "9 MB JavaScript payload", "source": "https://demo.example/"}],
        ))
    if not db.query(SecurityFinding).filter(SecurityFinding.scan_id == scan.id, SecurityFinding.rule_id == "phase12-csp").first():
        db.add(SecurityFinding(
            scan_id=scan.id,
            category="security",
            subject="Content-Security-Policy",
            statement="Content-Security-Policy was not observed in the stored response headers.",
            classification="OBSERVED",
            confidence=100,
            confidence_band="high",
            severity="low",
            rule_id="phase12-csp",
            rule_version="phase12-demo",
            evidence=[{"id": "phase12-csp", "type": "header", "observation": "CSP missing", "source": "https://demo.example/"}],
        ))
    if not db.query(ContentFinding).filter(ContentFinding.scan_id == scan.id, ContentFinding.subject == "Meta description").first():
        db.add(ContentFinding(
            scan_id=scan.id,
            category="metadata",
            subject="Meta description",
            statement="Meta description was not observed on the demo page.",
            classification="OBSERVED",
            evidence=[{"id": "phase12-meta-description", "type": "metadata", "observation": "description missing", "source": "https://demo.example/"}],
        ))
    db.commit()
    print(scan.id)
