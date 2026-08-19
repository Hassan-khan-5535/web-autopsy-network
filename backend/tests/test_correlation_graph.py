from uuid import uuid4

from sqlalchemy.orm import Session

from app.api.routes.scans import get_scan_attack_surface_graph, get_scan_risk_prioritization
from app.models.scan import (
    ApiEndpoint,
    AttackSurfaceGraphEdge,
    AttackSurfaceGraphNode,
    AttackSurfaceGraphUpdate,
    Dependency,
    EvidenceReview,
    HTTPObservation,
    Page,
    ReconAsset,
    ReconEndpoint,
    ReconParameter,
    RiskAssessment,
    Scan,
    ScanRiskSummary,
    SecurityFinding,
    Technology,
    Website,
)
from app.services.correlation import CORRELATION_VERSION, CorrelationAgent
from app.services.risk import RISK_COMPONENT_WEIGHTS, RiskAgent
from app.services.tasks import TaskGraphCoordinator


def _scan(db: Session) -> Scan:
    website = Website(id=uuid4(), tenant_id="default", canonical_origin="example.com")
    db.add(website)
    db.flush()
    scan = Scan(
        id=uuid4(),
        website_id=website.id,
        state="COMPLETED",
        requested_url="https://app.example.com/",
        max_depth=1,
        max_pages=5,
        max_concurrency=1,
        request_delay_ms=100,
        same_domain_mode="hostname",
    )
    db.add(scan)
    db.flush()
    return scan


def _seed_evidence(db: Session, scan: Scan) -> None:
    page = Page(scan_id=scan.id, canonical_url="https://app.example.com/account", depth=0, status_code=200, title="Account")
    db.add(page)
    db.flush()
    endpoint = ReconEndpoint(
        scan_id=scan.id,
        endpoint_kind="api",
        url_or_path="https://api.example.com/v1/account",
        http_method="GET",
        source="test",
        classification="OBSERVED",
        confidence=1.0,
        scope_status="in_scope",
        status_code=200,
        page_id=page.id,
        attributes={},
        evidence=[{"id": "recon-1"}],
        dedupe_key="api-account",
    )
    db.add(endpoint)
    db.flush()
    db.add_all([
        ReconAsset(
            scan_id=scan.id,
            asset_type="cloud_service",
            value="cdn.cloudfront.net",
            hostname="cdn.cloudfront.net",
            source="test",
            discovery_mode="passive_only",
            classification="OBSERVED",
            scope_status="in_scope",
            confidence=1.0,
            attributes={},
            evidence=[{"id": "asset-1"}],
            dedupe_key="cloudfront",
        ),
        ReconParameter(
            scan_id=scan.id,
            endpoint_id=endpoint.id,
            page_id=page.id,
            name="account_id",
            location="query",
            source="test",
            discovery_mode="passive_only",
            classification="OBSERVED",
            confidence=1.0,
            scope_status="in_scope",
            example_value=None,
            evidence=[{"id": "param-1"}],
            dedupe_key="account-id",
        ),
        ApiEndpoint(
            scan_id=scan.id,
            url_or_path="https://api.example.com/v1/account",
            http_method="GET",
            content_type="application/json",
            classification="OBSERVED",
            confidence=1.0,
            discovered_from_source="test",
        ),
        Technology(
            scan_id=scan.id,
            canonical_name="Next.js",
            category="framework",
            classification="inferred",
            confidence=85.0,
            confidence_band="high",
            rule_version="test",
        ),
        Dependency(
            scan_id=scan.id,
            domain="cdn.cloudfront.net",
            category="cloud",
            classification="inferred",
            confidence=80.0,
            reference_count=2,
            sample_resource_urls=[],
        ),
        HTTPObservation(
            scan_id=scan.id,
            page_id=page.id,
            observation_type="header",
            subject="content-security-policy",
            source="test",
            classification="OBSERVED",
            confidence=1.0,
            value={"present": False},
            redacted=True,
            truncated=False,
            dedupe_key="csp",
        ),
    ])
    db.flush()
    finding = SecurityFinding(
        scan_id=scan.id,
        page_id=page.id,
        category="security",
        subject="Missing Content-Security-Policy",
        statement="A Content-Security-Policy header was not observed in the stored response.",
        classification="OBSERVED",
        confidence=96.0,
        confidence_band="high",
        severity="high",
        rule_id="SEC-CSP-001",
        rule_version="test",
        evidence=[{"id": "obs-csp", "type": "header", "source": "test", "observation": "CSP was not observed."}],
        limitations="Stored evidence only.",
    )
    db.add(finding)
    db.flush()
    db.add(EvidenceReview(
        scan_id=scan.id,
        security_finding_id=finding.id,
        candidate_key="SEC-CSP-001:account",
        target="https://app.example.com/account",
        endpoint_or_asset="https://app.example.com/account",
        source_agent="EvidenceAgent",
        rule_id="SEC-CSP-001",
        finding_state="validated",
        evidence_quality="strong",
        confidence=96.0,
        prerequisites_valid=True,
        reproducibility_state="reproduced_from_persisted_response",
        observations=[{"observation": "CSP absent"}],
        safe_request_metadata=None,
        provenance=[{"id": "obs-csp"}],
        redacted=True,
    ))
    db.commit()


def test_correlation_agent_builds_evidence_backed_graph_and_safe_priority_paths(db: Session):
    scan = _scan(db)
    _seed_evidence(db, scan)

    result = CorrelationAgent(db, scan.id).analyze(source_event="test:seed")
    report = CorrelationAgent(db, scan.id).report()

    assert result["inserted_node_count"] > 0
    assert result["inserted_edge_count"] > 0
    assert report["correlation_version"] == CORRELATION_VERSION
    assert {"Domain", "Host", "Application", "Endpoint", "API", "Parameter", "Technology", "Finding", "Evidence", "Cloud Asset"}.issubset({node["entity_type"] for node in report["nodes"]})
    assert "POTENTIAL_ESCALATION_PRIORITY" in {edge["relationship_type"] for edge in report["edges"]}
    assert report["safety_contract"]["autonomous_exploitation_supported"] is False
    assert report["safety_contract"]["network_requests_performed"] is False
    assert report["priority_paths"][0]["disclaimer"].startswith("Prioritization only")
    assert db.query(AttackSurfaceGraphNode).filter_by(scan_id=scan.id).count() == report["summary"]["node_count"]
    assert db.query(AttackSurfaceGraphEdge).filter_by(scan_id=scan.id).count() == report["summary"]["edge_count"]
    assert db.query(AttackSurfaceGraphUpdate).filter_by(scan_id=scan.id).count() == 1

    route_report = get_scan_attack_surface_graph(scan.id, db)
    assert route_report["scan_id"] == str(scan.id)
    assert route_report["summary"]["priority_path_count"] == 1


def test_correlation_agent_rerun_refreshes_stable_records_without_duplication(db: Session):
    scan = _scan(db)
    _seed_evidence(db, scan)
    agent = CorrelationAgent(db, scan.id)
    first = agent.analyze(source_event="test:first")
    node_count = db.query(AttackSurfaceGraphNode).filter_by(scan_id=scan.id).count()
    edge_count = db.query(AttackSurfaceGraphEdge).filter_by(scan_id=scan.id).count()

    second = agent.analyze(source_event="test:second")

    assert first["inserted_node_count"] == node_count
    assert first["inserted_edge_count"] == edge_count
    assert second["inserted_node_count"] == 0
    assert second["inserted_edge_count"] == 0
    assert second["refreshed_node_count"] >= node_count
    assert second["refreshed_edge_count"] >= edge_count
    assert db.query(AttackSurfaceGraphNode).filter_by(scan_id=scan.id).count() == node_count
    assert db.query(AttackSurfaceGraphEdge).filter_by(scan_id=scan.id).count() == edge_count
    assert db.query(AttackSurfaceGraphUpdate).filter_by(scan_id=scan.id).count() == 2


def test_correlation_task_waits_for_evidence_and_gates_diagnosis(db: Session):
    scan = _scan(db)

    TaskGraphCoordinator.initialize_scan(db, scan.id)
    TaskGraphCoordinator.after_collection(db, scan.id)
    task_map = {task.task_type: task for task in scan.agent_tasks}

    assert task_map["correlation"].dependency_keys == ["evidence"]
    assert "correlation" in task_map["diagnosis"].dependency_keys
    assert task_map["risk"].dependency_keys == ["correlation", "evidence"]
    assert "risk" in task_map["diagnosis"].dependency_keys


def test_risk_agent_persists_transparent_scores_and_safe_contract(db: Session):
    scan = _scan(db)
    _seed_evidence(db, scan)
    CorrelationAgent(db, scan.id).analyze(source_event="test:risk")

    assessments = RiskAgent(db, scan.id).analyze()
    report = RiskAgent(db, scan.id).report()

    assert len(assessments) == 1
    assert db.query(RiskAssessment).filter_by(scan_id=scan.id).count() == 1
    assert db.query(ScanRiskSummary).filter_by(scan_id=scan.id).count() == 1
    assessment = report["assessments"][0]
    assert set(assessment["score_components"]) == set(RISK_COMPONENT_WEIGHTS)
    assert sum(component["weight"] for component in assessment["score_components"].values()) == 100
    assert assessment["risk_score"] >= 70
    assert assessment["evidence_snapshot"]["secret_values_included"] is False
    assert report["scoring_contract"]["model"] == "deterministic_heuristic"
    assert report["scoring_contract"]["opaque_override_allowed"] is False
    assert report["scoring_contract"]["active_exploitation_supported"] is False
    assert get_scan_risk_prioritization(scan.id, db)["summary"]["available"] is True


def test_risk_agent_caps_nonvalidated_evidence_and_compares_same_target(db: Session):
    current = _scan(db)
    _seed_evidence(db, current)
    review = db.query(EvidenceReview).filter_by(scan_id=current.id).one()
    review.finding_state = "candidate"
    db.commit()
    CorrelationAgent(db, current.id).analyze(source_event="test:current")

    prior = Scan(
        id=uuid4(),
        website_id=current.website_id,
        state="COMPLETED",
        requested_url="https://app.example.com/",
        max_depth=1,
        max_pages=5,
        max_concurrency=1,
        request_delay_ms=100,
        same_domain_mode="hostname",
    )
    db.add(prior)
    db.flush()
    prior_finding = SecurityFinding(
        scan_id=prior.id,
        category="security",
        subject="Missing Content-Security-Policy",
        statement="Stored CSP observation.",
        classification="OBSERVED",
        confidence=80.0,
        confidence_band="high",
        severity="medium",
        rule_id="SEC-CSP-001",
        rule_version="test",
        evidence=[{"id": "prior-csp"}],
        limitations="Stored evidence only.",
    )
    db.add(prior_finding)
    db.commit()
    RiskAgent(db, prior.id).analyze()
    RiskAgent(db, current.id).analyze()
    report = RiskAgent(db, current.id).report()

    assert report["assessments"][0]["risk_score"] <= 69.99
    assert any("capped" in note.lower() for note in report["assessments"][0]["decision_notes"])
    assert report["trend"]["prior_scan"]["scan_id"] == str(prior.id)
    assert report["trend"]["movement"] in {"increased", "decreased", "stable"}
    assert len(report["trend"]["series"]) == 2
