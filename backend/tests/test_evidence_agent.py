from __future__ import annotations

from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.scan import Base, EvidenceReview, HTTPObservation, HTTPResponse, Page, Scan, SecurityFinding, Website
from app.services.evidence import EvidenceAgent, EvidenceValidationError
from app.services.tasks import TaskGraphCoordinator


def _scan(db: Session) -> tuple[Scan, Page, HTTPResponse]:
    website = Website(id=uuid4(), tenant_id="default", canonical_origin="example.com")
    db.add(website)
    db.flush()
    scan = Scan(id=uuid4(), website_id=website.id, state="COMPLETED", requested_url="https://example.com/", max_depth=1, max_pages=2, max_concurrency=1, request_delay_ms=100, same_domain_mode="hostname")
    db.add(scan)
    db.flush()
    page = Page(scan_id=scan.id, canonical_url="https://example.com/account?token=should-not-persist", depth=0)
    db.add(page)
    db.flush()
    response = HTTPResponse(page_id=page.id, status_code=200, final_url=page.canonical_url, content_type="text/html", timings_ms=10, raw_body="<html>account</html>")
    db.add(response)
    db.flush()
    db.commit()
    return scan, page, response


def test_evidence_agent_requires_evidence_for_legacy_gate(db: Session):
    scan, _, _ = _scan(db)
    agent = EvidenceAgent(db, scan.id)
    agent.validate_finding([{"source": "https://example.com/", "value": "safe"}])
    try:
        agent.validate_finding([])
    except EvidenceValidationError:
        pass
    else:
        raise AssertionError("empty evidence should be rejected")


def test_evidence_agent_aggregates_redacts_and_reproduces_from_persisted_response():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        scan, page, response = _scan(db)
        db.add(HTTPObservation(scan_id=scan.id, page_id=page.id, http_response_id=response.id, observation_type="headers", subject=page.canonical_url, source="http_agent", value={"authorization": "AKIA1234567890ABCDEF", "cache_control": "no-store"}, classification="OBSERVED", confidence=0.99, redacted=True, dedupe_key="header-evidence"))
        db.add(SecurityFinding(scan_id=scan.id, page_id=page.id, category="security", subject="Account response policy", statement="A security policy candidate was observed.", classification="OBSERVED", confidence=75, confidence_band="medium", severity="medium", rule_id="SEC-TEST-001", rule_version="test-v1", evidence=[{"source": page.canonical_url, "header": "authorization", "value": "AKIA1234567890ABCDEF"}]))
        db.commit()
        reviews = EvidenceAgent(db, scan.id).analyze()
        assert len(reviews) == 1
        review = reviews[0]
        assert review.finding_state in {"candidate", "validated"}
        assert review.evidence_quality in {"moderate", "strong"}
        assert review.reproducibility_state == "reproduced_from_persisted_response"
        assert review.redacted is True
        assert review.safe_request_metadata["network_request_issued"] is False
        assert "AKIA1234567890ABCDEF" not in str(review.observations)
        assert review.provenance[0]["target"] == "https://example.com/"
        assert {"target", "endpoint_or_asset", "source_agent", "timestamp", "rule_id", "observation_id"}.issubset(review.provenance[0])
        report = EvidenceAgent(db, scan.id).report()
        assert report["provenance_contract"]["signature_alone_is_proof"] is False
        assert report["provenance_contract"]["secret_values_redacted"] is True


def test_evidence_agent_inconclusive_without_observations():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        scan, _, _ = _scan(db)
        db.add(SecurityFinding(scan_id=scan.id, page_id=None, category="security", subject="Unlinked candidate", statement="Candidate with no evidence", classification="INFERRED", confidence=40, confidence_band="low", severity="low", rule_id="SEC-EMPTY-001", rule_version="test-v1", evidence=[]))
        db.commit()
        review = EvidenceAgent(db, scan.id).analyze()[0]
        assert review.finding_state == "rejected"
        assert review.evidence_quality == "none"
        assert review.prerequisites_valid is False
        assert review.confidence == 0


def test_evidence_agent_is_idempotent_and_task_waits_for_analysis_agents():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        scan, _, _ = _scan(db)
        db.add(SecurityFinding(scan_id=scan.id, page_id=None, category="security", subject="Candidate", statement="Evidence-backed candidate", classification="OBSERVED", confidence=50, confidence_band="medium", severity="low", rule_id="SEC-IDEMP-001", rule_version="test-v1", evidence=[{"source": "https://example.com/", "value": "marker"}]))
        db.commit()
        first = EvidenceAgent(db, scan.id).analyze()
        second = EvidenceAgent(db, scan.id).analyze()
        assert len(first) == len(second) == 1
        assert db.query(EvidenceReview).filter_by(scan_id=scan.id).count() == 1
        TaskGraphCoordinator.initialize_scan(db, scan.id)
        TaskGraphCoordinator.after_collection(db, scan.id)
        task_map = {task.task_type: task for task in scan.agent_tasks}
        assert task_map["evidence"].dependency_keys
        assert "security" in task_map["evidence"].dependency_keys
        assert "evidence" in task_map["diagnosis"].dependency_keys
