from datetime import UTC, datetime

import pytest

from app.models.scan import ContentFinding, PerformanceMetric, Scan, SecurityFinding, Website
from app.services.diagnosis import CAUSE_OF_DEATH_DISCLAIMER, CauseOfDeathEngine, CauseOfDeathNarrative
from app.services.evidence import EvidenceValidationError
from app.services.risk import RUBRIC_WEIGHTS, RiskImpactEngine


class FakeLLM:
    def __init__(self, response):
        self.response = response

    def generate_json(self, _system_prompt, _user_prompt):
        return self.response


def seed_diagnosis_scan(db):
    website = Website(canonical_origin="diagnosis.example")
    db.add(website)
    db.flush()
    scan = Scan(website_id=website.id, requested_url="https://diagnosis.example", state="COMPLETED", created_at=datetime.now(UTC))
    db.add(scan)
    db.flush()
    huge_js = PerformanceMetric(
        scan_id=scan.id, scope="site", metric_name="diagnosis:large_js_payload", value=9000000,
        unit="bytes", classification="OBSERVED", confidence=100, confidence_band="high",
        capture_mode="test", statement="JavaScript payload is the largest captured contributor.",
        evidence=[{"id": "js-observation", "type": "resource", "observation": "9 MB JavaScript", "source": "https://diagnosis.example/"}],
    )
    security = SecurityFinding(
        scan_id=scan.id, category="security", subject="Content-Security-Policy", statement="Header missing",
        classification="OBSERVED", confidence=100, confidence_band="high", severity="low", rule_id="csp",
        rule_version="test", evidence=[{"id": "csp-observation", "type": "header", "observation": "CSP missing", "source": "https://diagnosis.example/"}],
    )
    content = ContentFinding(
        scan_id=scan.id, category="metadata", subject="description", statement="Meta description missing",
        classification="OBSERVED", evidence=[{"id": "seo-observation", "type": "metadata", "observation": "description missing", "source": "https://diagnosis.example/"}],
    )
    db.add_all([huge_js, security, content])
    db.commit()
    return scan


def test_risk_rubric_is_explicit_and_dominant_issue_wins(db):
    scan = seed_diagnosis_scan(db)
    ranked = RiskImpactEngine(db, scan.id).rank()
    assert set(RUBRIC_WEIGHTS) == {"impact", "confidence", "severity", "dependency_criticality", "frequency", "user_facing_effect"}
    assert sum(RUBRIC_WEIGHTS.values()) == pytest.approx(1.0)
    assert ranked[0]["subject"] == "diagnosis:large_js_payload"
    assert ranked[0]["evidence"]
    assert all(0 <= item["score"] <= 100 for item in ranked)


def test_diagnosis_persists_traceable_selection_and_disclaimer(db):
    scan = seed_diagnosis_scan(db)
    engine = CauseOfDeathEngine(db, scan.id)
    computed = engine.compute()
    persisted = engine.persist(narrative=CauseOfDeathNarrative(db).generate(computed))
    assert persisted["primary_issue"]["subject"] == "diagnosis:large_js_payload"
    assert persisted["evidence_count"] == len({item["id"] for item in persisted["evidence"]})
    assert persisted["evidence_count"] >= persisted["primary_issue"]["evidence_count"]
    assert persisted["disclaimer"] == CAUSE_OF_DEATH_DISCLAIMER
    assert persisted["ai_narrative"]


def test_ai_narrative_cannot_cite_outside_diagnosis_evidence(db):
    scan = seed_diagnosis_scan(db)
    diagnosis = CauseOfDeathEngine(db, scan.id).compute()
    narrative_engine = CauseOfDeathNarrative(db)
    narrative_engine.llm = FakeLLM({"narrative": "Contradictory claim", "evidence": ["fabricated-id"]})
    fallback = narrative_engine.generate(diagnosis)
    assert fallback["status"] == "graceful_degradation"
    assert diagnosis["primary_issue"]["subject"] in fallback["narrative"]
    assert set(fallback["evidence"]).issubset({entry["id"] for entry in diagnosis["evidence"]})
