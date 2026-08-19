"""Extension 15 public capability catalog and premium-dashboard data routes."""

from __future__ import annotations

from collections import Counter
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.scan import Scan, ScanRiskSummary, SecurityPostureSnapshot, Website
from app.services.reporting import SecurityReportService
from app.services.updates import UpdatePackageService

router = APIRouter()

CAPABILITIES = {
    "version": "extension15-v1",
    "safety": {
        "authorization_required_for_scan_creation": True,
        "scope_revalidated_before_agent_actions": True,
        "profiles": ["safe", "normal", "aggressive"],
        "prohibited": ["active exploitation", "scope expansion", "state-changing target actions"],
    },
    "capabilities": [
        {"id": "create_scan", "method": "POST", "path": "/v1/scans", "description": "Create an authorization-gated bounded assessment with scope and optional test-account configuration."},
        {"id": "scan_status", "method": "GET", "path": "/v1/scans/{scan_id}", "description": "Retrieve persisted scan state and configuration summary."},
        {"id": "progress_stream", "method": "GET", "path": "/v1/scans/{scan_id}/progress/stream", "description": "Stream persisted task, event, dependency, and budget progress."},
        {"id": "assets", "method": "GET", "path": "/v1/scans/{scan_id}/recon", "description": "List persisted assets, endpoints, parameters, and scope classifications."},
        {"id": "evidence", "method": "GET", "path": "/v1/scans/{scan_id}/evidence", "description": "List persisted evidence with source redaction."},
        {"id": "findings", "method": "GET", "path": "/v1/platform/scans/{scan_id}/findings", "description": "List evidence-backed findings, optionally filtered by severity and minimum confidence."},
        {"id": "graph", "method": "GET", "path": "/v1/scans/{scan_id}/attack-surface-graph", "description": "Inspect the persisted attack-surface graph."},
        {"id": "compare", "method": "POST", "path": "/v1/scans/compare", "description": "Compare persisted scans of the same target."},
        {"id": "report", "method": "GET", "path": "/v1/scans/{scan_id}/report", "description": "Retrieve the unified security posture report."},
        {"id": "exports", "method": "GET", "path": "/v1/scans/{scan_id}/report/export/{pdf|json|sarif}", "description": "Download redaction-preserving report exports."},
        {"id": "update_status", "method": "GET", "path": "/v1/platform/updates", "description": "Inspect locally verified rule and signature package provenance, activation, rollback, and offline fallback state."},
    ],
}


@router.get("/capabilities")
def get_capabilities():
    """Return an explicit API capability map for API clients and the CLI."""
    return CAPABILITIES


@router.get("/platform/dashboard")
def get_dashboard_snapshot(limit: int = Query(default=20, ge=1, le=100), db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(limit).all()
    state_counts = Counter(item.state for item in scans)
    risk_by_scan = {item.scan_id: item for item in db.query(ScanRiskSummary).filter(ScanRiskSummary.scan_id.in_([scan.id for scan in scans] or [UUID(int=0)])).all()}
    posture_by_scan = {item.scan_id: item for item in db.query(SecurityPostureSnapshot).filter(SecurityPostureSnapshot.scan_id.in_([scan.id for scan in scans] or [UUID(int=0)])).all()}
    websites = {item.id: item for item in db.query(Website).filter(Website.id.in_([scan.website_id for scan in scans] or [UUID(int=0)])).all()}
    return {
        "version": "extension15-v1",
        "summary": {
            "scan_count": len(scans),
            "target_count": len({item.website_id for item in scans}),
            "state_counts": dict(sorted(state_counts.items())),
            "active_scan_count": sum(state_counts.get(item, 0) for item in ("QUEUED", "VALIDATING", "COLLECTING", "ANALYZING", "SYNTHESIZING", "CANCELLING")),
        },
        "scans": [
            {
                "id": str(scan.id), "website_id": str(scan.website_id), "target_url": scan.requested_url,
                "canonical_origin": websites.get(scan.website_id).canonical_origin if scan.website_id in websites else None,
                "state": scan.state, "assessment_profile": scan.assessment_profile,
                "created_at": scan.created_at.isoformat(), "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                "risk_score": round(risk_by_scan[scan.id].overall_score, 1) if scan.id in risk_by_scan else None,
                "risk_band": risk_by_scan[scan.id].risk_band if scan.id in risk_by_scan else None,
                "posture_available": scan.id in posture_by_scan,
                "page_count": len(scan.pages),
            }
            for scan in scans
        ],
    }


@router.get("/platform/updates")
def get_update_status(db: Session = Depends(get_db)):
    """Read-only visibility into the local, verified update package lifecycle."""
    return UpdatePackageService(db).status()


@router.get("/platform/scans/{scan_id}/findings")
def list_platform_findings(
    scan_id: UUID,
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|info)$"),
    min_confidence: float | None = Query(default=None, ge=0, le=100),
    db: Session = Depends(get_db),
):
    try:
        report = SecurityReportService(db).build(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    findings = report["technical_findings"]
    if severity:
        findings = [item for item in findings if item["severity"] == severity]
    if min_confidence is not None:
        findings = [item for item in findings if item["confidence"] >= min_confidence]
    return {"scan_id": str(scan_id), "filters": {"severity": severity, "min_confidence": min_confidence}, "count": len(findings), "findings": findings}
