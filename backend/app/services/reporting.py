"""Evidence-backed Extension 14 reporting and safe export generation."""

from __future__ import annotations

import io
import json
import re
import textwrap
from collections import Counter
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlsplit
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.scan import (
    AttackSurfaceGraphEdge,
    AttackSurfaceGraphNode,
    BrowserScreenshot,
    ApiEndpoint,
    CVEIntelligence,
    EvidenceReview,
    ReconAsset,
    ReconEndpoint,
    RiskAssessment,
    Scan,
    ScanDifference,
    ScanRiskSummary,
    SecurityFinding,
    SecurityPostureSnapshot,
    TechnologyCVEMatch,
)

REPORT_VERSION = "extension14-v1"
SARIF_VERSION = "2.1.0"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SENSITIVE_TERMS = ("password", "secret", "token", "cookie", "authorization", "api_key", "apikey", "credential")


def utc_now() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class SecurityReportService:
    """Build a single redaction-preserving report model for UI and machine exports."""

    def __init__(self, db: Session):
        self.db = db

    def build(self, scan_id: UUID) -> dict[str, Any]:
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError("Scan not found")

        findings = self.db.query(SecurityFinding).filter(SecurityFinding.scan_id == scan.id).all()
        risk_by_finding = {
            item.security_finding_id: item
            for item in self.db.query(RiskAssessment).filter(RiskAssessment.scan_id == scan.id).all()
        }
        evidence_by_finding: dict[UUID, list[EvidenceReview]] = {}
        for review in self.db.query(EvidenceReview).filter(EvidenceReview.scan_id == scan.id).all():
            if review.security_finding_id:
                evidence_by_finding.setdefault(review.security_finding_id, []).append(review)
        cves = self._cves(scan.id)
        technical_findings = []
        seen_semantic_findings: set[tuple[str, str]] = set()
        for finding in sorted(findings, key=lambda item: self._finding_sort_key(item, risk_by_finding.get(item.id))):
            payload = self._finding_payload(finding, risk_by_finding.get(finding.id), evidence_by_finding.get(finding.id, []), cves)
            semantic_key = self._semantic_key(payload)
            if semantic_key in seen_semantic_findings:
                continue
            seen_semantic_findings.add(semantic_key)
            technical_findings.append(payload)
        risk_summary = self.db.query(ScanRiskSummary).filter(ScanRiskSummary.scan_id == scan.id).first()
        posture = self.db.query(SecurityPostureSnapshot).filter(SecurityPostureSnapshot.scan_id == scan.id).first()
        trend = self._trend(scan, posture)
        attack_surface = self._attack_surface(scan.id)
        severity_counts = dict(sorted(Counter(item["severity"] for item in technical_findings).items()))
        actionable = [item for item in technical_findings if item["eligible_for_prioritization"]]
        analysis_unavailable = self._analysis_unavailable(scan)
        screenshot_count = self.db.query(BrowserScreenshot).filter(BrowserScreenshot.scan_id == scan.id).count()
        executive = {
            "overall_risk_score": 0.0 if analysis_unavailable else (round(risk_summary.overall_score, 1) if risk_summary else 0.0),
            "risk_band": "not_analyzed" if analysis_unavailable else (risk_summary.risk_band if risk_summary else "info"),
            "coverage_state": "analysis_unavailable" if analysis_unavailable else "analyzed",
            "scan_state": scan.state,
            "finding_count": len(technical_findings),
            "prioritized_finding_count": len(actionable),
            "severity_counts": severity_counts,
            "summary": self._executive_summary(scan, actionable, risk_summary, severity_counts, analysis_unavailable=analysis_unavailable),
            "limitations": self._limitations(scan, analysis_unavailable),
        }
        security_posture = self._posture(posture, risk_summary)
        posture_summary = dict(security_posture.get("summary") or {})
        posture_summary.update({
            "security_finding_count": len(technical_findings),
            "vulnerability_count": sum(1 for item in technical_findings if item["category"] == "vulnerability"),
            "configuration_finding_count": sum(1 for item in technical_findings if item["category"] == "configuration"),
            "secret_finding_count": sum(1 for item in technical_findings if item["category"] == "secrets"),
            "severity_counts": severity_counts,
        })
        security_posture = {**security_posture, "summary": posture_summary}
        if analysis_unavailable:
            security_posture = {
                **security_posture,
                "overall_risk_score": 0.0,
                "risk_band": "not_analyzed",
                "summary": {**(security_posture.get("summary") or {}), "coverage_state": "analysis_unavailable"},
                "limitation": "Security analysis was unavailable; posture is not a vulnerability verdict.",
            }
        return {
            "report_version": REPORT_VERSION,
            "generated_at": utc_now().isoformat(),
            "scan": {
                "id": str(scan.id), "target_url": scan.requested_url, "state": scan.state,
                "assessment_profile": scan.assessment_profile, "recon_mode": scan.recon_mode,
                "created_at": as_utc(scan.created_at).isoformat() if scan.created_at else None,
                "finished_at": as_utc(scan.finished_at).isoformat() if scan.finished_at else None,
            },
            "executive_summary": executive,
            "technical_findings": technical_findings,
            "exploitation_breakpoints": self._breakpoints(actionable),
            "security_posture": security_posture,
            "trend_comparison": trend,
            "attack_surface_summary": attack_surface,
            "safe_screenshot_summary": {
                "captured_screenshot_count": screenshot_count,
                "status": "available" if screenshot_count else "not_available",
                "note": "Screenshots are bounded viewport captures from public pages; authenticated pages are skipped to avoid persisting private content." if screenshot_count else "No safe public-page screenshot was persisted for this scan.",
            },
        }

    def sarif(self, scan_id: UUID) -> dict[str, Any]:
        report = self.build(scan_id)
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []
        for finding in report["technical_findings"]:
            rule_id = finding["rule_id"]
            rules.setdefault(rule_id, {
                "id": rule_id,
                "name": self._sarif_name(rule_id),
                "shortDescription": {"text": finding["statement"][:240]},
                "help": {"text": finding["remediation"]},
                "properties": {"references": finding["references"], "report_version": REPORT_VERSION},
            })
            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": self._sarif_level(finding["severity"]),
                "message": {"text": finding["statement"]},
                "properties": {
                    "confidence": finding["confidence"],
                    "confidence_band": finding["confidence_band"],
                    "risk_score": finding["risk_score"],
                    "risk_band": finding["risk_band"],
                    "evidence_state": finding["evidence_state"],
                    "evidence_quality": finding["evidence_quality"],
                    "classification": finding["classification"],
                    "redacted": True,
                },
            }
            if finding["affected_url"]:
                result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": finding["affected_url"]}}}]
            results.append(result)
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": SARIF_VERSION,
            "runs": [{
                "tool": {"driver": {"name": "Web Autopsy Network", "version": REPORT_VERSION, "rules": list(rules.values())}},
                "automationDetails": {"id": f"web-autopsy/{report['scan']['id']}"},
                "invocations": [{"executionSuccessful": report["scan"]["state"] == "COMPLETED"}],
                "results": results,
                "properties": {
                    "scan_id": report["scan"]["id"],
                    "risk_score": report["executive_summary"]["overall_risk_score"],
                    "risk_band": report["executive_summary"]["risk_band"],
                    "limitations": report["executive_summary"]["limitations"],
                },
            }],
        }

    def pdf(self, scan_id: UUID) -> bytes:
        report = self.build(scan_id)
        lines = [
            "WEB AUTOPSY NETWORK — SECURITY POSTURE REPORT",
            f"Target: {report['scan']['target_url']}",
            f"Scan: {report['scan']['id']}  State: {report['scan']['state']}",
            f"Generated: {report['generated_at']}", "",
            "EXECUTIVE SUMMARY",
            report["executive_summary"]["summary"],
            f"Overall risk: {report['executive_summary']['overall_risk_score']} ({report['executive_summary']['risk_band']})",
            f"Severity counts: {json.dumps(report['executive_summary']['severity_counts'], sort_keys=True)}", "",
            *( ["COVERAGE NOTES", *report["executive_summary"]["limitations"], ""] if report["executive_summary"]["limitations"] else [] ),
            "TECHNICAL FINDINGS",
        ]
        for index, finding in enumerate(report["technical_findings"], start=1):
            lines.extend([
                f"{index}. [{finding['severity'].upper()}] {finding['rule_id']} — {finding['subject']}",
                finding["statement"],
                f"Confidence: {finding['confidence']} ({finding['confidence_band']}); Risk: {finding['risk_score']} ({finding['risk_band']})",
                f"Remediation: {finding['remediation']}",
                f"References: {', '.join(item['label'] for item in finding['references']) or 'None mapped'}", "",
            ])
        lines.extend(["EXPLOITATION BREAKPOINTS — HIGH-LEVEL PRIORITIZATION ONLY"])
        for point in report["exploitation_breakpoints"]:
            lines.extend([f"• {point['entry_point']}: {point['why_it_matters']}", point["safety_note"]])
        lines.extend(["", "ATTACK SURFACE SUMMARY", json.dumps(report["attack_surface_summary"], sort_keys=True), "", "TREND COMPARISON", json.dumps(report["trend_comparison"], sort_keys=True)])
        return MinimalPdfRenderer.render(lines)

    def _finding_payload(self, finding: SecurityFinding, risk: RiskAssessment | None, reviews: list[EvidenceReview], cves: list[dict[str, Any]]) -> dict[str, Any]:
        best_review = max(reviews, key=lambda item: item.confidence, default=None)
        return {
            "id": str(finding.id), "rule_id": finding.rule_id, "category": finding.category,
            "severity": (finding.severity or "info").lower(), "confidence": round(float(finding.confidence or 0.0), 1),
            "confidence_band": finding.confidence_band or "unknown", "classification": finding.classification,
            "subject": finding.subject, "affected_url": finding.subject if self._is_url(finding.subject) else (finding.page.canonical_url if finding.page else None),
            "affected_parameter": self._parameter(finding.subject), "statement": finding.statement,
            "evidence": self._redact(finding.evidence), "evidence_state": risk.evidence_state if risk else (best_review.finding_state if best_review else "not_reviewed"),
            "evidence_quality": best_review.evidence_quality if best_review else "not_available",
            "risk_score": round(float(risk.risk_score), 1) if risk else 0.0,
            "risk_band": risk.risk_band if risk else "info",
            "eligible_for_prioritization": bool(risk.eligible_for_prioritization) if risk else False,
            "remediation": self._remediation(finding),
            "references": self._references(finding, cves),
            "limitations": finding.limitations,
        }

    def _attack_surface(self, scan_id: UUID) -> dict[str, Any]:
        nodes = self.db.query(AttackSurfaceGraphNode).filter(AttackSurfaceGraphNode.scan_id == scan_id).all()
        edges = self.db.query(AttackSurfaceGraphEdge).filter(AttackSurfaceGraphEdge.scan_id == scan_id).all()
        return {
            "asset_count": self.db.query(ReconAsset).filter(ReconAsset.scan_id == scan_id).count(),
            "endpoint_count": self.db.query(ReconEndpoint).filter(ReconEndpoint.scan_id == scan_id).count() + self.db.query(ApiEndpoint).filter(ApiEndpoint.scan_id == scan_id).count(),
            "graph_node_count": len(nodes), "graph_edge_count": len(edges),
            "entities_by_type": dict(sorted(Counter(node.entity_type for node in nodes).items())),
            "relationships_by_type": dict(sorted(Counter(edge.relationship_type for edge in edges).items())),
        }

    def _trend(self, scan: Scan, posture: SecurityPostureSnapshot | None) -> dict[str, Any]:
        if posture:
            return {"baseline": bool((posture.comparison_summary or {}).get("baseline", True)), "posture_snapshot": posture.comparison_summary or {}, "overall_risk_score": posture.overall_risk_score, "risk_band": posture.risk_band, "limitation": "Trend comparisons are limited to persisted scans of the same target."}
        prior_difference = self.db.query(ScanDifference).filter(ScanDifference.scan_b_id == scan.id).order_by(ScanDifference.created_at.desc()).first()
        return {"baseline": prior_difference is None, "difference": self._redact(prior_difference.diff_data) if prior_difference else {}, "limitation": "No completed posture snapshot is available for this scan."}

    @staticmethod
    def _semantic_key(finding: dict[str, Any]) -> tuple[str, str]:
        canonical_rule = "cors_wildcard_credentials" if finding.get("rule_id") in {"cors_wildcard_credentials", "CFG-CORS-001"} else str(finding.get("rule_id") or "unknown")
        return canonical_rule, str(finding.get("affected_url") or finding.get("subject") or "unknown")

    @staticmethod
    def _analysis_unavailable(scan: Scan) -> bool:
        return any(finding.rule_id == "security_analysis_unavailable" for finding in scan.security_findings)

    @staticmethod
    def _limitations(scan: Scan, analysis_unavailable: bool) -> list[str]:
        notes: list[str] = []
        if scan.state != "COMPLETED":
            notes.append(f"Coverage is incomplete because the scan ended in {scan.state.lower()} state.")
        if analysis_unavailable:
            notes.append("Security analysis was unavailable for the collected evidence; the report does not make a vulnerability or clean-result conclusion.")
        return notes

    @staticmethod
    def _posture(posture: SecurityPostureSnapshot | None, risk: ScanRiskSummary | None) -> dict[str, Any]:
        return {"overall_risk_score": posture.overall_risk_score if posture else (risk.overall_score if risk else 0.0), "risk_band": posture.risk_band if posture else (risk.risk_band if risk else "info"), "summary": posture.posture_summary if posture else {}, "posture_version": posture.posture_version if posture else None}

    @staticmethod
    def _finding_sort_key(finding: SecurityFinding, risk: RiskAssessment | None) -> tuple[float, int, str]:
        return (-(risk.risk_score if risk else 0.0), SEVERITY_ORDER.get((finding.severity or "info").lower(), 5), finding.rule_id)

    def _cves(self, scan_id: UUID) -> list[dict[str, Any]]:
        rows = self.db.query(TechnologyCVEMatch, CVEIntelligence).outerjoin(CVEIntelligence, TechnologyCVEMatch.cve_intelligence_id == CVEIntelligence.id).filter(TechnologyCVEMatch.scan_id == scan_id).all()
        return [{"cve_id": cve.cve_id, "cwe": cve.cwe or [], "source_url": cve.source_url, "applicability_state": match.applicability_state, "confidence": round(match.applicability_confidence, 1)} for match, cve in rows if cve]

    @staticmethod
    def _executive_summary(scan: Scan, findings: list[dict[str, Any]], risk: ScanRiskSummary | None, severity_counts: dict[str, int], *, analysis_unavailable: bool = False) -> str:
        highest = findings[0] if findings else None
        score = 0.0 if analysis_unavailable else (round(risk.overall_score, 1) if risk else 0.0)
        if analysis_unavailable:
            return "Security analysis was unavailable for this scan. No vulnerability conclusion or clean-result claim is made from the collected evidence."
        if highest:
            return f"The {scan.assessment_profile or 'configured'} assessment recorded {len(findings)} prioritized evidence-backed findings. Overall deterministic risk is {score} ({risk.risk_band if risk else 'info'}); the highest-priority item is {highest['rule_id']} affecting {highest['subject']}."
        return f"The assessment recorded no eligible prioritized findings. Overall deterministic risk is {score} ({risk.risk_band if risk else 'info'}); this does not establish the absence of security risk."

    @staticmethod
    def _breakpoints(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{"entry_point": item["subject"], "rule_id": item["rule_id"], "severity": item["severity"], "risk_score": item["risk_score"], "why_it_matters": f"This entry point is prioritized because it has {item['severity']} severity, {item['confidence_band']} confidence, and a deterministic risk score of {item['risk_score']}.", "evidence_state": item["evidence_state"], "safety_note": "High-level prioritization only; this report intentionally omits exploit code, payloads, commands, and step-by-step instructions."} for item in findings[:5]]

    @staticmethod
    def _remediation(finding: SecurityFinding) -> str:
        key = f"{finding.rule_id} {finding.category}".lower()
        if "xss" in key or "dom" in key:
            return "Use context-appropriate output encoding, avoid unsafe DOM sinks, validate untrusted input, and enforce a restrictive Content Security Policy."
        if "secret" in key or "sensitive" in key or "data" in key:
            return "Remove sensitive material from client-visible responses, rotate any potentially exposed credentials, and add release checks that prevent recurrence."
        if "cors" in key:
            return "Restrict cross-origin access to explicit trusted origins and avoid credentialed wildcard configurations."
        if "header" in key or "config" in key or "security" in key:
            return "Set and test the applicable security response header with values appropriate to the application’s authenticated and unauthenticated flows."
        if "cve" in key or "vuln" in key:
            return "Confirm product and version applicability, then apply the vendor-supported update or compensating control and retest within the approved scope."
        return "Validate the observed condition, apply the least-privilege corrective control, and retest using the approved assessment profile and scope."

    @staticmethod
    def _references(finding: SecurityFinding, cves: list[dict[str, Any]]) -> list[dict[str, str]]:
        key = f"{finding.rule_id} {finding.category}".lower()
        refs: list[dict[str, str]] = []
        if "xss" in key or "dom" in key:
            refs.extend([{"label": "CWE-79", "url": "https://cwe.mitre.org/data/definitions/79.html"}, {"label": "OWASP A03:2021", "url": "https://owasp.org/Top10/A03_2021-Injection/"}])
        elif "cors" in key:
            refs.extend([{"label": "CWE-942", "url": "https://cwe.mitre.org/data/definitions/942.html"}, {"label": "OWASP A05:2021", "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"}])
        elif "header" in key or "config" in key:
            refs.extend([{"label": "CWE-693", "url": "https://cwe.mitre.org/data/definitions/693.html"}, {"label": "OWASP A05:2021", "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"}])
        elif "secret" in key or "sensitive" in key or "data" in key:
            refs.extend([{"label": "CWE-200", "url": "https://cwe.mitre.org/data/definitions/200.html"}, {"label": "OWASP A01:2021", "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"}])
        for cve in cves:
            refs.append({"label": cve["cve_id"], "url": cve["source_url"]})
        seen: set[str] = set()
        return [item for item in refs if not (item["label"] in seen or seen.add(item["label"]))]

    @classmethod
    def _redact(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(key): "[REDACTED]" if any(term in str(key).lower() for term in SENSITIVE_TERMS) else cls._redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [cls._redact(item) for item in value]
        if isinstance(value, str) and any(term in value.lower() for term in SENSITIVE_TERMS):
            return "[REDACTED]"
        return value

    @staticmethod
    def _parameter(subject: str) -> str | None:
        try:
            names = [name for name, _ in parse_qsl(urlsplit(subject).query, keep_blank_values=True)]
            return ", ".join(names) if names else None
        except ValueError:
            return None

    @staticmethod
    def _is_url(value: str) -> bool:
        return bool(urlsplit(value).scheme and urlsplit(value).netloc)

    @staticmethod
    def _sarif_level(severity: str) -> str:
        return "error" if severity in {"critical", "high"} else "warning" if severity == "medium" else "note"

    @staticmethod
    def _sarif_name(rule_id: str) -> str:
        return re.sub(r"[^A-Za-z0-9]+", " ", rule_id).strip().title() or "Security Finding"


class MinimalPdfRenderer:
    """A dependency-free, text-only PDF renderer for redacted report export."""

    @classmethod
    def render(cls, source_lines: list[str]) -> bytes:
        lines = [piece for line in source_lines for piece in textwrap.wrap(str(line), width=100, break_long_words=True) or [""]]
        page_lines = [lines[index:index + 46] for index in range(0, len(lines), 46)] or [["No report content available."]]
        objects: dict[int, bytes] = {
            1: b"<< /Type /Catalog /Pages 2 0 R >>",
            3: b"<< /Producer (Web Autopsy Network) /Title (Security Posture Report) >>",
            4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        }
        page_ids = [5 + index * 2 for index in range(len(page_lines))]
        objects[2] = f"<< /Type /Pages /Kids [{' '.join(f'{item} 0 R' for item in page_ids)}] /Count {len(page_ids)} >>".encode()
        for index, page in enumerate(page_lines):
            page_id, content_id = page_ids[index], page_ids[index] + 1
            stream = ["BT", "/F1 9 Tf", "50 760 Td", "12 TL"]
            for line in page:
                stream.append(f"({cls._escape(line)}) Tj")
                stream.append("T*")
            stream.append("ET")
            body = "\n".join(stream).encode("latin-1", "replace")
            objects[page_id] = f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents {content_id} 0 R >>".encode()
            objects[content_id] = b"<< /Length " + str(len(body)).encode() + b" >>\nstream\n" + body + b"\nendstream"
        output = io.BytesIO()
        output.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for object_id in range(1, max(objects) + 1):
            offsets.append(output.tell())
            output.write(f"{object_id} 0 obj\n".encode() + objects[object_id] + b"\nendobj\n")
        xref = output.tell()
        output.write(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
        for offset in offsets[1:]:
            output.write(f"{offset:010d} 00000 n \n".encode())
        output.write(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
        return output.getvalue()

    @staticmethod
    def _escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").replace("\r", " ").replace("\n", " ")
