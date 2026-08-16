from __future__ import annotations

# Evidence statements intentionally preserve readable, explicit security language.
# ruff: noqa: E501
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from bs4 import BeautifulSoup, Comment
from sqlalchemy.orm import Session

from app.models.scan import HTTPResponse, Observation, Page, Scan, SecurityFinding

RULE_VERSION = "phase7-v1"
PASSIVE_LIMITATIONS = (
    "Passive analysis only: findings use persisted evidence and do not probe, exploit, "
    "authenticate to, or actively confirm target resources."
)


class EvidenceValidationError(ValueError):
    """Raised when a security finding lacks the evidence required by the Evidence Agent."""


@dataclass(frozen=True)
class FindingCandidate:
    subject: str
    statement: str
    classification: str
    confidence: float
    confidence_band: str
    severity: str
    rule_id: str
    evidence: tuple[dict[str, Any], ...]
    page_id: Any | None = None
    limitations: str = PASSIVE_LIMITATIONS


class SecurityAnalysisService:
    """Pure database analysis of security-relevant evidence already captured by earlier phases."""

    SECURITY_HEADERS = (
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "x-xss-protection",
    )
    SESSION_COOKIE_PATTERN = re.compile(
        r"(?:session|sess|auth|token|jwt|sid|csrf|login|remember|identity)", re.IGNORECASE
    )
    SENSITIVE_COMMENT_PATTERN = re.compile(
        r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)",
        re.IGNORECASE,
    )
    EXPOSED_REFERENCE_PATTERN = re.compile(
        r"(?:/\.git/config|/\.env(?:\b|[?#])|config\.php|web\.config)",
        re.IGNORECASE,
    )

    def __init__(self, db: Session, scan_id: Any) -> None:
        self.db = db
        self.scan_id = scan_id
        self.scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not self.scan:
            raise ValueError("Scan not found")

    def analyze(self) -> list[SecurityFinding]:
        self.db.query(SecurityFinding).filter(SecurityFinding.scan_id == self.scan_id).delete(
            synchronize_session=False
        )
        self.db.flush()

        pages = self.db.query(Page).filter(Page.scan_id == self.scan_id).all()
        candidates: list[FindingCandidate] = []
        for page in pages:
            context = self._page_context(page)
            candidates.extend(self._header_findings(context))
            candidates.extend(self._cookie_findings(context))
            candidates.extend(self._cors_findings(context))
            candidates.extend(self._metadata_findings(context))
            candidates.extend(self._transport_findings(context))

        candidates.extend(self._cross_signal_findings(pages))
        candidates.extend(self._redirect_findings())
        findings = [self._persist_candidate(candidate) for candidate in candidates]
        self.db.commit()
        return findings

    def _persist_candidate(self, candidate: FindingCandidate) -> SecurityFinding:
        self._validate_candidate(candidate)
        finding = SecurityFinding(
            scan_id=self.scan_id,
            page_id=candidate.page_id,
            category="security",
            subject=candidate.subject,
            statement=candidate.statement,
            classification=candidate.classification,
            confidence=candidate.confidence,
            confidence_band=candidate.confidence_band,
            severity=candidate.severity,
            rule_id=candidate.rule_id,
            rule_version=RULE_VERSION,
            evidence=[dict(item) for item in candidate.evidence],
            limitations=candidate.limitations,
        )
        self.db.add(finding)
        self.db.flush()
        return finding

    @staticmethod
    def _validate_candidate(candidate: FindingCandidate) -> None:
        if candidate.classification not in {"OBSERVED", "INFERRED"}:
            raise EvidenceValidationError("Security classification must be OBSERVED or INFERRED.")
        if not candidate.statement.strip():
            raise EvidenceValidationError("Security finding requires a non-empty statement.")
        if not 0 <= candidate.confidence <= 100:
            raise EvidenceValidationError("Security confidence must be between 0 and 100.")
        if not candidate.rule_id or not RULE_VERSION:
            raise EvidenceValidationError("Security finding requires a rule and version.")
        if not candidate.evidence:
            raise EvidenceValidationError("Security finding rejected: evidence list is empty.")
        for item in candidate.evidence:
            if not item.get("id") or not item.get("type") or not item.get("source"):
                raise EvidenceValidationError("Security evidence requires id, type, and source.")
            if not item.get("observation"):
                raise EvidenceValidationError("Security evidence requires an observation excerpt.")

    def _page_context(self, page: Page) -> dict[str, Any]:
        response: HTTPResponse | None = page.http_responses[0] if page.http_responses else None
        headers = response.headers if response else []
        header_values: dict[str, list[str]] = {}
        for header in headers:
            header_values.setdefault(header.name.lower(), []).append(header.value)
        raw_body = response.raw_body if response and response.raw_body else ""
        rendered_body = response.rendered_body if response and response.rendered_body else ""
        html = raw_body or rendered_body
        soup = BeautifulSoup(html, "html.parser")
        return {
            "page": page,
            "response": response,
            "headers": header_values,
            "raw_body": raw_body,
            "rendered_body": rendered_body,
            "html": html,
            "soup": soup,
            "resources": [resource for resource in page.resources if resource.url],
        }

    def _header_findings(self, context: dict[str, Any]) -> list[FindingCandidate]:
        page: Page = context["page"]
        headers: dict[str, list[str]] = context["headers"]
        findings: list[FindingCandidate] = []
        for header_name in self.SECURITY_HEADERS:
            values = headers.get(header_name, [])
            label = header_name.title()
            if not values:
                severity = (
                    "medium"
                    if header_name
                    in {
                        "content-security-policy",
                        "strict-transport-security",
                        "x-frame-options",
                        "x-content-type-options",
                    }
                    else "low"
                )
                if header_name == "x-xss-protection":
                    severity = "info"
                findings.append(
                    self._candidate(
                        subject=label,
                        statement=f"{label} was not present in the stored response headers for {page.canonical_url}.",
                        classification="OBSERVED",
                        confidence=100,
                        severity=severity,
                        rule_id="header_absence",
                        page_id=page.id,
                        evidence=[
                            self._evidence(
                                "header_set",
                                page.canonical_url,
                                f"Observed response header set did not contain {header_name}.",
                                page.id,
                            )
                        ],
                    )
                )
                continue

            for value in values:
                quality, severity, note = self._header_quality(header_name, value)
                findings.append(
                    self._candidate(
                        subject=label,
                        statement=f"{label} was observed as `{value}`; passive assessment: {quality}. {note}",
                        classification="OBSERVED",
                        confidence=100,
                        severity=severity,
                        rule_id="header_configuration",
                        page_id=page.id,
                        evidence=[
                            self._evidence(
                                "header_value",
                                f"{page.canonical_url}#{header_name}",
                                f"{header_name}: {value}",
                                page.id,
                            )
                        ],
                    )
                )
        return findings

    @staticmethod
    def _header_quality(name: str, value: str) -> tuple[str, str, str]:
        lowered = value.lower()
        if name == "content-security-policy":
            strong = "default-src" in lowered or "script-src" in lowered
            return (
                ("strongly configured" if strong else "present but limited"),
                ("info" if strong else "low"),
                "The assessment is based only on the literal stored directive value.",
            )
        if name == "strict-transport-security":
            match = re.search(r"max-age=(\d+)", lowered)
            strong = bool(match and int(match.group(1)) >= 31536000)
            if "includesubdomains" in lowered:
                strong = strong and True
            return (
                ("strong HSTS duration observed" if strong else "present but potentially weak"),
                ("info" if strong else "low"),
                "No cipher-suite or certificate-chain analysis was performed.",
            )
        if name == "x-frame-options":
            strong = lowered.strip() in {"deny", "sameorigin"}
            return (
                "restrictive" if strong else "permissive or non-standard",
                "info" if strong else "low",
                "",
            )
        if name == "x-content-type-options":
            strong = lowered.strip() == "nosniff"
            return (
                "configured as nosniff" if strong else "present with non-standard value",
                "info" if strong else "low",
                "",
            )
        if name == "referrer-policy":
            strong = lowered.strip() in {
                "no-referrer",
                "strict-origin",
                "strict-origin-when-cross-origin",
            }
            return (
                "restrictive" if strong else "present but less restrictive",
                "info" if strong else "low",
                "",
            )
        if name == "permissions-policy":
            return (
                "present; directive review is required",
                "info",
                "No browser execution or policy simulation was performed.",
            )
        return (
            "legacy header present; it is deprecated in modern browsers",
            "low",
            "The literal header value is preserved as evidence.",
        )

    def _cookie_findings(self, context: dict[str, Any]) -> list[FindingCandidate]:
        page: Page = context["page"]
        findings: list[FindingCandidate] = []
        for raw_cookie in context["headers"].get("set-cookie", []):
            parts = [part.strip() for part in raw_cookie.split(";")]
            name_value = parts[0] if parts else raw_cookie
            cookie_name = name_value.split("=", 1)[0].strip()
            attrs = {
                part.split("=", 1)[0].strip().lower(): part.split("=", 1)[1].strip()
                if "=" in part
                else True
                for part in parts[1:]
            }
            secure = "secure" in attrs
            httponly = "httponly" in attrs
            samesite = attrs.get("samesite", "absent")
            domain = attrs.get("domain", "host-only")
            evidence = [
                self._evidence(
                    "set_cookie",
                    f"{page.canonical_url}#set-cookie:{cookie_name}",
                    raw_cookie,
                    page.id,
                )
            ]
            findings.append(
                self._candidate(
                    subject=f"Cookie: {cookie_name}",
                    statement=(
                        f"Observed cookie attributes: Secure={'present' if secure else 'absent'}, "
                        f"HttpOnly={'present' if httponly else 'absent'}, SameSite={samesite}, Domain={domain}."
                    ),
                    classification="OBSERVED",
                    confidence=100,
                    severity="info",
                    rule_id="cookie_attributes",
                    page_id=page.id,
                    evidence=evidence,
                )
            )
            if self.SESSION_COOKIE_PATTERN.search(cookie_name):
                missing = []
                if not httponly:
                    missing.append("HttpOnly")
                if urlsplit(page.canonical_url).scheme == "https" and not secure:
                    missing.append("Secure")
                if str(samesite).lower() == "absent":
                    missing.append("SameSite")
                if missing:
                    findings.append(
                        self._candidate(
                            subject=f"Session-like cookie: {cookie_name}",
                            statement=(
                                f"The cookie name matches a session-like pattern and is missing "
                                f"{', '.join(missing)}; this is an inferred configuration risk, not proof of compromise."
                            ),
                            classification="INFERRED",
                            confidence=80,
                            severity="medium",
                            rule_id="session_cookie_attributes",
                            page_id=page.id,
                            evidence=evidence
                            + [
                                self._evidence(
                                    "cookie_name_pattern",
                                    f"{page.canonical_url}#cookie-name",
                                    f"Cookie name `{cookie_name}` matched the session-like pattern.",
                                    page.id,
                                )
                            ],
                        )
                    )
        return findings

    def _cors_findings(self, context: dict[str, Any]) -> list[FindingCandidate]:
        page: Page = context["page"]
        headers: dict[str, list[str]] = context["headers"]
        allowed_origins = headers.get("access-control-allow-origin", [])
        allowed_credentials = headers.get("access-control-allow-credentials", [])
        if not allowed_origins:
            return [
                self._candidate(
                    subject="CORS headers",
                    statement=f"No Access-Control-Allow-Origin header was present in the stored response for {page.canonical_url}.",
                    classification="OBSERVED",
                    confidence=100,
                    severity="info",
                    rule_id="cors_header_absence",
                    page_id=page.id,
                    evidence=[
                        self._evidence(
                            "header_set",
                            page.canonical_url,
                            "Stored response header set did not contain Access-Control-Allow-Origin.",
                            page.id,
                        )
                    ],
                )
            ]
        findings: list[FindingCandidate] = []
        for origin in allowed_origins:
            credentials = any(value.lower().strip() == "true" for value in allowed_credentials)
            evidence = [
                self._evidence(
                    "cors_header",
                    f"{page.canonical_url}#access-control-allow-origin",
                    f"Access-Control-Allow-Origin: {origin}",
                    page.id,
                )
            ]
            if credentials:
                evidence.append(
                    self._evidence(
                        "cors_header",
                        f"{page.canonical_url}#access-control-allow-credentials",
                        "Access-Control-Allow-Credentials: true",
                        page.id,
                    )
                )
            if origin.strip() == "*" and credentials:
                findings.append(
                    self._candidate(
                        subject="CORS wildcard with credentials",
                        statement="Wildcard CORS origin was observed together with credentials allowed; this is an inferred overly permissive configuration risk.",
                        classification="INFERRED",
                        confidence=95,
                        severity="high",
                        rule_id="cors_wildcard_credentials",
                        page_id=page.id,
                        evidence=evidence,
                    )
                )
            else:
                findings.append(
                    self._candidate(
                        subject="CORS configuration",
                        statement=f"Access-Control-Allow-Origin was observed as `{origin}`; no active cross-origin request was performed.",
                        classification="OBSERVED",
                        confidence=100,
                        severity="info" if origin.strip() != "*" else "low",
                        rule_id="cors_header_value",
                        page_id=page.id,
                        evidence=evidence,
                    )
                )
        return findings

    def _metadata_findings(self, context: dict[str, Any]) -> list[FindingCandidate]:
        page: Page = context["page"]
        html = context["html"]
        soup: BeautifulSoup = context["soup"]
        findings: list[FindingCandidate] = []
        headers: dict[str, list[str]] = context["headers"]
        for value in headers.get("server", []):
            if re.search(r"\d+\.\d+", value):
                findings.append(
                    self._candidate(
                        subject="Verbose server header",
                        statement=f"A version-like server header was observed: `{value}`.",
                        classification="OBSERVED",
                        confidence=100,
                        severity="low",
                        rule_id="verbose_server_version",
                        page_id=page.id,
                        evidence=[
                            self._evidence(
                                "header_value",
                                f"{page.canonical_url}#server",
                                f"Server: {value}",
                                page.id,
                            )
                        ],
                    )
                )
        resource_matches = [
            str(resource.url)
            for resource in context["resources"]
            if ".map" in str(resource.url).lower()
        ]
        html_resource_matches = [
            str(element.get("src"))
            for element in soup.find_all("script", src=True)
            if ".map" in str(element.get("src")).lower()
        ]
        resource_matches = list(dict.fromkeys(resource_matches + html_resource_matches))
        if resource_matches:
            findings.append(
                self._candidate(
                    subject="Source map reference",
                    statement="A source-map URL was referenced by stored page resources; the source map was not fetched or validated.",
                    classification="OBSERVED",
                    confidence=100,
                    severity="low",
                    rule_id="source_map_reference",
                    page_id=page.id,
                    evidence=[
                        self._evidence("resource_url", url, url, page.id)
                        for url in resource_matches
                    ],
                )
            )
        exposed_refs = self.EXPOSED_REFERENCE_PATTERN.findall(html)
        if exposed_refs:
            findings.append(
                self._candidate(
                    subject="Exposed configuration reference",
                    statement="A reference to a sensitive-looking configuration path was observed in stored HTML/resources; no follow-up request was made.",
                    classification="OBSERVED",
                    confidence=100,
                    severity="medium",
                    rule_id="exposed_config_reference",
                    page_id=page.id,
                    evidence=[
                        self._evidence(
                            "html_reference",
                            page.canonical_url,
                            ", ".join(sorted(set(exposed_refs))),
                            page.id,
                        )
                    ],
                    limitations=PASSIVE_LIMITATIONS
                    + " This is a manual follow-up suggestion only; referenced paths were not fetched.",
                )
            )
        comments = [
            str(comment) for comment in soup.find_all(string=lambda text: isinstance(text, Comment))
        ]
        sensitive_comments = [
            comment.strip()[:500]
            for comment in comments
            if self.SENSITIVE_COMMENT_PATTERN.search(comment)
        ]
        if sensitive_comments:
            findings.append(
                self._candidate(
                    subject="Sensitive-looking HTML comment",
                    statement="A comment contained a sensitive-looking keyword pattern; the value was not validated, used, or treated as a credential.",
                    classification="OBSERVED",
                    confidence=100,
                    severity="medium",
                    rule_id="sensitive_comment_pattern",
                    page_id=page.id,
                    evidence=[
                        self._evidence("html_comment", page.canonical_url, comment, page.id)
                        for comment in sensitive_comments
                    ],
                )
            )
        return findings

    def _transport_findings(self, context: dict[str, Any]) -> list[FindingCandidate]:
        page: Page = context["page"]
        response: HTTPResponse | None = context["response"]
        final_url = response.final_url if response else page.canonical_url
        final_is_https = urlsplit(final_url).scheme.lower() == "https"
        return [
            self._candidate(
                subject="HTTPS transport",
                statement=(
                    f"Stored response was reached over HTTPS at `{final_url}`."
                    if final_is_https
                    else f"Stored response was not reached over HTTPS: `{final_url}`."
                ),
                classification="OBSERVED",
                confidence=100,
                severity="info" if final_is_https else "medium",
                rule_id="https_observation",
                page_id=page.id,
                evidence=[
                    self._evidence(
                        "final_url", final_url, f"Final stored response URL: {final_url}", page.id
                    )
                ],
            )
        ]

    def _redirect_findings(self) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        redirect_observations = (
            self.db.query(Observation)
            .filter(
                Observation.scan_id == self.scan_id,
                Observation.category == "HTTP",
            )
            .all()
        )
        for observation in redirect_observations:
            if not observation.observation.lower().startswith("redirects to "):
                continue
            target_url = observation.observation[len("Redirects to ") :].strip()
            if (
                urlsplit(observation.subject).scheme.lower() == "http"
                and urlsplit(target_url).scheme.lower() == "https"
            ):
                findings.append(
                    self._candidate(
                        subject="HTTP to HTTPS redirect",
                        statement=(
                            f"A stored redirect observation shows `{observation.subject}` redirects "
                            f"to HTTPS at `{target_url}`."
                        ),
                        classification="OBSERVED",
                        confidence=100,
                        severity="info",
                        rule_id="http_to_https_redirect",
                        page_id=None,
                        evidence=[
                            self._evidence(
                                "redirect_chain",
                                observation.subject,
                                observation.observation,
                                None,
                            )
                        ],
                    )
                )
        return findings

    def _cross_signal_findings(self, pages: list[Page]) -> list[FindingCandidate]:
        findings: list[FindingCandidate] = []
        for page in pages:
            context = self._page_context(page)
            if "content-security-policy" not in context["headers"]:
                inline_scripts = [
                    script
                    for script in context["soup"].find_all("script")
                    if not script.get("src") and script.get_text(strip=True)
                ]
                if inline_scripts:
                    findings.append(
                        self._candidate(
                            subject="CSP and inline script surface",
                            statement="Missing CSP combined with inline script content suggests an elevated XSS exposure surface; this is an inferred configuration risk, not proof of exploitability.",
                            classification="INFERRED",
                            confidence=75,
                            severity="medium",
                            rule_id="csp_inline_script_surface",
                            page_id=page.id,
                            evidence=[
                                self._evidence(
                                    "header_absence",
                                    page.canonical_url,
                                    "Content-Security-Policy was absent from stored headers.",
                                    page.id,
                                ),
                                self._evidence(
                                    "inline_script",
                                    page.canonical_url,
                                    f"Observed {len(inline_scripts)} inline script element(s).",
                                    page.id,
                                ),
                            ],
                        )
                    )
        return findings

    @staticmethod
    def _evidence(
        evidence_type: str, source: str, observation: str, page_id: Any | None
    ) -> dict[str, Any]:
        return {
            "id": str(uuid4()),
            "type": evidence_type,
            "source": source,
            "observation": observation[:2000],
            "page_id": str(page_id) if page_id else None,
            "captured_at": datetime.now(UTC).isoformat(),
        }

    @staticmethod
    def _candidate(
        *,
        subject: str,
        statement: str,
        classification: str,
        confidence: float,
        severity: str,
        rule_id: str,
        page_id: Any | None,
        evidence: list[dict[str, Any]],
        limitations: str = PASSIVE_LIMITATIONS,
    ) -> FindingCandidate:
        band = "high" if confidence >= 80 else "medium" if confidence >= 50 else "low"
        return FindingCandidate(
            subject=subject,
            statement=statement,
            classification=classification,
            confidence=confidence,
            confidence_band=band,
            severity=severity,
            rule_id=rule_id,
            evidence=tuple(evidence),
            page_id=page_id,
            limitations=limitations,
        )


__all__ = ["EvidenceValidationError", "FindingCandidate", "SecurityAnalysisService"]
