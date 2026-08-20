from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from app.models.scan import HTTPObservation, HTTPResponse, Page, SecurityFinding, Scan
from app.services.updates import UpdatePackageError, UpdatePackageService


RULE_VERSION = "phase4-config-v1"
LIMITATIONS = (
    "Detection is based on persisted, bounded HTTP evidence only. The Configuration Agent does not probe, exploit, authenticate, submit forms, or claim compromise."
)


@dataclass(frozen=True)
class ConfigurationRule:
    rule_id: str
    title: str
    prerequisites: str
    detection_logic: str
    evidence_requirements: str
    severity: str
    confidence: int
    remediation_guidance: str
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "prerequisites": self.prerequisites,
            "detection_logic": self.detection_logic,
            "evidence_requirements": self.evidence_requirements,
            "severity": self.severity,
            "confidence": self.confidence,
            "remediation_guidance": self.remediation_guidance,
            "cwe": list(self.cwe),
            "owasp": list(self.owasp),
            "rule_version": RULE_VERSION,
        }


CONFIGURATION_RULES: dict[str, ConfigurationRule] = {
    "CFG-HEADERS-001": ConfigurationRule(
        "CFG-HEADERS-001", "Weak baseline security headers", "Successful HTML response with a reliable content type.",
        "Require at least two missing baseline headers: CSP, HSTS on HTTPS, X-Content-Type-Options, or X-Frame-Options.",
        "HTTP security-policy observations plus status and content-type observations.", "medium", 98,
        "Deploy a context-appropriate security-header baseline and review framing, MIME-sniffing, CSP, and transport policy.",
        ("CWE-693",), ("OWASP-A05",),
    ),
    "CFG-CORS-001": ConfigurationRule(
        "CFG-CORS-001", "Wildcard credentialed CORS", "CORS response observation contains both allow-origin and allow-credentials values.",
        "Report only when Access-Control-Allow-Origin is exactly * and Access-Control-Allow-Credentials is true.",
        "Normalized CORS observation containing both explicit values; no origin-reflection claim.", "high", 99,
        "Replace wildcard origins with an explicit allowlist and review credentialed cross-origin requirements.",
        ("CWE-942",), ("OWASP-A05",),
    ),
    "CFG-TLS-001": ConfigurationRule(
        "CFG-TLS-001", "Sensitive path served over HTTP", "Successful response for a sensitive-looking in-scope path.",
        "Report when a sensitive path is observed with an http scheme.",
        "Status and TLS transport observations plus the scoped page URL.", "high", 99,
        "Serve sensitive workflows only over HTTPS and enforce secure redirects before enabling HSTS.",
        ("CWE-319",), ("OWASP-A02",),
    ),
    "CFG-TLS-002": ConfigurationRule(
        "CFG-TLS-002", "Weak or missing HSTS on sensitive HTTPS path", "Successful HTTPS response for a sensitive-looking path.",
        "Report when HSTS is absent or max-age is below one year; do not infer certificate or cipher weaknesses.",
        "TLS and security-policy observations.", "medium", 96,
        "Configure HSTS with an appropriate lifetime after confirming complete HTTPS coverage.",
        ("CWE-319",), ("OWASP-A02",),
    ),
    "CFG-DIR-001": ConfigurationRule(
        "CFG-DIR-001", "Directory listing exposed", "Successful HTML response with a strong directory-index marker and listing-style links.",
        "Require Index of / or Directory listing for plus at least two anchor links in the bounded body.",
        "Stored bounded response body, status, and content type.", "high", 99,
        "Disable autoindexing or restrict directory access at the web server and edge.",
        ("CWE-548",), ("OWASP-A05",),
    ),
    "CFG-EXPOSED-ARTIFACT-001": ConfigurationRule(
        "CFG-EXPOSED-ARTIFACT-001", "Sensitive deployment artifact exposed", "A successful in-scope response was actually captured at a sensitive artifact path.",
        "Require a non-generic response body or non-HTML content for .git/config, .env, config, backup, archive, or database artifact paths.",
        "Scoped URL, status, content type, and bounded body marker or non-HTML response evidence.", "high", 98,
        "Remove artifacts from web roots, deny access, rotate any exposed secrets, and verify deployment packaging.",
        ("CWE-530", "CWE-538"), ("OWASP-A05",),
    ),
    "CFG-ERROR-001": ConfigurationRule(
        "CFG-ERROR-001", "Verbose server error disclosure", "5xx response with a strong framework, traceback, exception, SQLSTATE, or debug marker.",
        "Require a server-error status and a high-signal error signature in the bounded response body.",
        "Error status plus redacted bounded body excerpt.", "high", 98,
        "Disable production debug output and return generic errors while retaining server-side logs.",
        ("CWE-209",), ("OWASP-A05",),
    ),
    "CFG-CACHE-001": ConfigurationRule(
        "CFG-CACHE-001", "Session-like cookie publicly cacheable", "Session-like cookie and explicit public or shared-cache metadata on the same response.",
        "Report only when a session-like cookie is set and cache-control contains public or s-maxage.",
        "Redacted cookie attributes plus normalized cache observation.", "high", 98,
        "Mark personalized responses private or no-store and review CDN cache keys and variation.",
        ("CWE-525",), ("OWASP-A05",),
    ),
    "CFG-DISCLOSURE-001": ConfigurationRule(
        "CFG-DISCLOSURE-001", "Versioned product disclosure", "Server or X-Powered-By header contains an explicit version number.",
        "Report only versioned values; generic product names without a version are not escalated by this rule.",
        "Safe bounded header observation.", "low", 98,
        "Remove unnecessary product and version disclosure at the edge or proxy.",
        ("CWE-200",), ("OWASP-A05",),
    ),
    "CFG-COOKIE-001": ConfigurationRule(
        "CFG-COOKIE-001", "Insecure session cookie attributes", "Session-like cookie observation with transport scheme known.",
        "Report missing HttpOnly, missing Secure on HTTPS, or SameSite=None without Secure.",
        "Redacted cookie name and attributes plus TLS transport observation.", "medium", 99,
        "Set HttpOnly, Secure, and an appropriate SameSite policy for session-like cookies.",
        ("CWE-614", "CWE-1004"), ("OWASP-A05",),
    ),
    "CFG-HTTP-001": ConfigurationRule(
        "CFG-HTTP-001", "Dangerous HTTP method advertised", "Allow-like response header explicitly contains TRACE, CONNECT, or DEBUG.",
        "Report only method tokens in Allow, Public, or X-Allowed-Methods headers; CORS method lists are excluded.",
        "Safe bounded method-capability header observation.", "medium", 98,
        "Disable unsafe methods at the application, proxy, and web-server layers.",
        ("CWE-749",), ("OWASP-A05",),
    ),
}

SESSION_RE = re.compile(r"(?:session|sess|auth|token|jwt|sid|csrf|login|remember|identity)", re.I)
SENSITIVE_PATH_RE = re.compile(r"(?:/login|/signin|/admin|/account|/checkout|/payment|/oauth|/token|/api/auth|/\.git/config|/\.env|/config(?:\.|/)|/debug)", re.I)
ARTIFACT_PATH_RE = re.compile(r"(?:/\.git/config|/\.env(?:$|[?#])|/(?:web\.config|config\.php)|\.(?:bak|backup|old|orig|save|zip|tar|gz|sql)(?:$|[?#]))", re.I)
ERROR_RE = re.compile(r"(?:traceback \(most recent call last\)|stack trace|exception in thread|sqlstate\[|syntax error at or near|debug toolbar|werkzeug debugger|laravel ignition|fatal error:|panic:)", re.I)
VERSION_RE = re.compile(r"(?:^|[ /_-])v?\d+(?:\.\d+){1,3}(?:$|[ /_-])", re.I)
BASELINE_HEADERS = ("content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options")


class ConfigurationAgent:
    """Deterministic, passive-only configuration misconfiguration analyzer."""

    def __init__(self, db: Session, scan_id: UUID) -> None:
        self.db = db
        self.scan_id = scan_id
        self.scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not self.scan:
            raise ValueError("Scan not found")
        self.rule_version, self.disabled_rule_ids = self._update_metadata()

    def analyze(self) -> list[SecurityFinding]:
        self.db.query(SecurityFinding).filter(
            SecurityFinding.scan_id == self.scan_id,
            SecurityFinding.category == "configuration",
        ).delete(synchronize_session=False)
        self.db.flush()
        findings: list[SecurityFinding] = []
        pages = self.db.query(Page).filter(Page.scan_id == self.scan_id).order_by(Page.canonical_url).all()
        for page in pages:
            response = (
                self.db.query(HTTPResponse)
                .filter(HTTPResponse.page_id == page.id)
                .order_by(HTTPResponse.created_at.desc())
                .first()
            )
            context = self._context(page, response)
            for candidate in self._candidates(context):
                finding = self._persist(candidate)
                findings.append(finding)
        self.db.commit()
        return findings

    def _candidates(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        for rule in (
            self._headers_rule,
            self._cors_rule,
            self._tls_http_rule,
            self._tls_hsts_rule,
            self._directory_rule,
            self._artifact_rule,
            self._error_rule,
            self._cache_rule,
            self._disclosure_rule,
            self._cookie_rule,
            self._dangerous_method_rule,
        ):
            candidate = rule(context)
            if candidate:
                candidates.append(candidate)
        return [candidate for candidate in candidates if candidate["rule"].rule_id not in self.disabled_rule_ids]

    def _update_metadata(self) -> tuple[str, set[str]]:
        try:
            active = UpdatePackageService(self.db).resolve_component("configuration_rules")
        except UpdatePackageError:
            active = None
        if not active:
            return RULE_VERSION, set()
        component = active["component"]
        version = component.get("version", RULE_VERSION)
        return f"{version}+{active['package_name']}-{active['package_version']}", set(component.get("disabled_rule_ids", []))

    def _context(self, page: Page, response: HTTPResponse | None) -> dict[str, Any]:
        observations = self.db.query(HTTPObservation).filter(
            HTTPObservation.scan_id == self.scan_id,
            HTTPObservation.page_id == page.id,
        ).all()
        by_type: dict[str, list[HTTPObservation]] = defaultdict(list)
        for item in observations:
            by_type[item.observation_type].append(item)
        headers: dict[str, list[str]] = defaultdict(list)
        for item in by_type.get("header", []):
            value = item.value if isinstance(item.value, dict) else {}
            name = str(value.get("name", "")).lower()
            if name:
                raw_values = value.get("values") or []
                values = raw_values if isinstance(raw_values, list) else [raw_values]
                for safe_value in values:
                    if safe_value is not None:
                        headers[name].append(self._safe_text(safe_value))
        policies: dict[str, dict[str, Any]] = {}
        for item in by_type.get("security_policy", []):
            value = item.value if isinstance(item.value, dict) else {}
            name = str(value.get("name", "")).lower()
            if name:
                policies[name] = value
        status = self._first_value(by_type.get("status_code"))
        content_type = self._first_value(by_type.get("content_type"))
        tls = self._first_value(by_type.get("tls"))
        cache = self._first_value(by_type.get("cache"))
        cors = self._first_value(by_type.get("cors"))
        cookies = [item.value for item in by_type.get("cookie", []) if isinstance(item.value, dict)]
        body = response.raw_body if response and response.raw_body else ""
        return {
            "page": page,
            "response": response,
            "observations": by_type,
            "headers": headers,
            "policies": policies,
            "status": status or {"status_code": response.status_code if response else None},
            "content_type": content_type or {"media_type": (response.content_type or "").split(";", 1)[0].lower() if response else None},
            "tls": tls or {"scheme": urlsplit(page.canonical_url).scheme.lower(), "https_observed": urlsplit(page.canonical_url).scheme.lower() == "https"},
            "cache": cache or {},
            "cors": cors or {},
            "cookies": cookies,
            "body": body[: 5 * 1024 * 1024],
        }

    @staticmethod
    def _first_value(items: list[HTTPObservation] | None) -> dict[str, Any] | None:
        return next((item.value for item in items or [] if isinstance(item.value, dict)), None)

    def _headers_rule(self, ctx: dict[str, Any]) -> dict[str, Any] | None:
        status = int(ctx["status"].get("status_code") or 0)
        media = str(ctx["content_type"].get("media_type") or "")
        if not 200 <= status < 400 or "html" not in media:
            return None
        missing = [name for name in BASELINE_HEADERS if not self._policy_present(ctx, name)]
        if len(missing) < 2:
            return None
        return self._candidate("CFG-HEADERS-001", ctx, f"Missing baseline security headers: {', '.join(missing)}.", f"Observed successful HTML response without {', '.join(missing)}.")

    def _cors_rule(self, ctx: dict[str, Any]) -> dict[str, Any] | None:
        values = ctx["cors"].get("headers", {}) if isinstance(ctx["cors"], dict) else {}
        origins = [str(x).strip() for x in (values.get("access-control-allow-origin") or [])]
        credentials = [str(x).strip().lower() for x in (values.get("access-control-allow-credentials") or [])]
        if "*" not in origins or "true" not in credentials:
            return None
        return self._candidate("CFG-CORS-001", ctx, "The response allows all origins while also allowing credentials.", "Observed Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.", severity="high", confidence=99)

    def _tls_http_rule(self, ctx: dict[str, Any]) -> dict[str, Any] | None:
        page: Page = ctx["page"]
        if urlsplit(page.canonical_url).scheme.lower() != "http" or not SENSITIVE_PATH_RE.search(urlsplit(page.canonical_url).path):
            return None
        if not 200 <= int(ctx["status"].get("status_code") or 0) < 400:
            return None
        return self._candidate("CFG-TLS-001", ctx, "A sensitive-looking path was served over HTTP.", f"Successful response observed at an HTTP sensitive path: {page.canonical_url}.", severity="high", confidence=99)

    def _tls_hsts_rule(self, ctx: dict[str, Any]) -> dict[str, Any] | None:
        page: Page = ctx["page"]
        if not ctx["tls"].get("https_observed") or not SENSITIVE_PATH_RE.search(urlsplit(page.canonical_url).path):
            return None
        if not 200 <= int(ctx["status"].get("status_code") or 0) < 400:
            return None
        hsts_policy = ctx["policies"].get("strict-transport-security") or {}
        hsts_values = hsts_policy.get("values") or [] if isinstance(hsts_policy, dict) else []
        match = re.search(r"max-age=(\d+)", " ".join(map(str, hsts_values)), re.I)
        if match and int(match.group(1)) >= 31536000:
            return None
        return self._candidate("CFG-TLS-002", ctx, "HSTS is missing or has a max-age below one year on a sensitive HTTPS path.", "HTTPS transport was observed but Strict-Transport-Security did not meet the one-year minimum used by this rule.")

    def _directory_rule(self, ctx: dict[str, Any]) -> dict[str, Any] | None:
        body = ctx["body"]
        if int(ctx["status"].get("status_code") or 0) < 200 or int(ctx["status"].get("status_code") or 0) >= 300 or "html" not in str(ctx["content_type"].get("media_type") or ""):
            return None
        marker = re.search(r"(?:Index of /|Directory listing for)", body, re.I)
        links = re.findall(r"<a\b[^>]+href=", body, re.I)
        if not marker or len(links) < 2:
            return None
        return self._candidate("CFG-DIR-001", ctx, "A directory-index marker and listing-style links were observed in a successful HTML response.", f"Observed directory listing marker {marker.group(0)!r} with {len(links)} link(s) in the bounded response body.")

    def _artifact_rule(self, ctx: dict[str, Any]) -> dict[str, Any] | None:
        page: Page = ctx["page"]
        if not ARTIFACT_PATH_RE.search(urlsplit(page.canonical_url).path) or not 200 <= int(ctx["status"].get("status_code") or 0) < 400:
            return None
        body = ctx["body"]
        media = str(ctx["content_type"].get("media_type") or "")
        markers = re.search(r"(?:\[core\]|(?:APP|DB|AWS|SECRET|PASSWORD)[A-Z_]*\s*=|CREATE TABLE|PK\x03\x04)", body, re.I)
        generic_html = "html" in media and ("<html" in body.lower() or "<!doctype" in body.lower()) and not markers
        if generic_html or (not body and "html" in media):
            return None
        severity = "high" if re.search(r"/\.git/config|/\.env", urlsplit(page.canonical_url).path, re.I) else "medium"
        confidence = 99 if markers or "html" not in media else 96
        return self._candidate("CFG-EXPOSED-ARTIFACT-001", ctx, "A sensitive deployment artifact returned a non-generic response.", f"Observed successful in-scope artifact path {urlsplit(page.canonical_url).path} with content type {media or 'unknown'} and a bounded non-generic response.", severity=severity, confidence=confidence)

    def _error_rule(self, ctx: dict[str, Any]) -> dict[str, Any] | None:
        status = int(ctx["status"].get("status_code") or 0)
        match = ERROR_RE.search(ctx["body"])
        if status < 500 or not match:
            return None
        return self._candidate("CFG-ERROR-001", ctx, "A server-error response disclosed a strong verbose-error signature.", f"Observed HTTP {status} with a bounded response marker matching {match.group(0)!r}.", severity="high", confidence=98)

    def _cache_rule(self, ctx: dict[str, Any]) -> dict[str, Any] | None:
        cookies = [cookie for cookie in ctx["cookies"] if SESSION_RE.search(str(cookie.get("name", "")))]
        directives = (ctx["cache"].get("cache_control_directives") or {}) if isinstance(ctx["cache"], dict) else {}
        if not cookies or not ("public" in directives or "s-maxage" in directives):
            return None
        return self._candidate("CFG-CACHE-001", ctx, "A session-like cookie was set on a response with explicit shared-cache metadata.", f"Observed {len(cookies)} session-like cookie(s) together with cache directives containing public or s-maxage.", severity="high", confidence=98)

    def _disclosure_rule(self, ctx: dict[str, Any]) -> dict[str, Any] | None:
        disclosures = []
        for name in ("server", "x-powered-by"):
            for value in ctx["headers"].get(name, []):
                if VERSION_RE.search(value):
                    disclosures.append(f"{name}: {self._safe_text(value)}")
        if not disclosures:
            return None
        return self._candidate("CFG-DISCLOSURE-001", ctx, "A versioned server or framework header was disclosed.", "Observed versioned product metadata in: " + "; ".join(disclosures), severity="low", confidence=98)

    def _cookie_rule(self, ctx: dict[str, Any]) -> dict[str, Any] | None:
        page: Page = ctx["page"]
        insecure: list[str] = []
        for cookie in ctx["cookies"]:
            name = str(cookie.get("name", ""))
            if not SESSION_RE.search(name):
                continue
            if not cookie.get("httponly"):
                insecure.append(f"{name} missing HttpOnly")
            if urlsplit(page.canonical_url).scheme.lower() == "https" and not cookie.get("secure"):
                insecure.append(f"{name} missing Secure on HTTPS")
            if str(cookie.get("samesite", "")).lower() == "none" and not cookie.get("secure"):
                insecure.append(f"{name} uses SameSite=None without Secure")
        if not insecure:
            return None
        return self._candidate("CFG-COOKIE-001", ctx, "A session-like cookie lacked one or more protective attributes.", "; ".join(insecure), severity="medium", confidence=99)

    def _dangerous_method_rule(self, ctx: dict[str, Any]) -> dict[str, Any] | None:
        tokens: list[str] = []
        for name in ("allow", "public", "x-allowed-methods"):
            for value in ctx["headers"].get(name, []):
                tokens.extend(re.findall(r"\b(?:TRACE|CONNECT|DEBUG)\b", value, re.I))
        if not tokens:
            return None
        return self._candidate("CFG-HTTP-001", ctx, "A dangerous HTTP method was explicitly advertised by a method-capability header.", "Observed method token(s): " + ", ".join(sorted(set(token.upper() for token in tokens))), severity="medium", confidence=98)

    def _policy_present(self, ctx: dict[str, Any], name: str) -> bool:
        policy = ctx["policies"].get(name)
        return bool(isinstance(policy, dict) and policy.get("present"))

    def _candidate(self, rule_id: str, ctx: dict[str, Any], subject: str, observation: str, *, severity: str | None = None, confidence: int | None = None) -> dict[str, Any]:
        rule = CONFIGURATION_RULES[rule_id]
        page: Page = ctx["page"]
        return {
            "rule": rule,
            "subject": f"{rule.title} — {page.canonical_url}",
            "statement": subject,
            "observation": self._safe_text(observation),
            "page_id": page.id,
            "severity": severity or rule.severity,
            "confidence": confidence or rule.confidence,
        }

    def _persist(self, candidate: dict[str, Any]) -> SecurityFinding:
        rule: ConfigurationRule = candidate["rule"]
        evidence = {
            "id": str(uuid4()),
            "type": "configuration_http_observation",
            "source": f"Page:{candidate['page_id']}",
            "observation": candidate["observation"][:512],
            "page_id": str(candidate["page_id"]),
            "captured_at": datetime.now(UTC).isoformat(),
            "rule_id": rule.rule_id,
            "prerequisites": rule.prerequisites,
        }
        finding = SecurityFinding(
            scan_id=self.scan_id,
            page_id=candidate["page_id"],
            category="configuration",
            subject=candidate["subject"],
            statement=candidate["statement"],
            classification="OBSERVED",
            confidence=float(candidate["confidence"]),
            confidence_band="high" if candidate["confidence"] >= 80 else "medium",
            severity=candidate["severity"],
            rule_id=rule.rule_id,
            rule_version=self.rule_version,
            evidence=[evidence],
            limitations=LIMITATIONS,
        )
        self.db.add(finding)
        self.db.flush()
        return finding

    @staticmethod
    def _safe_text(value: Any) -> str:
        text = str(value)
        text = re.sub(r"(?i)(authorization|cookie|token|secret|password|api[-_]?key)\s*[:=]\s*[^;, ]+", r"\1=[REDACTED]", text)
        return text[:512]


__all__ = ["CONFIGURATION_RULES", "ConfigurationAgent", "ConfigurationRule", "RULE_VERSION"]
