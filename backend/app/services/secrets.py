from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlsplit
from uuid import UUID

from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.models.scan import HTTPResponse, Page, Resource, SecurityFinding
from app.services.updates import UpdatePackageError, UpdatePackageService

RULE_VERSION = "phase7-secrets-v1"
REDACTED = "[REDACTED]"
LIMITATIONS = (
    "Secret values are never persisted, logged, or returned. This agent reports only high-confidence or context-supported "
    "leakage indicators from bounded persisted evidence; it does not fetch artifacts, validate credentials, or attempt authentication."
)


@dataclass(frozen=True)
class SecretsRule:
    rule_id: str
    title: str
    source_types: tuple[str, ...]
    prerequisites: str
    detection_logic: str
    suppression_logic: str
    evidence_requirements: str
    severity: str
    confidence_tier: str
    confidence: int
    remediation_guidance: str
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "source_types": list(self.source_types),
            "prerequisites": self.prerequisites,
            "detection_logic": self.detection_logic,
            "suppression_logic": self.suppression_logic,
            "evidence_requirements": self.evidence_requirements,
            "severity": self.severity,
            "confidence_tier": self.confidence_tier,
            "confidence": self.confidence,
            "remediation_guidance": self.remediation_guidance,
            "cwe": list(self.cwe),
            "owasp": list(self.owasp),
            "rule_version": RULE_VERSION,
        }


SECRETS_RULES: dict[str, SecretsRule] = {
    "SECRET-SIG-001": SecretsRule(
        "SECRET-SIG-001", "Provider credential signature", ("http_response", "javascript", "source_map", "public_config", "header"),
        "A bounded source contains a high-confidence provider key, token, private-key, or credential signature.",
        "Match provider-specific prefixes, private-key delimiters, and context-bound assignments; store only the signature family and redaction metadata.",
        "Suppress placeholders, documentation examples, short values, all-zero values, and known test/demo markers.",
        "Source location, signature family, length bucket, confidence tier, and redaction marker; never the matched value.",
        "high", "high", 98,
        "Remove the secret from public assets, revoke and rotate confirmed credentials, restrict scope, and move runtime secrets to a managed secret store.",
        ("CWE-200", "CWE-798"), ("OWASP-A02",),
    ),
    "SECRET-SIG-002": SecretsRule(
        "SECRET-SIG-002", "Private-key material signature", ("http_response", "javascript", "source_map", "public_config"),
        "A bounded response or script contains a PEM-style private-key delimiter.",
        "Detect private-key material delimiters without retaining any key body or subsequent lines.",
        "Only the delimiter family is retained; certificate/public-key labels and documentation text are not treated as private keys.",
        "Source location, key family, and redaction marker.",
        "critical", "high", 100,
        "Remove the key immediately, revoke or replace it, review access logs, and keep private keys outside web roots and client bundles.",
        ("CWE-321", "CWE-522"), ("OWASP-A02",),
    ),
    "SECRET-CONTEXT-001": SecretsRule(
        "SECRET-CONTEXT-001", "Context-bound credential assignment", ("http_response", "javascript", "source_map", "public_config", "header"),
        "A credential-like name is assigned a sufficiently long non-placeholder value in bounded evidence.",
        "Require a secret-context key such as api_key, client_secret, access_token, password, authorization, or private_key and a value with adequate length and entropy.",
        "Suppress common placeholders, hashes used as content IDs, UUIDs without a secret context, URLs, filenames, CSS values, and values below entropy/length thresholds.",
        "Context key category, length bucket, entropy tier, source location, and redaction marker.",
        "high", "high", 92,
        "Remove credentials from client-visible configuration, rotate exposed values, and use server-side secret injection with least privilege.",
        ("CWE-200", "CWE-798"), ("OWASP-A02",),
    ),
    "SECRET-ENTROPY-001": SecretsRule(
        "SECRET-ENTROPY-001", "High-entropy contextual secret candidate", ("javascript", "source_map", "public_config", "http_response"),
        "A long, high-entropy value occurs near a credential or configuration context but has no provider-specific signature.",
        "Use Shannon entropy, character diversity, assignment context, and minimum length to assign a medium confidence tier.",
        "Suppress values that look like URLs, hashes with explicit content-hash context, timestamps, generated CSS, minified code fragments, and repeated public constants.",
        "Entropy bucket, length bucket, context class, source location, and redaction marker.",
        "medium", "medium", 78,
        "Review the source context manually, remove secrets from public bundles, and rotate the value if it is confirmed as credential material.",
        ("CWE-200",), ("OWASP-A02",),
    ),
    "SECRET-ID-001": SecretsRule(
        "SECRET-ID-001", "Sensitive identifier signature", ("http_response", "javascript", "source_map", "public_config"),
        "A bounded source contains a high-confidence sensitive identifier such as an SSN-like value or a checksum-valid payment-card number near a relevant context.",
        "Use strict format checks, Luhn validation for payment-card candidates, and nearby context before reporting only the identifier class.",
        "Suppress random numeric strings, test-card markers, dates, phone numbers, order IDs, and values without a relevant identifier context.",
        "Identifier class, context class, length bucket, source location, and redaction marker.",
        "high", "high", 94,
        "Minimize or remove sensitive identifiers from public responses, apply access controls and masking, and follow the organization’s incident process for confirmed exposure.",
        ("CWE-359", "CWE-200"), ("OWASP-A02",),
    ),
    "SECRET-ARTIFACT-001": SecretsRule(
        "SECRET-ARTIFACT-001", "Public configuration or source-map leakage surface", ("source_map", "public_config"),
        "A stored response is classified as a source map or public configuration artifact and contains a secret candidate detected by another rule.",
        "Correlate artifact classification with a separate redacted signature finding; never fetch referenced artifacts or include their contents.",
        "Require a secret candidate in the captured artifact body; a URL reference alone is not a leakage finding.",
        "Artifact type, source location, linked signature family, and redaction marker.",
        "high", "high", 96,
        "Remove or restrict the artifact, rebuild public bundles without embedded secrets, and rotate any confirmed credential.",
        ("CWE-200",), ("OWASP-A05", "OWASP-A02"),
    ),
}


@dataclass(frozen=True)
class SecretCandidate:
    rule_id: str
    subject: str
    statement: str
    classification: str
    confidence: int
    confidence_tier: str
    severity: str
    evidence: tuple[dict[str, Any], ...]
    page_id: UUID | None
    secret_kind: str
    source_type: str
    context_class: str
    length_bucket: str
    entropy_tier: str
    limitations: str = LIMITATIONS


@dataclass(frozen=True)
class SecretSource:
    source_type: str
    source: str
    text: str
    page_id: UUID | None
    context_class: str
    artifact_type: str | None = None


PROVIDER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{16,}\b")),
    ("stripe_secret", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
)
CONTEXT_VALUE_RE = re.compile(
    r"[\"']?(?P<key>api[_-]?key|access[_-]?token|auth(?:orization)?|client[_-]?secret|secret[_-]?key|password|passwd|private[_-]?key|refresh[_-]?token|session[_-]?token)[\"']?\s*[:=]\s*(?:[\"'](?P<quoted>[^\"']{8,})[\"']|(?P<bare>[A-Za-z0-9_./+=:-]{12,}))",
    re.IGNORECASE,
)
GENERIC_ASSIGNMENT_RE = re.compile(r"[\"']?(?P<key>[A-Za-z][A-Za-z0-9_.-]{1,40})[\"']?\s*[:=]\s*[\"'](?P<quoted>[A-Za-z0-9_./+=:-]{20,})[\"']")
SSN_RE = re.compile(r"(?<!\d)(\d{3})[- ](\d{2})[- ](\d{4})(?!\d)")
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
PLACEHOLDER_RE = re.compile(r"(?:your[_ -]?|replace[_ -]?me|example|sample|dummy|test|fake|mock|changeme|redacted|placeholder|undefined|null|none|password123|secret123)", re.IGNORECASE)
URL_RE = re.compile(r"^(?:https?|wss?|data):", re.IGNORECASE)
HASH_CONTEXT_RE = re.compile(r"(?:hash|checksum|digest|etag|content[_-]?id)", re.IGNORECASE)
IDENTIFIER_CONTEXT_RE = re.compile(r"(?:ssn|social[_ -]?security|tax[_ -]?id|card|credit|payment|pan|account[_ -]?number)", re.IGNORECASE)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _luhn(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


class SecretsAgent:
    """Detect likely leaked secrets while never persisting or returning secret values."""

    def __init__(self, db: Session, scan_id: UUID) -> None:
        self.db = db
        self.scan_id = scan_id
        self.rule_version, self.disabled_rule_ids = self._update_metadata()

    def _sources(self) -> list[SecretSource]:
        sources: list[SecretSource] = []
        pages = self.db.query(Page).filter(Page.scan_id == self.scan_id).order_by(Page.canonical_url).all()
        for page in pages:
            response = self.db.query(HTTPResponse).filter(HTTPResponse.page_id == page.id).order_by(HTTPResponse.created_at.desc()).first()
            if not response:
                continue
            final_url = response.final_url or page.canonical_url
            body = response.raw_body or ""
            media_type = (response.content_type or "").split(";", 1)[0].lower()
            path = urlsplit(final_url).path.lower()
            artifact_type = self._artifact_type(final_url, media_type, body)
            if body:
                source_type = "javascript" if media_type in {"application/javascript", "text/javascript", "application/x-javascript"} or path.endswith(".js") else artifact_type or "http_response"
                sources.append(SecretSource(source_type, self._safe_source(final_url), body, page.id, self._context_from_body(body), artifact_type))
                if "<script" in body.lower():
                    soup = BeautifulSoup(body, "html.parser")
                    for index, script in enumerate(soup.find_all("script")):
                        script_text = script.get_text("\n", strip=False)
                        if script_text.strip():
                            sources.append(SecretSource("javascript", f"{self._safe_source(final_url)}#inline-script-{index}", script_text, page.id, "inline_script", None))
            for header in response.headers:
                sources.append(SecretSource("header", f"{self._safe_source(final_url)}#{header.name.lower()}", f"{header.name}: {header.value}", page.id, f"header:{header.name.lower()}", None))
            for resource in self.db.query(Resource).filter(Resource.page_id == page.id).all():
                resource_url = str(resource.url or "")
                if resource_url.lower().endswith((".map", ".env", ".json", ".yaml", ".yml")):
                    sources.append(SecretSource("source_map" if resource_url.lower().endswith(".map") else "public_config", self._safe_source(resource_url), "", page.id, "resource_reference", "source_map" if resource_url.lower().endswith(".map") else "public_config"))
        return [source for source in sources if source.text]

    def analyze(self) -> list[SecurityFinding]:
        self.db.query(SecurityFinding).filter(SecurityFinding.scan_id == self.scan_id, SecurityFinding.category == "secrets").delete(synchronize_session=False)
        self.db.flush()
        findings: list[SecurityFinding] = []
        seen: set[tuple[str, str, str, UUID | None]] = set()
        for source in self._sources():
            for candidate in self._detect_source(source):
                if candidate.rule_id in self.disabled_rule_ids:
                    continue
                key = (candidate.rule_id, candidate.secret_kind, candidate.source_type, candidate.page_id)
                if key in seen:
                    continue
                seen.add(key)
                self._validate(candidate)
                finding = SecurityFinding(
                    scan_id=self.scan_id,
                    page_id=candidate.page_id,
                    category="secrets",
                    subject=candidate.subject,
                    statement=candidate.statement,
                    classification=candidate.classification,
                    confidence=candidate.confidence,
                    confidence_band="high" if candidate.confidence >= 90 else "medium" if candidate.confidence >= 70 else "low",
                    severity=candidate.severity,
                    rule_id=candidate.rule_id,
                    rule_version=self.rule_version,
                    evidence=[dict(item) for item in candidate.evidence],
                    limitations=candidate.limitations,
                )
                self.db.add(finding)
                self.db.flush()
                findings.append(finding)
        self.db.commit()
        return findings

    def report(self) -> dict[str, Any]:
        findings = self.db.query(SecurityFinding).filter(SecurityFinding.scan_id == self.scan_id, SecurityFinding.category == "secrets").order_by(SecurityFinding.severity.desc(), SecurityFinding.subject).all()
        return {
            "scan_id": str(self.scan_id),
            "rule_version": self.rule_version,
            "rules": [SECRETS_RULES[key].as_dict() for key in sorted(SECRETS_RULES) if key not in self.disabled_rule_ids],
            "findings": [self._finding_dict(finding) for finding in findings],
            "summary": {
                "rule_count": len([key for key in SECRETS_RULES if key not in self.disabled_rule_ids]),
                "finding_count": len(findings),
                "critical_count": sum(1 for item in findings if item.severity == "critical"),
                "high_count": sum(1 for item in findings if item.severity == "high"),
                "medium_count": sum(1 for item in findings if item.severity == "medium"),
                "low_count": sum(1 for item in findings if item.severity == "low"),
                "confidence_tiers": {tier: sum(1 for item in findings if (item.evidence or [{}])[0].get("confidence_tier") == tier) for tier in ("high", "medium", "low")},
            },
            "redaction": {"values_persisted": False, "values_logged": False, "values_returned": False, "stored_evidence_mode": "minimum-redacted-metadata"},
        }

    def _update_metadata(self) -> tuple[str, set[str]]:
        try:
            active = UpdatePackageService(self.db).resolve_component("secret_patterns")
        except UpdatePackageError:
            active = None
        if not active:
            return RULE_VERSION, set()
        component = active["component"]
        version = component.get("version", RULE_VERSION)
        return f"{version}+{active['package_name']}-{active['package_version']}", set(component.get("disabled_rule_ids", []))

    def _detect_source(self, source: SecretSource) -> Iterable[SecretCandidate]:
        text = source.text
        detected_kinds: list[str] = []
        for kind, pattern in PROVIDER_PATTERNS:
            for match in pattern.finditer(text):
                value = match.group(0)
                if self._suppressed(value, source.context_class, kind):
                    continue
                rule_id = "SECRET-SIG-002" if kind == "private_key" else "SECRET-SIG-001"
                detected_kinds.append(kind)
                yield self._candidate(rule_id, source, kind, "provider_or_key_signature", "high", 100 if kind == "private_key" else 98, "critical" if kind == "private_key" else "high", value, match.start())
        for match in CONTEXT_VALUE_RE.finditer(text):
            value = match.group("quoted") or match.group("bare") or ""
            key = match.group("key")
            if self._suppressed(value, key, "context_assignment"):
                continue
            entropy = shannon_entropy(value)
            if len(value) < 16 or entropy < 3.2:
                continue
            detected_kinds.append(key.lower())
            yield self._candidate("SECRET-CONTEXT-001", source, key.lower(), "context_bound_assignment", "high", 92, "high", value, match.start(), entropy)
        for match in GENERIC_ASSIGNMENT_RE.finditer(text):
            key = match.group("key")
            value = match.group("quoted") or ""
            entropy = shannon_entropy(value)
            if not self._contextual_key(key) or self._suppressed(value, key, "generic_assignment") or len(value) < 24 or entropy < 3.8:
                continue
            detected_kinds.append(key.lower())
            yield self._candidate("SECRET-ENTROPY-001", source, key.lower(), "high_entropy_assignment", "medium", 78, "medium", value, match.start(), entropy)
        for match in SSN_RE.finditer(text):
            if not self._identifier_context(text, match.start()) or self._suppressed(match.group(0), "identifier", "ssn"):
                continue
            detected_kinds.append("ssn")
            yield self._candidate("SECRET-ID-001", source, "ssn", "sensitive_identifier", "high", 94, "high", match.group(0), match.start())
        for match in CARD_RE.finditer(text):
            value = match.group(0)
            if not _luhn(value) or not self._identifier_context(text, match.start()) or self._suppressed(value, "identifier", "payment_card"):
                continue
            detected_kinds.append("payment_card")
            yield self._candidate("SECRET-ID-001", source, "payment_card", "sensitive_identifier", "high", 94, "high", value, match.start())
        if source.artifact_type and detected_kinds:
            kind = sorted(set(detected_kinds))[0]
            yield self._candidate("SECRET-ARTIFACT-001", source, kind, "artifact_correlated_secret", "high", 96, "high", REDACTED, 0)

    def _candidate(self, rule_id: str, source: SecretSource, kind: str, context_class: str, tier: str, confidence: int, severity: str, value: str, position: int, entropy: float | None = None) -> SecretCandidate:
        length = len(value)
        length_bucket = "<16" if length < 16 else "16-31" if length < 32 else "32-63" if length < 64 else "64+"
        entropy_tier = "high" if (entropy or 0) >= 4.5 else "medium" if (entropy or 0) >= 3.2 else "low"
        observation = f"Detected {kind} in {source.source_type}; value={REDACTED}; length_bucket={length_bucket}; entropy_tier={entropy_tier}; confidence_tier={tier}; occurrence_offset_bucket={position // 100}."
        evidence = ({"id": f"secret:{rule_id}:{source.source}:{kind}", "type": "redacted_secret_indicator", "source": source.source[:2048], "observation": observation, "redacted": True, "confidence_tier": tier, "secret_kind": kind, "length_bucket": length_bucket, "entropy_tier": entropy_tier},)
        artifact_suffix = " in a public configuration/source-map artifact" if source.artifact_type else ""
        return SecretCandidate(rule_id, f"Potential {kind.replace('_', ' ')} exposure{artifact_suffix}", f"A likely {kind.replace('_', ' ')} was detected in bounded {source.source_type} evidence. The value is redacted and was not validated.", "OBSERVED" if tier == "high" else "INFERRED", confidence, tier, severity, evidence, source.page_id, kind, source.source_type, context_class, length_bucket, entropy_tier)

    @staticmethod
    def _validate(candidate: SecretCandidate) -> None:
        if not candidate.evidence or not candidate.limitations or REDACTED not in str(candidate.evidence):
            raise ValueError("Secrets findings require redacted evidence")
        if any(value in str(candidate.evidence).lower() for value in ("akia", "ghp_", "AIza", "sk_live_", "xox")):
            raise ValueError("Secrets evidence must not contain provider token material")

    @staticmethod
    def _suppressed(value: str, context: str, kind: str) -> bool:
        normalized = value.strip()
        if len(normalized) < 8 or PLACEHOLDER_RE.search(normalized) or URL_RE.match(normalized) or len(set(normalized)) <= 2:
            return True
        if kind in {"generic_assignment", "context_assignment"} and HASH_CONTEXT_RE.search(context):
            return True
        if normalized.lower() in {"authorization", "content", "application/json", "text/plain", "localhost", "production"}:
            return True
        return False

    @staticmethod
    def _contextual_key(key: str) -> bool:
        return bool(re.search(r"(?:key|token|secret|auth|password|passwd|credential|private)", key, re.IGNORECASE))

    @staticmethod
    def _identifier_context(text: str, position: int) -> bool:
        return bool(IDENTIFIER_CONTEXT_RE.search(text[max(0, position - 100): position + 100]))

    @staticmethod
    def _context_from_body(body: str) -> str:
        lowered = body.lower()
        if "sourcescontent" in lowered or "\"version\": 3" in lowered:
            return "source_map_or_json"
        if "api_key" in lowered or "access_token" in lowered or "client_secret" in lowered:
            return "configuration_context"
        return "response_body"

    @staticmethod
    def _artifact_type(url: str, media_type: str, body: str) -> str | None:
        path = urlsplit(url).path.lower()
        if path.endswith(".map") or "sourcescontent" in body.lower() or '"version": 3' in body.lower():
            return "source_map"
        if path.endswith((".env", ".json", ".yaml", ".yml")) or media_type in {"application/json", "application/yaml", "text/yaml"}:
            return "public_config"
        return None

    @staticmethod
    def _safe_source(source: str) -> str:
        parsed = urlsplit(source)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme and parsed.netloc else source.split("?", 1)[0]

    @staticmethod
    def _finding_dict(finding: SecurityFinding) -> dict[str, Any]:
        return {"id": str(finding.id), "category": finding.category, "subject": finding.subject, "statement": finding.statement, "classification": finding.classification, "confidence": finding.confidence, "confidence_band": finding.confidence_band, "severity": finding.severity, "rule_id": finding.rule_id, "rule_version": finding.rule_version, "limitations": finding.limitations, "page_id": str(finding.page_id) if finding.page_id else None, "evidence": finding.evidence or [], "created_at": finding.created_at.isoformat()}


__all__ = ["LIMITATIONS", "REDACTED", "RULE_VERSION", "SECRETS_RULES", "SecretsAgent", "SecretsRule", "shannon_entropy"]
