from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.models.scan import (
    HTTPResponse,
    Observation,
    Page,
    Technology,
    TechnologyEvidence,
)

RULESET_PATH = Path(__file__).resolve().parent.parent / "data" / "technology_signatures.json"


class EvidenceValidationError(ValueError):
    """Raised when a finding cannot be supported by linked evidence."""


@dataclass(frozen=True)
class SignatureRule:
    id: str
    technology: str
    category: str
    signal_type: str
    pattern: str
    weight: float
    field: str


@dataclass(frozen=True)
class DetectionSignal:
    rule: SignatureRule
    page_id: Any
    source: str
    observation: str


@dataclass(frozen=True)
class DetectionCandidate:
    technology: str
    category: str
    confidence: float
    confidence_band: str
    rule_version: str
    signals: tuple[DetectionSignal, ...]


class TechnologyDetectionService:
    """Deterministic, evidence-backed technology detection over stored crawl artifacts."""

    CLASSIFICATION = "inferred"

    def __init__(self, db: Session, scan_id: Any) -> None:
        self.db = db
        self.scan_id = scan_id
        self.rule_version, self.rules = self._load_rules()

    def detect(self) -> list[Technology]:
        pages = self.db.query(Page).filter(Page.scan_id == self.scan_id).all()
        contexts = [self._build_context(page) for page in pages]
        candidates: dict[tuple[str, str], list[DetectionSignal]] = {}

        for rule in self.rules:
            for context in contexts:
                signal = self._match_rule(rule, context)
                if signal is not None:
                    candidates.setdefault((rule.technology, rule.category), []).append(signal)

        existing_ids = [
            technology_id
            for (technology_id,) in self.db.query(Technology.id)
            .filter(Technology.scan_id == self.scan_id)
            .all()
        ]
        if existing_ids:
            self.db.query(TechnologyEvidence).filter(
                TechnologyEvidence.technology_id.in_(existing_ids)
            ).delete(synchronize_session=False)
        self.db.query(Technology).filter(Technology.scan_id == self.scan_id).delete(
            synchronize_session=False
        )
        self.db.query(Observation).filter(
            Observation.scan_id == self.scan_id,
            Observation.category == "TECHNOLOGY",
        ).delete(synchronize_session=False)
        self.db.flush()

        detections: list[Technology] = []
        for (technology_name, category), signals in sorted(candidates.items()):
            candidate = self._candidate_from_signals(
                technology_name, category, signals, self.rule_version
            )
            technology = self._persist_candidate(candidate)
            detections.append(technology)
            self.db.add(
                Observation(
                    scan_id=self.scan_id,
                    category="TECHNOLOGY",
                    subject=technology_name,
                    observation=(
                        f"Detected {technology_name} with {technology.confidence:.0f}% confidence "
                        f"from {len(signals)} evidence signal(s)."
                    ),
                    classification="INFERRED",
                )
            )

        self.db.commit()
        return detections

    def _persist_candidate(self, candidate: DetectionCandidate) -> Technology:
        self._validate_candidate(candidate)
        technology = Technology(
            scan_id=self.scan_id,
            canonical_name=candidate.technology,
            category=candidate.category,
            classification=self.CLASSIFICATION,
            confidence=candidate.confidence,
            confidence_band=candidate.confidence_band,
            rule_version=candidate.rule_version,
        )
        for signal in candidate.signals:
            technology.evidence.append(
                TechnologyEvidence(
                    scan_id=self.scan_id,
                    page_id=signal.page_id,
                    signal_type=signal.rule.signal_type,
                    match_rule=signal.rule.id,
                    source=signal.source,
                    observation=signal.observation,
                    match_weight=signal.rule.weight,
                )
            )
        # The relationship must remain non-empty before the Technology row is added.
        if not technology.evidence:
            raise EvidenceValidationError("Technology detection rejected: evidence list is empty.")
        self.db.add(technology)
        self.db.flush()
        return technology

    @staticmethod
    def _validate_candidate(candidate: DetectionCandidate) -> None:
        if candidate.confidence < 0 or candidate.confidence > 100:
            raise EvidenceValidationError("Technology confidence must be between 0 and 100.")
        if candidate.rule_version == "":
            raise EvidenceValidationError("Technology detection requires a ruleset version.")
        if not candidate.signals:
            raise EvidenceValidationError(
                f"Technology detection rejected for {candidate.technology}: no linked evidence."
            )
        for signal in candidate.signals:
            if not signal.source or not signal.observation or not signal.rule.id:
                raise EvidenceValidationError(
                    "Technology detection rejected for "
                    f"{candidate.technology}: incomplete evidence."
                )

    def _candidate_from_signals(
        self,
        technology: str,
        category: str,
        signals: list[DetectionSignal],
        rule_version: str,
    ) -> DetectionCandidate:
        # Count each rule once for explainability; multiple pages corroborate provenance
        # but do not inflate confidence simply because a site repeats the same asset.
        unique_signals = list({signal.rule.id: signal for signal in signals}.values())
        total_weight = sum(signal.rule.weight for signal in unique_signals)
        independent_bonus = max(0, len(unique_signals) - 1) * 5
        confidence = min(100.0, round(total_weight + independent_bonus, 2))
        if confidence >= 70:
            band = "high"
        elif confidence >= 40:
            band = "medium"
        else:
            band = "low"
        return DetectionCandidate(
            technology=technology,
            category=category,
            confidence=confidence,
            confidence_band=band,
            rule_version=rule_version,
            signals=tuple(signals),
        )

    def _build_context(self, page: Page) -> dict[str, Any]:
        response: HTTPResponse | None = page.http_responses[0] if page.http_responses else None
        html = response.raw_body if response and response.raw_body else ""
        soup = BeautifulSoup(html, "html.parser") if html else BeautifulSoup("", "html.parser")
        inline_scripts = [
            script.get_text(" ", strip=True)
            for script in soup.find_all("script")
            if not script.get("src") and script.get_text(strip=True)
        ]
        meta_values = []
        for meta in soup.find_all("meta"):
            values = [meta.get("name"), meta.get("property"), meta.get("content")]
            meta_values.append(" ".join(str(value) for value in values if value))
        headers = []
        cookies = []
        if response:
            headers = [f"{header.name}={header.value}" for header in response.headers]
            cookies = [
                header.value.split("=", 1)[0].strip()
                for header in response.headers
                if header.name.lower() == "set-cookie" and "=" in header.value
            ]
        resources = [resource for resource in page.resources if resource.url]
        return {
            "page": page,
            "html": html,
            "html_lower": html.lower(),
            "inline_scripts": inline_scripts,
            "meta_values": meta_values,
            "headers": headers,
            "cookies": cookies,
            "resources": resources,
        }

    def _match_rule(self, rule: SignatureRule, context: dict[str, Any]) -> DetectionSignal | None:
        values: list[tuple[str, str]] = []
        field = rule.field
        if field == "resource_url":
            values = [(str(resource.url), str(resource.url)) for resource in context["resources"]]
        elif field == "stylesheet_pattern":
            values = [
                (str(resource.url), str(resource.url))
                for resource in context["resources"]
                if resource.type == "link"
                and "stylesheet"
                in [str(item).lower() for item in (resource.attributes or {}).get("rel", [])]
            ]
        elif field == "resource_pattern":
            values = [(str(resource.url), str(resource.url)) for resource in context["resources"]]
        elif field == "headers":
            values = [(value, value) for value in context["headers"]]
        elif field == "inline_scripts":
            values = [(value, value) for value in context["inline_scripts"]]
        elif field == "cookies":
            values = [(value, value) for value in context["cookies"]]
        elif field == "meta_tag":
            values = [(value, value) for value in context["meta_values"]]
        elif field in {"html", "dom_pattern"}:
            values = [(context["html"], context["html"])]

        try:
            compiled = re.compile(rule.pattern, re.IGNORECASE)
        except re.error as exc:
            raise EvidenceValidationError(f"Invalid signature rule {rule.id}: {exc}") from exc

        for value, evidence_value in values:
            match = compiled.search(value)
            if match:
                excerpt = self._excerpt(evidence_value, match.group(0))
                page = context["page"]
                source = page.canonical_url
                if field in {"resource_url", "resource_pattern", "stylesheet_pattern"}:
                    source = evidence_value
                elif field == "headers":
                    source = f"{page.canonical_url}#{evidence_value.split('=', 1)[0]}"
                return DetectionSignal(
                    rule=rule,
                    page_id=page.id,
                    source=source,
                    observation=excerpt,
                )
        return None

    @staticmethod
    def _excerpt(value: str, matched: str) -> str:
        if not value:
            return ""
        position = value.lower().find(matched.lower()) if matched else 0
        if position < 0:
            return value[:300]
        start = max(0, position - 100)
        return value[start : start + 300]

    @staticmethod
    def _load_rules() -> tuple[str, list[SignatureRule]]:
        with RULESET_PATH.open(encoding="utf-8") as handle:
            data = json.load(handle)
        rules = [SignatureRule(**raw_rule) for raw_rule in data["rules"]]
        if not data.get("version") or not rules:
            raise EvidenceValidationError(
                "Technology ruleset must have a version and at least one rule."
            )
        return data["version"], rules


__all__ = [
    "DetectionCandidate",
    "DetectionSignal",
    "EvidenceValidationError",
    "SignatureRule",
    "TechnologyDetectionService",
]
