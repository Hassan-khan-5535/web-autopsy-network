"""Bounded SQL injection detection for explicitly authorized, safe validation scans.

The agent is intentionally conservative. It only sends GET requests to already
collected in-scope URLs, requires an explicit persisted opt-in, never submits
forms or JSON/XML bodies, never extracts data, and records only redacted
request/response metadata.
"""

from __future__ import annotations

import hashlib
import re
import statistics
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from uuid import UUID

import httpx
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.models.scan import HTTPObservation, HTTPResponse, Page, Scan, SecurityFinding
from app.services.assessment import (
    append_audit_event,
    credentials_headers,
    get_authorization,
    get_credentials,
    path_allowed,
    url_in_scope,
)
from app.services.scanner_security import (
    ScannerSecurityError,
    bounded_body,
    bounded_headers,
    redact_sensitive_text,
    revalidate_egress,
)

RULE_VERSION = "phase-sqli-v1"
LIMITATIONS = (
    "Authorized, bounded, non-destructive GET validation only. No forms are submitted, "
    "no JSON/XML bodies are sent, no authentication or cookies are guessed, no data is extracted, "
    "and no finding is treated as proof without the recorded validation evidence."
)

SQLI_RULES: dict[str, dict[str, Any]] = {
    "SQLI-ERROR-001": {
        "title": "SQL injection error-based candidate",
        "stage": "Stage 1: Error-Based",
        "severity": "high",
        "confidence": 75,
        "proof_required": "Baseline success, SQL-specific error response, safe counterpart success, timing bound, and three reproducible breaker responses.",
        "remediation": "Use parameterized queries, safe ORM bindings, strict input handling, and generic production error responses.",
        "cwe": ["CWE-89"],
        "owasp": ["OWASP-A03"],
    },
    "SQLI-DIFF-001": {
        "title": "SQL injection differential candidate",
        "stage": "Stage 2: Differential",
        "severity": "high",
        "confidence": 90,
        "proof_required": "Five stable baseline GETs, three reproducible true/false pairs, true responses matching the baseline, false responses differing by body hash or more than 10% in length, and no rate-limit/cache noise; no data extraction is performed.",
        "remediation": "Use parameterized statements and verify that boolean input cannot alter query structure.",
        "cwe": ["CWE-89"],
        "owasp": ["OWASP-A03"],
    },
    "SQLI-TIMING-001": {
        "title": "SQL injection timing indicator",
        "stage": "Stage 3: Timing-Safe",
        "severity": "high",
        "confidence": 90,
        "proof_required": "A measurable, reproducible delay from a safe timing canary. Heavy-delay payloads are disabled because they can create resource exhaustion.",
        "remediation": "Use parameterized queries, query timeouts, resource limits, and generic error handling.",
        "cwe": ["CWE-89", "CWE-400"],
        "owasp": ["OWASP-A03"],
    },
    "SQLI-UNION-001": {
        "title": "SQL injection union column-count candidate",
        "stage": "Stage 4: Union-Safe",
        "severity": "high",
        "confidence": 96,
        "proof_required": "Incremental NULL-only union probes produce exactly one HTTP 200 response with baseline page structure while other bounded counts produce SQL errors; database-specific null handling is checked and sensitive-response signals are absent.",
        "remediation": "Use parameterized queries and deny unexpected query structure; never rely on input filtering alone.",
        "cwe": ["CWE-89"],
        "owasp": ["OWASP-A03"],
    },
    "NOSQL-GET-001": {
        "title": "NoSQL operator differential candidate",
        "stage": "NoSQL Injection: Safe GET Operator",
        "severity": "high",
        "confidence": 65,
        "proof_required": "An in-scope GET query parameter with array-operator syntax produces a reproducible, non-sensitive response differential without submitting JSON, executing JavaScript, or modifying data.",
        "remediation": "Use strict schema validation, reject unexpected operator keys, and bind query values through a safe data-access layer.",
        "cwe": ["CWE-943"],
        "owasp": ["OWASP-A03"],
    },
    "SQLI-SECOND-ORDER-001": {
        "title": "Second-order SQL injection requires controlled workflow",
        "stage": "Second-Order SQLi: Passive Coverage",
        "severity": "high",
        "confidence": 70,
        "proof_required": "A uniquely traceable primary stored-value action, a separate safe secondary trigger, a SQL-specific error, and a non-injected control flow. This agent does not perform those state-changing actions.",
        "remediation": "Parameterize stored-value queries at every use site and validate both write and later read workflows under controlled authorized testing.",
        "cwe": ["CWE-89"],
        "owasp": ["OWASP-A03"],
    },
}

SQL_ERROR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("mysql", re.compile(r"(?:you have an error in your sql syntax|mysql|#1064)", re.IGNORECASE)),
    ("postgresql", re.compile(r"(?:error:\s+syntax error at or near|pg::error|postgres(?:ql)?)", re.IGNORECASE)),
    ("mssql", re.compile(r"(?:unclosed quotation mark|incorrect syntax near|\bmsg\s*\d+)", re.IGNORECASE)),
    ("oracle", re.compile(r"(?:ora-00933|ora-01756|ora-00907|pl/sql)", re.IGNORECASE)),
    ("sqlite", re.compile(r"(?:sqlite|jdbc|near\s+[^\n]{1,80}:\s+syntax error)", re.IGNORECASE)),
)

STAGE1_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("single_quote_break", "'"),
    ("double_quote_break", '"'),
    ("parenthesis_mismatch", "')"),
)
BOOLEAN_PAYLOAD_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("numeric_and", " AND 1=1", " AND 1=2"),
    ("string_and", "' AND '1'='1", "' AND '1'='2"),
    ("or_logic", " OR 1=1", " OR 1=2"),
    ("comment_bypass", "'-- ", "' AND '1'='2'-- "),
)
MAX_SURFACES = 3
MAX_REPRODUCTIONS = 3
BASELINE_SAMPLES = 5
DIFFERENTIAL_PAIRS = 3
DIFFERENTIAL_LENGTH_THRESHOLD = 0.10
MAX_UNION_COLUMNS = 3
TIMING_VALUES_SECONDS: tuple[int, ...] = (1, 3, 5)
TIMING_BASELINE_SAMPLES = 10
TIMING_MAX_DELAY_SECONDS = 5
TIMING_MULTIPLIER = 2.0
TIMING_DATABASES: tuple[str, ...] = ("mysql", "postgresql", "mssql", "oracle")
TIMING_UNSUPPORTED_DATABASES: tuple[str, ...] = ("sqlite",)
NOSQL_OPERATOR_PROBES: tuple[tuple[str, str, str], ...] = (
    ("array_ne", "[$ne]", "__web_autopsy_null__"),
    ("array_gt", "[$gt]", ""),
    ("array_regex", "[$regex]", "^.*$"),
)
NOSQL_REPRODUCTIONS = 2


@dataclass(frozen=True)
class ProbeResponse:
    status_code: int | None
    elapsed_ms: float
    body: str
    body_hash: str
    marker_categories: tuple[str, ...]
    error: str | None = None
    body_length: int = 0
    noise_signals: tuple[str, ...] = ()

    @property
    def successful(self) -> bool:
        return self.status_code is not None and 200 <= self.status_code < 300 and self.error is None


@dataclass(frozen=True)
class InputSurface:
    page_id: UUID
    url: str
    name: str
    location: str
    method: str
    original_value: str


class SQLiDetectionAgent:
    """Run the explicitly opted-in, non-destructive SQLi validation pipeline."""

    def __init__(self, db: Session, scan_id: UUID):
        self.db = db
        self.scan_id = scan_id
        self.scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not self.scan:
            raise ValueError(f"Scan {scan_id} not found")
        self.authorization = get_authorization(db, scan_id)
        scope = dict(self.authorization.scope_json or {}) if self.authorization else {}
        self.enabled = bool(scope.get("sqli_validation_enabled")) and self.scan.recon_mode == "active_safe"
        self.extended_enabled = self.enabled and bool(scope.get("sqli_extended_validation_enabled"))
        self.scope = scope
        self.allowed_ports = {int(item) for item in scope.get("allowed_ports", []) if str(item).isdigit()}
        self.auth_headers = credentials_headers(get_credentials(db, scan_id))
        self.rate_limit_seconds = max(0, int(getattr(self.authorization, "rate_limit_per_host_ms", 1000) or 1000)) / 1000
        self.max_requests = int((self.authorization.max_requests if self.authorization else None) or self.scan.max_requests or 30)
        self.requests_used = int(self.scan.requests_used or 0)
        self.last_request_at: dict[str, float] = {}
        self.probe_observations: list[HTTPObservation] = []
        self.summary: dict[str, Any] = {
            "enabled": self.enabled,
            "mode": "authorized_get_only" if self.enabled else "disabled_by_default",
            "extended_enabled": self.extended_enabled,
            "differential_validation": {"baseline_samples_required": BASELINE_SAMPLES, "pairs_required": DIFFERENTIAL_PAIRS, "length_threshold": DIFFERENTIAL_LENGTH_THRESHOLD, "noise_suppressed": 0},
            "timing_validation": {"baseline_samples_required": TIMING_BASELINE_SAMPLES, "timing_values_seconds": list(TIMING_VALUES_SECONDS), "max_delay_seconds": TIMING_MAX_DELAY_SECONDS, "delay_multiplier": TIMING_MULTIPLIER, "noise_suppressed": 0},
            "union_validation": {"max_columns": MAX_UNION_COLUMNS, "null_only": True, "database_variants_tested": ["generic", "mysql", "oracle", "mssql"], "sensitive_response_suppressed": 0},
            "nosql_validation": {"mode": "safe_get_operator_only", "json_body_probes": 0, "javascript_probes": 0, "array_operator_probes": 0, "sensitive_response_suppressed": 0},
            "second_order_validation": {"mode": "passive_only", "status": "not_tested_safely", "primary_actions_submitted": 0, "secondary_actions_triggered": 0, "control_flows_run": 0, "sql_error_response_candidates": 0, "finding_count": 0},
            "stages": {"error_based": 0, "differential": 0, "timing_safe": 0, "union_safe": 0, "nosql": 0, "second_order": 0},
            "surfaces": {"query_tested": 0, "get_forms_tested": 0, "post_forms_not_tested": 0, "headers_not_tested": 0, "cookies_not_tested": 0, "json_xml_not_tested": 0},
            "requests_issued": 0,
            "payloads_sent": 0,
            "mutating_requests_issued": 0,
            "data_extraction_attempted": False,
            "limitations": LIMITATIONS,
        }

    def analyze(self) -> list[SecurityFinding]:
        self.db.query(SecurityFinding).filter(SecurityFinding.scan_id == self.scan_id, SecurityFinding.category == "sqli").delete(synchronize_session=False)
        self.db.query(HTTPObservation).filter(HTTPObservation.scan_id == self.scan_id, HTTPObservation.observation_type == "sqli_validation").delete(synchronize_session=False)
        self.db.flush()
        if not self.enabled:
            self.db.commit()
            return []

        findings: list[SecurityFinding] = []
        surfaces = self._surfaces()
        self._record_second_order_coverage(surfaces)
        for surface in surfaces[:MAX_SURFACES]:
            if surface.location == "form_post":
                self.summary["surfaces"]["post_forms_not_tested"] += 1
                self._record_coverage(surface, "post_form_not_tested", "POST forms are intentionally not submitted by the non-destructive SQLi agent.")
                continue
            if surface.location not in {"query", "form_get"} or surface.method != "GET":
                self._record_coverage(surface, "input_location_not_tested", "Only in-scope GET query/form inputs are eligible; headers, cookies, JSON, and XML bodies are not probed.")
                continue
            if surface.location == "query":
                self.summary["surfaces"]["query_tested"] += 1
            else:
                self.summary["surfaces"]["get_forms_tested"] += 1
            finding = self._test_surface(surface)
            if finding:
                findings.append(finding)

        self.summary["surfaces"]["headers_not_tested"] = 1
        self.summary["surfaces"]["cookies_not_tested"] = 1
        self.summary["surfaces"]["json_xml_not_tested"] = 1
        self.scan.requests_used = self.requests_used
        self.db.commit()
        return findings

    def report(self) -> dict[str, Any]:
        findings = self.db.query(SecurityFinding).filter(SecurityFinding.scan_id == self.scan_id, SecurityFinding.category == "sqli").order_by(SecurityFinding.created_at, SecurityFinding.subject).all()
        return {
            "scan_id": str(self.scan_id),
            "rule_version": RULE_VERSION,
            "rules": [self._rule_dict(rule_id, value) for rule_id, value in SQLI_RULES.items()],
            "findings": [self._finding_dict(item) for item in findings],
            "summary": {**self.summary, "finding_count": len(findings), "high_count": sum(str(item.severity).lower() == "high" for item in findings)},
            "safe_validation": {
                "mode": "authorized_get_only",
                "network_requests_issued": self.summary["requests_issued"],
                "payloads_sent": self.summary["payloads_sent"],
                "forms_submitted": 0,
                "mutating_requests_issued": 0,
                "authentication_attempts": 0,
                "data_extraction_attempted": False,
            },
        }

    def _surfaces(self) -> list[InputSurface]:
        surfaces: list[InputSurface] = []
        pages = self.db.query(Page).filter(Page.scan_id == self.scan_id).order_by(Page.canonical_url).all()
        seen: set[tuple[UUID, str, str]] = set()
        for page in pages:
            parsed = urlsplit(page.canonical_url)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                key = (page.id, "query", name)
                if key not in seen:
                    seen.add(key)
                    surfaces.append(InputSurface(page.id, page.canonical_url, name, "query", "GET", value))
            response = self.db.query(HTTPResponse).filter(HTTPResponse.page_id == page.id).order_by(HTTPResponse.created_at.desc()).first()
            if not response:
                continue
            body = response.raw_body or response.rendered_body or ""
            for form in BeautifulSoup(body, "html.parser").find_all("form"):
                method = str(form.get("method") or "get").upper()
                action = urljoin(page.canonical_url, str(form.get("action") or page.canonical_url))
                for field in form.find_all(["input", "textarea", "select"]):
                    name = str(field.get("name") or "").strip()
                    if not name:
                        continue
                    key = (page.id, "form_get" if method == "GET" else "form_post", name)
                    if key in seen:
                        continue
                    seen.add(key)
                    value = str(field.get("value") or "")
                    surfaces.append(InputSurface(page.id, action, name, "form_get" if method == "GET" else "form_post", method, value))
        return surfaces

    def _test_surface(self, surface: InputSurface) -> SecurityFinding | None:
        baseline_samples = [self._request(surface.url, f"baseline:{index}") for index in range(BASELINE_SAMPLES)]
        if not self._baseline_gate(baseline_samples):
            if any(item.noise_signals for item in baseline_samples):
                self.summary["differential_validation"]["noise_suppressed"] += 1
            self._record_coverage(surface, "baseline_not_stable", f"Five baseline GETs were required, but the responses were unsuccessful, unstable, rate-limited, or cache-affected; no SQLi canary was sent.", baseline_samples[0] if baseline_samples else None)
            return None
        baseline = baseline_samples[0]

        stage1 = self._stage1(surface, baseline_samples)
        if stage1:
            return stage1
        stage2 = self._stage2(surface, baseline_samples)
        if stage2:
            return stage2
        if self.extended_enabled:
            stage3 = self._stage3(surface, baseline_samples)
            if stage3:
                return stage3
            stage4 = self._stage4(surface, baseline)
            if stage4:
                return stage4
            nosql = self._nosql_get_stage(surface, baseline)
            if nosql:
                return nosql
        self._record_coverage(surface, "no_high_signal_difference", "Safe SQLi and NoSQL canaries did not produce the required reproducible evidence. Second-order validation remains passive because state-changing actions are prohibited.", baseline)
        return None

    def _stage1(self, surface: InputSurface, baseline_samples: list[ProbeResponse]) -> SecurityFinding | None:
        baseline = baseline_samples[0]
        for payload_name, suffix in STAGE1_PAYLOADS:
            breaking_url = self._replace_value(surface.url, surface.name, surface.original_value + suffix)
            counterpart_url = self._replace_value(surface.url, surface.name, surface.original_value + "''")
            breaking = self._request(breaking_url, payload_name)
            counterpart = self._request(counterpart_url, "safe_counterpart")
            if not self._error_gate(baseline, breaking, counterpart):
                continue
            repetitions = [self._request(breaking_url, f"{payload_name}:repeat:{index}") for index in range(MAX_REPRODUCTIONS)]
            if not all(self._same_error_signature(breaking, item) for item in repetitions):
                continue
            self.summary["stages"]["error_based"] += 1
            evidence = self._evidence(surface, "error_based", payload_name, baseline, breaking, counterpart, repetitions)
            return self._persist_finding(
                surface,
                "SQLI-ERROR-001",
                f"A reproducible SQL-specific error response was observed when a syntax-breaking canary was applied to GET parameter `{surface.name}`. The safe counterpart returned successfully; no data was extracted.",
                "OBSERVED",
                75,
                evidence,
            )
        return None

    def _stage2(self, surface: InputSurface, baseline_samples: list[ProbeResponse]) -> SecurityFinding | None:
        baseline = baseline_samples[0]
        baseline_signatures = {self._signature(item) for item in baseline_samples}
        for payload_name, true_suffix, false_suffix in BOOLEAN_PAYLOAD_PAIRS:
            pairs: list[tuple[ProbeResponse, ProbeResponse]] = []
            for index in range(DIFFERENTIAL_PAIRS):
                true_result = self._request(self._replace_value(surface.url, surface.name, surface.original_value + true_suffix), f"boolean:{payload_name}:true:{index}")
                false_result = self._request(self._replace_value(surface.url, surface.name, surface.original_value + false_suffix), f"boolean:{payload_name}:false:{index}")
                pairs.append((true_result, false_result))
            if not all(self._differential_pair_gate(true_result, false_result, baseline_signatures) for true_result, false_result in pairs):
                if any(item.noise_signals for pair in pairs for item in pair):
                    self.summary["differential_validation"]["noise_suppressed"] += 1
                continue
            self.summary["stages"]["differential"] += 1
            true_results = [pair[0] for pair in pairs]
            false_results = [pair[1] for pair in pairs]
            first_true, first_false = true_results[0], false_results[0]
            evidence = self._evidence(
                surface,
                "differential",
                payload_name,
                baseline,
                first_true,
                first_false,
                true_results + false_results,
                details={
                    "baseline_samples": len(baseline_samples),
                    "pair_count": len(pairs),
                    "true_matches_baseline": True,
                    "false_differential_pairs": len(pairs),
                    "false_length_ratio": self._length_ratio(first_true, first_false),
                    "false_hash_differs": first_true.body_hash != first_false.body_hash,
                    "noise_signals": sorted({signal for pair in pairs for item in pair for signal in item.noise_signals}),
                },
            )
            return self._persist_finding(
                surface,
                "SQLI-DIFF-001",
                f"Five stable baselines and three reproducible true/false boolean pairs produced a baseline-matching true response and a materially different false response for GET parameter `{surface.name}`. No data-bearing expression was used or returned.",
                "OBSERVED",
                90,
                evidence,
            )
        return None

    def _nosql_get_stage(self, surface: InputSurface, baseline: ProbeResponse) -> SecurityFinding | None:
        """Test only URL query operator syntax; JSON bodies and JavaScript are never sent."""
        if surface.location != "query" or not baseline.successful or self._contains_sensitive_data(baseline.body):
            return None
        baseline_structure = self._structure_hash(baseline.body)
        safe_control = self._request(surface.url, "nosql_safe_control")
        if not safe_control.successful or safe_control.noise_signals or self._signature(safe_control) != self._signature(baseline):
            return None
        for probe_name, operator_suffix, operator_value in NOSQL_OPERATOR_PROBES:
            results: list[ProbeResponse] = []
            for index in range(NOSQL_REPRODUCTIONS):
                url = self._replace_operator(surface.url, surface.name, operator_suffix, operator_value)
                results.append(self._request(url, f"nosql:{probe_name}:{index}"))
            if not all(item.successful and not item.noise_signals for item in results):
                continue
            if any(self._contains_sensitive_data(item.body) for item in results):
                self.summary["nosql_validation"]["sensitive_response_suppressed"] += 1
                continue
            if not all(self._structure_hash(item.body) == baseline_structure for item in results):
                continue
            if len({self._signature(item) for item in results}) != 1:
                continue
            if not all(item.body_hash != baseline.body_hash or self._length_ratio(baseline, item) > DIFFERENTIAL_LENGTH_THRESHOLD for item in results):
                continue
            self.summary["nosql_validation"]["array_operator_probes"] += 1
            self.summary["stages"]["nosql"] += 1
            evidence = self._evidence(surface, "nosql", probe_name, baseline, results[0], safe_control, results, details={"operator_family": probe_name, "reproductions": len(results), "baseline_structure_preserved": True, "response_differential": True, "json_body_probes": 0, "javascript_probes": 0, "data_extraction_attempted": False, "mutating_requests_issued": 0})
            return self._persist_finding(
                surface,
                "NOSQL-GET-001",
                f"A safe GET query-operator probe produced a reproducible, structure-preserving response differential for parameter `{surface.name}`. No JSON body, JavaScript expression, or data extraction was used.",
                "INFERRED",
                65,
                evidence,
            )
        return None

    def _record_second_order_coverage(self, surfaces: list[InputSurface]) -> None:
        """Record the required second-order workflow state without performing prohibited writes or triggers."""
        response_rows = self.db.query(HTTPResponse).join(Page, HTTPResponse.page_id == Page.id).filter(Page.scan_id == self.scan_id).all()
        sql_error_candidates = sum(1 for response in response_rows if self._markers(response.raw_body or response.rendered_body or ""))
        self.summary["second_order_validation"]["sql_error_response_candidates"] = sql_error_candidates
        self.summary["second_order_validation"]["status"] = "inconclusive_passive_only" if sql_error_candidates else "not_tested_safely"
        if surfaces:
            self._record_coverage(surfaces[0], "second_order_not_tested", "Second-order SQLi requires a uniquely traceable stored-value action and a later trigger; this non-destructive agent submits neither primary state-changing actions nor secondary workflows.")

    @staticmethod
    def _replace_operator(url: str, name: str, operator_suffix: str, value: str) -> str:
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        output: list[tuple[str, str]] = []
        for key, current in pairs:
            if key == name and not replaced:
                output.append((f"{key}{operator_suffix}", value))
                replaced = True
            else:
                output.append((key, current))
        if not replaced:
            output.append((f"{name}{operator_suffix}", value))
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(output), ""))

    def _stage3(self, surface: InputSurface, _prior_baseline_samples: list[ProbeResponse]) -> SecurityFinding | None:
        """Validate timing correlation with bounded 1/3/5-second canaries only."""
        baseline_samples = [self._request(surface.url, f"timing_baseline:{index}") for index in range(TIMING_BASELINE_SAMPLES)]
        if len(baseline_samples) != TIMING_BASELINE_SAMPLES or not all(item.successful and not item.noise_signals for item in baseline_samples):
            self.summary["timing_validation"]["noise_suppressed"] += 1 if any(item.noise_signals for item in baseline_samples) else 0
            return None
        baseline_times = [item.elapsed_ms for item in baseline_samples]
        baseline_mean = statistics.mean(baseline_times)
        baseline_stdev = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0.0
        baseline_upper_bound = baseline_mean + (2 * baseline_stdev)
        threshold_ms = max(baseline_mean * TIMING_MULTIPLIER, baseline_upper_bound)
        safe_control = self._request(surface.url, "timing_safe_control")
        if not safe_control.successful or safe_control.noise_signals or safe_control.elapsed_ms > baseline_upper_bound:
            return None
        timing_results: list[dict[str, Any]] = []
        grouped: dict[str, list[tuple[dict[str, Any], ProbeResponse]]] = {}
        for delay_seconds in TIMING_VALUES_SECONDS:
            per_database: list[ProbeResponse] = []
            for database, payload in self._timing_payloads(delay_seconds):
                url = self._replace_value(surface.url, surface.name, surface.original_value + payload)
                result = self._request(url, f"timing_safe:{database}:{delay_seconds}")
                per_database.append(result)
                item = {"database": database, "requested_delay_seconds": delay_seconds, "elapsed_ms": result.elapsed_ms, "status_code": result.status_code, "error": bool(result.error), "noise_signals": list(result.noise_signals)}
                timing_results.append(item)
                if not result.error and not result.noise_signals and result.status_code is not None:
                    grouped.setdefault(database, []).append((item, result))
            if any(item.noise_signals for item in per_database):
                self.summary["timing_validation"]["noise_suppressed"] += 1
        correlations: dict[str, float] = {}
        for database, pairs in grouped.items():
            if len(pairs) != len(TIMING_VALUES_SECONDS):
                continue
            ordered = sorted(pairs, key=lambda value: value[0]["requested_delay_seconds"])
            requested = [item[0]["requested_delay_seconds"] for item in ordered]
            measured = [item[0]["elapsed_ms"] for item in ordered]
            correlations[database] = self._pearson_correlation(requested, measured)
        confirmed = []
        for database, pairs in grouped.items():
            ordered = sorted(pairs, key=lambda value: value[0]["requested_delay_seconds"])
            measured = [item[0]["elapsed_ms"] for item in ordered]
            if len(ordered) == len(TIMING_VALUES_SECONDS) and correlations.get(database, 0.0) >= 0.85 and all(item[0]["elapsed_ms"] > threshold_ms for item in ordered) and all(left < right for left, right in zip(measured, measured[1:])):
                confirmed.append((database, ordered))
        if not confirmed:
            return None
        database, pairs = max(confirmed, key=lambda pair: correlations.get(pair[0], 0.0))
        ordered_pairs = sorted(pairs, key=lambda value: value[0]["requested_delay_seconds"])
        self.summary["stages"]["timing_safe"] += 1
        evidence = self._evidence(surface, "timing_safe", f"timing_values_{database}", baseline_samples[0], ordered_pairs[-1][1], safe_control, [item for _, item in ordered_pairs], details={"baseline_sample_count": len(baseline_samples), "baseline_mean_ms": round(baseline_mean, 2), "baseline_stdev_ms": round(baseline_stdev, 2), "baseline_mean_plus_two_sigma_ms": round(baseline_upper_bound, 2), "delay_threshold_ms": round(threshold_ms, 2), "safe_control_elapsed_ms": safe_control.elapsed_ms, "database_type": database, "timing_values_seconds": list(TIMING_VALUES_SECONDS), "timing_results": [item for item, _ in ordered_pairs], "correlation": round(correlations[database], 4), "max_delay_seconds": TIMING_MAX_DELAY_SECONDS, "heavy_delay_payloads_used": False, "network_jitter_accounted": True, "unsupported_database_types": list(TIMING_UNSUPPORTED_DATABASES)})
        return self._persist_finding(
            surface,
            "SQLI-TIMING-001",
            f"Bounded timing canaries at 1, 3, and 5 seconds correlated with requested delays for GET parameter `{surface.name}` and exceeded the ten-sample baseline threshold. No data was extracted.",
            "INFERRED",
            90,
            evidence,
        )

    @staticmethod
    def _timing_payloads(delay_seconds: int) -> tuple[tuple[str, str], ...]:
        """Return only bounded vendor-specific timing expressions; never accept arbitrary delay input."""
        if delay_seconds not in TIMING_VALUES_SECONDS or delay_seconds > TIMING_MAX_DELAY_SECONDS:
            raise ValueError("unsupported timing value")
        return (
            ("mysql", f"' AND IF(1=1,SLEEP({delay_seconds}),0)-- "),
            ("postgresql", f"'; SELECT pg_sleep({delay_seconds})-- "),
            ("mssql", f"'; WAITFOR DELAY '00:00:0{delay_seconds}'-- "),
            ("oracle", f"' AND DBMS_LOCK.SLEEP({delay_seconds})-- "),
        )

    @staticmethod
    def _pearson_correlation(first: list[float], second: list[float]) -> float:
        if len(first) != len(second) or len(first) < 2:
            return 0.0
        first_mean, second_mean = statistics.mean(first), statistics.mean(second)
        numerator = sum((left - first_mean) * (right - second_mean) for left, right in zip(first, second))
        first_variance = sum((left - first_mean) ** 2 for left in first)
        second_variance = sum((right - second_mean) ** 2 for right in second)
        denominator = (first_variance * second_variance) ** 0.5
        return numerator / denominator if denominator else 0.0

    def _stage4(self, surface: InputSurface, baseline: ProbeResponse) -> SecurityFinding | None:
        """Infer one column-count match using only NULL expressions and stable page structure."""
        baseline_structure = self._structure_hash(baseline.body)
        if not baseline.successful or self._contains_sensitive_data(baseline.body):
            self.summary["union_validation"]["sensitive_response_suppressed"] += 1
            return None
        matches: list[tuple[int, list[tuple[dict[str, Any], ProbeResponse]]]] = []
        mismatches: list[ProbeResponse] = []
        column_results: list[dict[str, Any]] = []
        for columns in range(1, MAX_UNION_COLUMNS + 1):
            variant_results: list[tuple[dict[str, Any], ProbeResponse]] = []
            for database, union in self._union_payloads(columns):
                result = self._request(self._replace_value(surface.url, surface.name, surface.original_value + union), f"union_null_columns:{database}:{columns}")
                structure_match = result.successful and self._structure_hash(result.body) == baseline_structure
                sensitive = self._contains_sensitive_data(result.body)
                metadata = {"database_variant": database, "column_count": columns, "status_code": result.status_code, "body_hash": result.body_hash, "structure_match": structure_match, "sql_error": bool(result.marker_categories) or bool(result.status_code and result.status_code >= 500), "sensitive_data_signal": sensitive}
                variant_results.append((metadata, result))
                column_results.append(metadata)
            valid_matches = [(metadata, result) for metadata, result in variant_results if metadata["structure_match"] and not metadata["sensitive_data_signal"]]
            if valid_matches:
                matches.append((columns, valid_matches))
            else:
                mismatch = next((result for metadata, result in variant_results if metadata["sql_error"]), None)
                if mismatch:
                    mismatches.append(mismatch)
            if any(metadata["sensitive_data_signal"] for metadata, _ in variant_results):
                self.summary["union_validation"]["sensitive_response_suppressed"] += 1
        if len(matches) != 1 or not mismatches:
            return None
        columns, matching_variants = matches[0]
        match_metadata, match = matching_variants[0]
        self.summary["stages"]["union_safe"] += 1
        evidence = self._evidence(surface, "union_safe", f"null_columns_{columns}", baseline, match, mismatches[0], [result for _, result in matching_variants] + mismatches, details={"column_count": columns, "max_columns_tested": MAX_UNION_COLUMNS, "null_only": True, "baseline_structure_hash": baseline_structure, "matching_variant": match_metadata, "column_results": column_results, "mismatch_count": len(mismatches), "sensitive_data_checked": True, "sensitive_data_detected": False})
        return self._persist_finding(
            surface,
            "SQLI-UNION-001",
            f"A NULL-only union probe with {columns} inferred column(s) returned HTTP 200 with baseline page structure while other bounded NULL counts produced SQL errors. No application data was selected or retained.",
            "INFERRED",
            96,
            evidence,
        )

    @staticmethod
    def _union_payloads(columns: int) -> tuple[tuple[str, str], ...]:
        """Return bounded NULL-only probes with safe database-specific terminators."""
        if columns < 1 or columns > MAX_UNION_COLUMNS:
            raise ValueError("unsupported union column count")
        nulls = ",".join("NULL" for _ in range(columns))
        return (
            ("generic", f"' UNION SELECT {nulls}-- "),
            ("mysql", f"' UNION SELECT {nulls}#"),
            ("oracle", f"' UNION SELECT {nulls} FROM DUAL-- "),
            ("mssql", f"' UNION SELECT {nulls}-- "),
        )

    @staticmethod
    def _structure_hash(body: str) -> str:
        normalized = re.sub(r"<!--.*?-->", "", body[:512 * 1024], flags=re.DOTALL)
        normalized = re.sub(r"\s+", " ", normalized).strip().lower()
        normalized = re.sub(r"\b\d+\b", "<number>", normalized)
        return hashlib.sha256(normalized.encode("utf-8", "ignore")).hexdigest()[:16]

    @staticmethod
    def _contains_sensitive_data(body: str) -> bool:
        if not body:
            return False
        sensitive_patterns = (
            r"-----begin [^-]{0,40}private key-----",
            r"\beyj[a-z0-9_-]{20,}\.[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}\b",
            r"\b(?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*[\"']?[a-z0-9_+/=-]{16,}",
        )
        if any(re.search(pattern, body, re.IGNORECASE) for pattern in sensitive_patterns):
            return True
        for token in re.findall(r"[A-Za-z0-9+/=_-]{24,}", body):
            if SQLiDetectionAgent._shannon_entropy(token) >= 4.2:
                return True
        return False

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = {character: value.count(character) for character in set(value)}
        length = len(value)
        return -sum((count / length) * __import__("math").log2(count / length) for count in counts.values())

    def _baseline_gate(self, samples: list[ProbeResponse]) -> bool:
        if len(samples) != BASELINE_SAMPLES or not all(item.successful and not item.noise_signals for item in samples):
            return False
        return len({self._signature(item) for item in samples}) == 1

    def _differential_pair_gate(self, true_result: ProbeResponse, false_result: ProbeResponse, baseline_signatures: set[tuple[int | None, str, tuple[str, ...]]]) -> bool:
        if not true_result.successful or true_result.noise_signals or false_result.error or false_result.noise_signals:
            return False
        if self._signature(true_result) not in baseline_signatures:
            return False
        if self._signature(true_result) == self._signature(false_result):
            return False
        return false_result.body_hash != true_result.body_hash or self._length_ratio(true_result, false_result) > DIFFERENTIAL_LENGTH_THRESHOLD

    @staticmethod
    def _length_ratio(first: ProbeResponse, second: ProbeResponse) -> float:
        denominator = max(first.body_length, 1)
        return abs(second.body_length - first.body_length) / denominator

    @staticmethod
    def _error_gate(baseline: ProbeResponse, breaking: ProbeResponse, counterpart: ProbeResponse) -> bool:
        if not baseline.successful or not counterpart.successful:
            return False
        has_error = (breaking.status_code is not None and breaking.status_code >= 500) or bool(breaking.marker_categories)
        baseline_time = max(baseline.elapsed_ms, 1.0)
        return has_error and breaking.elapsed_ms < baseline_time * 2

    @staticmethod
    def _same_error_signature(first: ProbeResponse, other: ProbeResponse) -> bool:
        return first.status_code == other.status_code and first.marker_categories == other.marker_categories

    def _request(self, url: str, variant: str = "baseline") -> ProbeResponse:
        if self.requests_used >= self.max_requests:
            return ProbeResponse(None, 0.0, "", "", (), "SQLi request budget exhausted")
        if not self.authorization or not url_in_scope(url, self.authorization):
            return ProbeResponse(None, 0.0, "", "", (), "SQLi URL is outside the persisted authorization scope")
        hostname = (urlsplit(url).hostname or "").lower()
        now = time.monotonic()
        remaining = self.rate_limit_seconds - (now - self.last_request_at.get(hostname, 0.0))
        if remaining > 0:
            time.sleep(remaining)
        self.last_request_at[hostname] = time.monotonic()
        try:
            canonical = revalidate_egress(
                url,
                assessment_profile=self.scan.assessment_profile if self.scan.assessment_profile in {"safe", "normal", "aggressive"} else None,
                explicit_allowlist=bool(self.authorization.allowed_domains),
                allowed_ports=self.allowed_ports,
            )
            started = time.perf_counter()
            with httpx.Client(timeout=10.0, follow_redirects=False, headers={"User-Agent": "WebAutopsyNetwork/0.3 (authorized safe SQLi validation)", "Accept": "text/html,application/json,text/plain", **self.auth_headers}) as client:
                with client.stream("GET", canonical) as response:
                    headers = bounded_headers(response, 64 * 1024)
                    body_bytes, truncated = bounded_body(response, 512 * 1024)
                    body = body_bytes.decode(response.encoding or "utf-8", errors="replace")
                    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
                    markers = self._markers(body)
                    noise_signals = self._noise_signals(response.status_code, headers)
                    result = ProbeResponse(response.status_code, elapsed_ms, body, self._body_hash(body), markers, body_length=len(body), noise_signals=noise_signals)
                    self.requests_used += 1
                    self.summary["requests_issued"] += 1
                    if variant != "baseline":
                        self.summary["payloads_sent"] += 1
                    self._record_probe(url, variant, result, truncated, headers)
                    return result
        except (httpx.HTTPError, ScannerSecurityError, ValueError) as exc:
            self.requests_used += 1
            self.summary["requests_issued"] += 1
            result = ProbeResponse(None, round((time.perf_counter() - started) * 1000, 2) if "started" in locals() else 0.0, "", "", (), redact_sensitive_text(exc))
            self._record_probe(url, variant, result, False, [])
            return result

    def _record_probe(self, url: str, variant: str, result: ProbeResponse, truncated: bool, headers: list[tuple[str, str]]) -> None:
        redacted_url = self._redact_url(url)
        marker_text = ",".join(result.marker_categories) or "none"
        value = {
            "variant": variant[:80],
            "status_code": result.status_code,
            "elapsed_ms": result.elapsed_ms,
            "body_hash": result.body_hash,
            "sql_error_categories": list(result.marker_categories),
            "response_truncated": bool(truncated),
            "body_length": result.body_length,
            "noise_signals": list(result.noise_signals),
            "error": redact_sensitive_text(result.error) if result.error else None,
            "headers_observed": sorted({name.lower() for name, _ in headers})[:40],
            "payload_value_stored": False,
            "redacted": True,
        }
        page_id = None
        page = self.db.query(Page).filter(Page.scan_id == self.scan_id, Page.canonical_url == url.split("?", 1)[0]).first()
        if page:
            page_id = page.id
        probe_sequence = len(self.probe_observations)
        dedupe_key = hashlib.sha256(f"{self.scan_id}|{probe_sequence}|{redacted_url}|{variant}|{result.status_code}|{result.body_hash}|{result.elapsed_ms}".encode()).hexdigest()
        observation = HTTPObservation(
            scan_id=self.scan_id,
            page_id=page_id,
            observation_type="sqli_validation",
            subject=redacted_url,
            source="sqli_agent",
            classification="OBSERVED" if result.error is None else "INCONCLUSIVE",
            confidence=0.9 if result.marker_categories else 0.7,
            value=value,
            redacted=True,
            truncated=bool(truncated),
            dedupe_key=dedupe_key,
        )
        self.db.add(observation)
        self.db.flush()
        self.probe_observations.append(observation)
        if self.authorization:
            append_audit_event(
                self.db,
                scan_id=self.scan_id,
                authorization_id=self.authorization.id,
                event_type="SQLI_PROBE_EXECUTED",
                actor_id="system",
                payload={"endpoint": redacted_url, "variant": variant[:80], "status_code": result.status_code, "elapsed_ms": result.elapsed_ms, "sql_error_categories": list(result.marker_categories), "payload_value_stored": False},
            )

    def _record_coverage(self, surface: InputSurface, variant: str, reason: str, response: ProbeResponse | None = None) -> None:
        value = {"variant": variant, "reason": reason, "status_code": response.status_code if response else None, "redacted": True, "payload_value_stored": False}
        self.db.add(HTTPObservation(scan_id=self.scan_id, page_id=surface.page_id, observation_type="sqli_validation", subject=self._redact_url(surface.url), source="sqli_agent", classification="INCONCLUSIVE", confidence=0.5, value=value, redacted=True, truncated=False, dedupe_key=hashlib.sha256(f"{self.scan_id}|coverage|{surface.page_id}|{surface.name}|{variant}".encode()).hexdigest()))

    def _persist_finding(self, surface: InputSurface, rule_id: str, statement: str, classification: str, confidence: int, evidence: list[dict[str, Any]]) -> SecurityFinding:
        finding = SecurityFinding(scan_id=self.scan_id, page_id=surface.page_id, category="sqli", subject=f"{SQLI_RULES[rule_id]['title']}: {surface.name}", statement=statement, classification=classification, confidence=confidence, confidence_band="high" if confidence >= 90 else "medium", severity=SQLI_RULES[rule_id]["severity"], rule_id=rule_id, rule_version=RULE_VERSION, evidence=evidence, limitations=LIMITATIONS)
        self.db.add(finding)
        self.db.flush()
        return finding

    def _evidence(self, surface: InputSurface, stage: str, variant: str, baseline: ProbeResponse, first: ProbeResponse, counterpart: ProbeResponse, repetitions: list[ProbeResponse], details: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        entries = [
            {"id": f"sqli:{stage}:baseline:{surface.page_id}", "type": "baseline", "source": self._redact_url(surface.url), "observation": f"Baseline GET succeeded with status {baseline.status_code}, body fingerprint {baseline.body_hash}.", "status_code": baseline.status_code, "elapsed_ms": baseline.elapsed_ms},
            {"id": f"sqli:{stage}:first:{surface.page_id}", "type": "validation_response", "source": self._redact_url(surface.url), "observation": f"{stage} canary `{variant}` returned status {first.status_code}, SQL error categories {', '.join(first.marker_categories) or 'none'}, body fingerprint {first.body_hash}.", "status_code": first.status_code, "elapsed_ms": first.elapsed_ms},
            {"id": f"sqli:{stage}:counterpart:{surface.page_id}", "type": "safe_counterpart", "source": self._redact_url(surface.url), "observation": f"Safe counterpart returned status {counterpart.status_code}, body fingerprint {counterpart.body_hash}.", "status_code": counterpart.status_code, "elapsed_ms": counterpart.elapsed_ms},
            {"id": f"sqli:{stage}:reproducibility:{surface.page_id}", "type": "reproducibility", "source": self._redact_url(surface.url), "observation": f"Repeated validation count {len(repetitions)}; stable signature requirement passed.", "repeat_count": len(repetitions), "stable": True},
        ]
        if details:
            entries.append({"id": f"sqli:{stage}:gate:{surface.page_id}", "type": "validation_gate", "source": self._redact_url(surface.url), **details})
        return entries

    @staticmethod
    def _noise_signals(status_code: int, headers: list[tuple[str, str]]) -> tuple[str, ...]:
        names = {str(name).lower(): str(value).lower() for name, value in headers}
        signals: set[str] = set()
        if status_code == 429 or any(name.startswith("x-ratelimit") or name == "retry-after" for name in names):
            signals.add("rate_limited")
        cache_markers = ("x-cache", "cf-cache-status", "age", "x-cache-status", "akamai-cache-status")
        if any(name in names and ("hit" in names[name] or name == "age") for name in cache_markers):
            signals.add("cache_hit")
        return tuple(sorted(signals))

    @staticmethod
    def _markers(body: str) -> tuple[str, ...]:
        return tuple(sorted(name for name, pattern in SQL_ERROR_PATTERNS if pattern.search(body)))

    @staticmethod
    def _body_hash(body: str) -> str:
        normalized = re.sub(r"\s+", " ", body[:512 * 1024]).strip().lower()
        return hashlib.sha256(normalized.encode("utf-8", "ignore")).hexdigest()[:16]

    @staticmethod
    def _signature(response: ProbeResponse) -> tuple[int | None, str, tuple[str, ...]]:
        return response.status_code, response.body_hash, response.marker_categories

    @staticmethod
    def _replace_value(url: str, name: str, value: str) -> str:
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        output: list[tuple[str, str]] = []
        for key, current in pairs:
            if key == name and not replaced:
                output.append((key, value))
                replaced = True
            else:
                output.append((key, current))
        if not replaced:
            output.append((name, value))
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(output), ""))

    @staticmethod
    def _redact_url(url: str) -> str:
        parsed = urlsplit(url)
        query = [(key, "[REDACTED]") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))

    def _rule_dict(self, rule_id: str, rule: dict[str, Any]) -> dict[str, Any]:
        return {"rule_id": rule_id, **rule, "rule_version": RULE_VERSION, "validation_mode": "bounded_authorized_get"}

    @staticmethod
    def _finding_dict(finding: SecurityFinding) -> dict[str, Any]:
        return {"id": str(finding.id), "category": finding.category, "subject": finding.subject, "statement": finding.statement, "classification": finding.classification, "confidence": finding.confidence, "confidence_band": finding.confidence_band, "severity": finding.severity, "rule_id": finding.rule_id, "rule_version": finding.rule_version, "evidence": finding.evidence or [], "limitations": finding.limitations, "page_id": str(finding.page_id) if finding.page_id else None, "created_at": finding.created_at.isoformat()}


__all__ = ["LIMITATIONS", "RULE_VERSION", "SQLI_RULES", "SQLiDetectionAgent"]
