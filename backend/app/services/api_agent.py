from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.scan import (
    ApiEndpoint,
    HTTPObservation,
    HTTPResponse,
    Page,
    ReconEndpoint,
    ReconParameter,
    SecurityFinding,
)

RULE_VERSION = "phase5-api-v1"
LIMITATIONS = (
    "Detection is based on persisted, bounded inventory, schema, and HTTP evidence only. "
    "The API Agent does not probe, exploit, authenticate, submit forms, mutate data, or claim authorization impact."
)


@dataclass(frozen=True)
class APIRule:
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


API_AGENT_RULES: dict[str, APIRule] = {
    "API-INV-001": APIRule(
        "API-INV-001",
        "Undocumented API route candidate",
        "A captured OpenAPI/Swagger document contains paths and a separate in-scope route was discovered.",
        "Report only when a route is present in the bounded inventory but absent from the captured schema path set on the same host.",
        "Schema URL and normalized path evidence plus the discovered route source.",
        "low",
        92,
        "Keep the API contract synchronized with deployed routes and review undocumented routes before release.",
        ("CWE-1059",),
        ("OWASP-A04",),
    ),
    "API-METHOD-001": APIRule(
        "API-METHOD-001",
        "Dangerous API method exposed",
        "An API-like route or Allow header was captured with TRACE.",
        "Report only an observed TRACE method; PUT, PATCH, and DELETE remain inventory signals and are not treated as vulnerabilities by themselves.",
        "Normalized method inventory or redacted Allow header observation.",
        "high",
        99,
        "Disable TRACE at the edge and review whether every mutating method is required, authenticated, authorized, and protected by CSRF controls where applicable.",
        ("CWE-749",),
        ("OWASP-A05",),
    ),
    "API-PARAM-001": APIRule(
        "API-PARAM-001",
        "Sensitive parameter exposed in API URL",
        "A normalized API query parameter has a sensitive name and was observed in a URL-based location.",
        "Report the parameter name only; never persist or display its example value. This is an exposure indicator, not proof that a secret value was transmitted.",
        "Normalized parameter name, location, endpoint route, and source evidence.",
        "medium",
        90,
        "Avoid placing credentials, bearer tokens, session identifiers, or secrets in query strings; use protected headers or request bodies with appropriate transport and logging controls.",
        ("CWE-598",),
        ("OWASP-A04",),
    ),
    "API-AUTH-001": APIRule(
        "API-AUTH-001",
        "Sensitive API authentication boundary not observable",
        "A sensitive-looking API route returned a successful response but no authentication challenge or session signal was observed.",
        "Report as an information-level review item only. Passive evidence cannot establish whether upstream authentication or authorization exists outside the captured response.",
        "Sensitive route path, status, content type, and observed auth-signal inventory.",
        "info",
        82,
        "Verify authentication and object-level authorization at the API gateway and service layer with an authorized test account and an explicit test plan.",
        ("CWE-306", "CWE-862"),
        ("OWASP-A01", "OWASP-A07"),
    ),
    "API-AUTH-002": APIRule(
        "API-AUTH-002",
        "Basic authentication challenge over HTTP",
        "A captured API response advertises Basic authentication and its final URL uses HTTP.",
        "Report only when the observed challenge is Basic and transport is explicitly HTTP; do not classify HTTPS Basic authentication as insecure solely from this evidence.",
        "Redacted WWW-Authenticate scheme, final transport scheme, and response status.",
        "high",
        99,
        "Use HTTPS end to end and prefer modern token or session mechanisms with secure lifecycle controls; review Basic credentials and rotation policy.",
        ("CWE-319", "CWE-522"),
        ("OWASP-A02", "OWASP-A07"),
    ),
    "API-DATA-001": APIRule(
        "API-DATA-001",
        "Sensitive fields in captured API response",
        "A successful JSON-like API response contains high-signal sensitive field names in its bounded body.",
        "Report field names only when a JSON object includes password, secret, token, API-key, private-key, or similar keys. Values are never persisted by this rule.",
        "Response status/content type, normalized field names, and bounded response source.",
        "high",
        94,
        "Return only fields required by the client, apply response DTO allowlists, remove secrets from public responses, and review authorization and logging boundaries.",
        ("CWE-200", "CWE-359"),
        ("OWASP-A01", "OWASP-A02"),
    ),
    "API-RATE-001": APIRule(
        "API-RATE-001",
        "Rate-limit indicator assessment",
        "One or more API-like responses or headers were captured.",
        "Record Retry-After and X-RateLimit-* indicators in the report. Absence is not escalated as a vulnerability because no repeated probe was performed.",
        "Observed rate-limit header names, 429 statuses, and response routes.",
        "info",
        100,
        "Confirm rate limits, quotas, burst handling, and abuse responses with an authorized test plan appropriate to the API’s risk profile.",
        ("CWE-770",),
        ("OWASP-A04",),
    ),
    "API-ERROR-001": APIRule(
        "API-ERROR-001",
        "Unsafe API error detail",
        "A captured API-like response has an error status and a high-signal stack, debug, exception, SQL, or framework trace marker.",
        "Report only high-signal markers from the bounded response body and persist the marker category, never the full error body or secret values.",
        "Status, content type, normalized error marker, and response source.",
        "high",
        97,
        "Return generic production errors, keep diagnostic detail in protected server logs, and ensure correlation IDs do not expose internal data.",
        ("CWE-209",),
        ("OWASP-A05",),
    ),
    "API-POLICY-001": APIRule(
        "API-POLICY-001",
        "Wildcard CORS on API response",
        "A JSON-like API response explicitly contains Access-Control-Allow-Origin: *.",
        "Report the wildcard API policy as a low-severity review item; credentialed wildcard CORS remains covered by the Configuration Agent.",
        "Normalized CORS header observation, route, and content type.",
        "low",
        96,
        "Use an explicit origin allowlist and verify credential, method, header, and preflight policy against the API’s intended clients.",
        ("CWE-942",),
        ("OWASP-A05",),
    ),
    "API-SCHEMA-001": APIRule(
        "API-SCHEMA-001",
        "Public API schema document observed",
        "A bounded response contains a parseable OpenAPI or Swagger document.",
        "Report the schema as an information-level inventory item and expose its documented paths and security scheme metadata; public visibility alone does not prove a vulnerability.",
        "Schema document URL, version/format, path count, and security-scheme names without secrets.",
        "info",
        100,
        "Review whether the schema should be public, keep it synchronized with deployed behavior, and remove examples or descriptions that disclose sensitive operational details.",
        ("CWE-200",),
        ("OWASP-A05",),
    ),
}

SENSITIVE_PARAMETER_RE = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token|private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)
SENSITIVE_ROUTE_RE = re.compile(r"/(?:admin|account|user|profile|billing|manage|private|internal)(?:/|$)", re.IGNORECASE)
SENSITIVE_FIELD_RE = re.compile(
    r"[\"']([A-Za-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|ssn|social[_-]?security)[A-Za-z0-9_.-]*)[\"']\s*:",
    re.IGNORECASE,
)
ERROR_MARKER_RE = re.compile(
    r"(?:traceback|stack trace|exception|sqlstate|syntax error|debug\s*(?:true|mode)|django\s+debug|laravel|rails\s+error|spring\s+boot\s+error)",
    re.IGNORECASE,
)
API_PATH_RE = re.compile(r"/(?:api|v[0-9]+|graphql|rpc|rest|json|openapi|swagger)(?:/|$)|\.(?:json|graphql|xml)$", re.IGNORECASE)
SCHEMA_PATH_RE = re.compile(r"(?:openapi|swagger)(?:\.(?:json|ya?ml))?$", re.IGNORECASE)
RATE_LIMIT_HEADERS = {"retry-after", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset"}
AUTH_HEADERS = {"authorization", "www-authenticate", "proxy-authenticate"}


class APIAgent:
    """Analyze persisted API inventory and HTTP evidence without issuing target requests."""

    def __init__(self, db: Session, scan_id: UUID) -> None:
        self.db = db
        self.scan_id = scan_id

    def analyze(self) -> list[SecurityFinding]:
        report = self._build_report()
        self.db.query(SecurityFinding).filter(
            SecurityFinding.scan_id == self.scan_id,
            SecurityFinding.category == "api",
        ).delete(synchronize_session=False)
        self.db.flush()
        persisted: list[SecurityFinding] = []
        for candidate in report["candidates"]:
            self._validate_candidate(candidate)
            finding = SecurityFinding(
                scan_id=self.scan_id,
                page_id=candidate.get("page_id"),
                category="api",
                subject=candidate["subject"],
                statement=candidate["statement"],
                classification=candidate["classification"],
                confidence=candidate["confidence"],
                confidence_band=self._confidence_band(candidate["confidence"]),
                severity=candidate["severity"],
                rule_id=candidate["rule_id"],
                rule_version=RULE_VERSION,
                evidence=candidate["evidence"],
                limitations=LIMITATIONS,
            )
            self.db.add(finding)
            self.db.flush()
            persisted.append(finding)
        self.db.commit()
        return persisted

    def report(self) -> dict[str, Any]:
        report = self._build_report()
        findings = (
            self.db.query(SecurityFinding)
            .filter(SecurityFinding.scan_id == self.scan_id, SecurityFinding.category == "api")
            .order_by(SecurityFinding.severity.desc(), SecurityFinding.subject)
            .all()
        )
        return {
            "scan_id": str(self.scan_id),
            "rule_version": RULE_VERSION,
            "rules": [rule.as_dict() for rule in API_AGENT_RULES.values()],
            "inventory": report["inventory"],
            "schemas": report["schemas"],
            "indicators": report["indicators"],
            "findings": [self._finding_dict(item) for item in findings],
            "summary": report["summary"] | {"finding_count": len(findings)},
        }

    def _build_report(self) -> dict[str, Any]:
        routes: dict[str, dict[str, Any]] = {}
        endpoint_keys: dict[str, str] = {}
        source_counts = {"api_intelligence": 0, "recon": 0, "observed_http": 0}
        pages = {page.id: page for page in self.db.query(Page).filter(Page.scan_id == self.scan_id).all()}

        for endpoint in self.db.query(ApiEndpoint).filter(ApiEndpoint.scan_id == self.scan_id).all():
            key = self._route_key(endpoint.url_or_path)
            self._add_route(routes, key, endpoint.url_or_path, endpoint.http_method, endpoint.content_type, endpoint.confidence, "api_intelligence", None, None, None)
            source_counts["api_intelligence"] += 1
            endpoint_keys[str(endpoint.id)] = key

        recon_endpoints = self.db.query(ReconEndpoint).filter(ReconEndpoint.scan_id == self.scan_id).all()
        for endpoint in recon_endpoints:
            if not self._is_api_route(endpoint.url_or_path) and endpoint.endpoint_kind.lower() not in {"api", "schema", "graphql", "rpc"}:
                continue
            key = self._route_key(endpoint.url_or_path)
            self._add_route(routes, key, endpoint.url_or_path, endpoint.http_method, endpoint.content_type, endpoint.confidence, "recon", endpoint.status_code, endpoint.scope_status, endpoint.page_id)
            source_counts["recon"] += 1
            endpoint_keys[str(endpoint.id)] = key

        responses = (
            self.db.query(HTTPResponse)
            .join(Page, HTTPResponse.page_id == Page.id)
            .filter(Page.scan_id == self.scan_id)
            .all()
        )
        response_records: list[dict[str, Any]] = []
        for response in responses:
            page = pages.get(response.page_id)
            url = response.final_url or (page.canonical_url if page else "")
            body = response.raw_body or ""
            content_type = (response.content_type or "").lower()
            schema = self._parse_schema(url, body)
            is_api = self._is_api_route(url) or "json" in content_type or schema is not None
            if not is_api:
                continue
            key = self._route_key(url)
            headers = self._headers(response)
            self._add_route(routes, key, url, "UNKNOWN", response.content_type, 1.0, "observed_http", response.status_code, "in_scope", response.page_id)
            for allow_value in headers.get("allow", []):
                routes[key]["methods"].update(item.strip().upper() for item in allow_value.split(",") if item.strip())
            routes[key].setdefault("responses", []).append({"response": response, "page": page, "headers": headers, "body": body, "schema": schema})
            source_counts["observed_http"] += 1
            response_records.append({"route_key": key, "response": response, "page": page, "headers": headers, "body": body, "schema": schema})

        for parameter in self.db.query(ReconParameter).filter(ReconParameter.scan_id == self.scan_id).all():
            key = endpoint_keys.get(str(parameter.endpoint_id)) if parameter.endpoint_id else None
            if key is None and parameter.endpoint_id:
                endpoint = next((item for item in recon_endpoints if item.id == parameter.endpoint_id), None)
                key = self._route_key(endpoint.url_or_path) if endpoint else None
            if key in routes:
                routes[key].setdefault("parameters", []).append({"name": parameter.name, "location": parameter.location, "source": parameter.source, "page_id": parameter.page_id})

        schemas = self._schemas(response_records)
        documented_paths = {(schema["host"], schema_path) for schema in schemas for schema_path in schema["paths"]}
        for route in routes.values():
            route["documented"] = (route["host"], route["path"]) in documented_paths
        candidates: list[dict[str, Any]] = []
        for schema in schemas:
            candidates.append(self._candidate(
                "API-SCHEMA-001",
                f"Public API schema observed: {schema['url']}",
                f"A bounded response exposed a parseable {schema['format']} document with {len(schema['paths'])} path(s).",
                "OBSERVED",
                100,
                "info",
                self._evidence("schema", schema["url"], f"Schema version: {schema.get('version') or 'unknown'}; documented paths: {len(schema['paths'])}; security schemes: {', '.join(schema['security_schemes']) or 'none observed'}."),
            ))
        for route in routes.values():
            candidates.extend(self._route_candidates(route, documented_paths, schemas))

        rate_routes = []
        auth_routes = []
        error_routes = []
        policy_routes = []
        for record in response_records:
            headers = record["headers"]
            response = record["response"]
            route = routes[record["route_key"]]
            rate_headers = sorted(name for name in headers if name in RATE_LIMIT_HEADERS)
            if rate_headers or response.status_code == 429:
                rate_routes.append({"route": route["display"], "status_code": response.status_code, "headers": rate_headers, "retry_after_observed": "retry-after" in headers})
            auth_headers = sorted(name for name in headers if name in AUTH_HEADERS)
            if auth_headers:
                auth_routes.append({"route": route["display"], "status_code": response.status_code, "headers": auth_headers})
            if response.status_code >= 400:
                markers = sorted(set(item.lower() for item in ERROR_MARKER_RE.findall(record["body"][:300_000])))
                if markers:
                    error_routes.append({"route": route["display"], "status_code": response.status_code, "markers": markers})
            cors_values = headers.get("access-control-allow-origin", [])
            if any(value.strip() == "*" for value in cors_values) and "json" in (response.content_type or "").lower():
                policy_routes.append({"route": route["display"], "status_code": response.status_code, "policy": "wildcard_allow_origin"})

        if rate_routes:
            candidates.append(self._candidate(
                "API-RATE-001", "API rate-limit indicators observed",
                "At least one API-like response exposed a rate-limit header or returned 429.", "INFERRED", 100, "info",
                self._evidence("rate_limit", "rate_limit", "Observed rate-limit indicators on " + str(len(rate_routes)) + " route response(s)."),
            ))
        for route in routes.values():
            if route.get("parameters"):
                for parameter in route["parameters"]:
                    if parameter["location"].lower() in {"query", "url", "path"} and SENSITIVE_PARAMETER_RE.search(parameter["name"]):
                        candidates.append(self._candidate(
                            "API-PARAM-001", f"Sensitive parameter name '{parameter['name']}' observed in API URL",
                            f"Parameter '{parameter['name']}' was normalized at the {parameter['location']} location for {route['display']}; its example value was not retained.",
                            "OBSERVED", 90, "medium", self._evidence("parameter", parameter["source"], f"Sensitive parameter name: {parameter['name']}; location: {parameter['location']}.", parameter.get("page_id")), route.get("page_id"),
                        ))

        summary = {
            "inventory_count": len(routes),
            "schema_count": len(schemas),
            "documented_route_count": sum(1 for route in routes.values() if route.get("documented")),
            "undocumented_route_count": sum(1 for candidate in candidates if candidate["rule_id"] == "API-INV-001"),
            "source_counts": source_counts,
            "method_counts": self._method_counts(routes),
            "rate_limit_route_count": len(rate_routes),
            "auth_signal_route_count": len(auth_routes),
            "error_route_count": len(error_routes),
            "policy_route_count": len(policy_routes),
            "high_count": sum(1 for item in candidates if item["severity"] == "high"),
            "medium_count": sum(1 for item in candidates if item["severity"] == "medium"),
            "low_count": sum(1 for item in candidates if item["severity"] == "low"),
            "info_count": sum(1 for item in candidates if item["severity"] == "info"),
        }
        indicators = {
            "rate_limit": {"observed": bool(rate_routes), "routes": rate_routes, "absence_not_escalated": True},
            "authentication": {"routes": auth_routes, "absence_not_escalated": True},
            "errors": error_routes,
            "policy": policy_routes,
            "methods": self._method_observations(routes),
        }
        inventory = [self._route_dict(route) for route in sorted(routes.values(), key=lambda item: item["display"])]
        return {"inventory": inventory, "schemas": schemas, "indicators": indicators, "candidates": candidates, "summary": summary}

    def _route_candidates(self, route: dict[str, Any], documented_paths: set[tuple[str, str]], schemas: list[dict[str, Any]]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        host_path = (route["host"], route["path"])
        if schemas and route.get("source_types") and not route.get("is_schema") and host_path not in documented_paths:
            evidence = [self._evidence("schema", schema["url"], f"Captured {schema['format']} schema documents {len(schema['paths'])} path(s); route {route['display']} was not listed.") for schema in schemas if schema["host"] == route["host"]]
            if evidence:
                candidates.append(self._candidate("API-INV-001", f"Undocumented API route candidate: {route['display']}", f"The in-scope route {route['display']} was discovered from {', '.join(sorted(route['source_types']))} but was not present in the captured API schema path set.", "INFERRED", 92, "low", evidence + [self._evidence("route", route["display"], f"Route sources: {', '.join(sorted(route['sources']))}.", route.get("page_id"))], route.get("page_id")))
        if "TRACE" in route["methods"]:
            candidates.append(self._candidate("API-METHOD-001", f"TRACE method exposed by API route {route['display']}", f"TRACE was observed in the method inventory for {route['display']}.", "OBSERVED", 99, "high", [self._evidence("method", route["display"], "Observed method: TRACE.", route.get("page_id"))], route.get("page_id")))
        responses = route.get("responses", [])
        for record in responses:
            response = record["response"]
            headers = record["headers"]
            body = record["body"][:300_000]
            if response.status_code >= 200 and response.status_code < 300 and SENSITIVE_ROUTE_RE.search(route["path"]):
                auth_signals = sorted(name for name in headers if name in AUTH_HEADERS or name == "set-cookie")
                if not auth_signals:
                    candidates.append(self._candidate("API-AUTH-001", f"Authentication boundary not observable for {route['display']}", f"A sensitive-looking API route returned status {response.status_code} without a captured authentication challenge or session signal.", "INFERRED", 82, "info", [self._evidence("auth_boundary", route["display"], f"Status {response.status_code}; observed auth signals: none.", record.get("page").id if record.get("page") else None)], route.get("page_id")))
            challenge = "; ".join(headers.get("www-authenticate", []))
            if "basic" in challenge.lower() and urlsplit(response.final_url).scheme.lower() == "http":
                candidates.append(self._candidate("API-AUTH-002", f"Basic authentication challenge over HTTP at {route['display']}", "The stored response advertised Basic authentication while its final URL used HTTP.", "OBSERVED", 99, "high", [self._evidence("auth_challenge", route["display"], "WWW-Authenticate scheme: Basic; transport scheme: http.", record.get("page").id if record.get("page") else None)], route.get("page_id")))
            if response.status_code >= 200 and response.status_code < 300 and ("json" in (response.content_type or "").lower() or self._is_api_route(response.final_url)):
                fields = sorted(set(match.group(1) for match in SENSITIVE_FIELD_RE.finditer(body)))
                if fields:
                    candidates.append(self._candidate("API-DATA-001", f"Sensitive fields in captured API response {route['display']}", f"The bounded response contained sensitive field names: {', '.join(fields)}. Values were not retained by the API Agent.", "OBSERVED", 94, "high", [self._evidence("data_exposure", route["display"], f"Sensitive field names observed: {', '.join(fields)}; response body values omitted.", record.get("page").id if record.get("page") else None)], route.get("page_id")))
                if any(value.strip() == "*" for value in headers.get("access-control-allow-origin", [])):
                    candidates.append(self._candidate("API-POLICY-001", f"Wildcard CORS policy on API response {route['display']}", "Access-Control-Allow-Origin was observed as wildcard on a JSON-like API response.", "OBSERVED", 96, "low", [self._evidence("cors_policy", route["display"], "Access-Control-Allow-Origin: wildcard; origin variation was not tested.", record.get("page").id if record.get("page") else None)], route.get("page_id")))
            if response.status_code >= 400 and ERROR_MARKER_RE.search(body):
                markers = sorted(set(match.group(0).lower() for match in ERROR_MARKER_RE.finditer(body)))[:5]
                candidates.append(self._candidate("API-ERROR-001", f"Unsafe API error detail at {route['display']}", f"The stored error response exposed high-signal diagnostic markers: {', '.join(markers)}.", "OBSERVED", 97, "high", [self._evidence("error_detail", route["display"], f"Status {response.status_code}; diagnostic marker categories: {', '.join(markers)}; body excerpt omitted.", record.get("page").id if record.get("page") else None)], route.get("page_id")))
        return candidates

    def _schemas(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        schemas: list[dict[str, Any]] = []
        seen: set[str] = set()
        for record in records:
            parsed = record.get("schema")
            if not parsed:
                continue
            url = record["response"].final_url
            if url in seen:
                continue
            seen.add(url)
            schemas.append({"url": self._route_display(url), "host": (urlsplit(url).hostname or "").lower(), "format": parsed["format"], "version": parsed.get("version"), "paths": sorted(parsed.get("paths", [])), "security_schemes": sorted(parsed.get("security_schemes", [])), "publicly_observable": True})
        return schemas

    @staticmethod
    def _parse_schema(url: str, body: str) -> dict[str, Any] | None:
        if not body or not (SCHEMA_PATH_RE.search(url) or ("openapi" in body.lower() and "paths" in body.lower()) or ("swagger" in body.lower() and "paths" in body.lower())):
            return None
        try:
            data = json.loads(body)
        except (TypeError, ValueError):
            data = None
        if isinstance(data, dict) and isinstance(data.get("paths"), dict):
            paths = [str(path) for path in data["paths"] if isinstance(path, str)]
            schemes = []
            for name, value in (data.get("components", {}).get("securitySchemes", {}) if isinstance(data.get("components"), dict) else {}).items():
                schemes.append(str(name))
            for name in (data.get("securityDefinitions", {}) if isinstance(data.get("securityDefinitions"), dict) else {}):
                schemes.append(str(name))
            return {"format": "openapi-json" if data.get("openapi") else "swagger-json", "version": data.get("openapi") or data.get("swagger"), "paths": paths, "security_schemes": schemes}
        path_matches = re.findall(r"(?m)^\s{2,}(/[^:#\s]+)\s*:", body[:300_000])
        if path_matches:
            version_match = re.search(r"(?im)^\s*(?:openapi|swagger)\s*:\s*([^\s#]+)", body)
            return {"format": "openapi-yaml", "version": version_match.group(1) if version_match else None, "paths": sorted(set(path_matches)), "security_schemes": []}
        return None

    @staticmethod
    def _headers(response: HTTPResponse) -> dict[str, list[str]]:
        values: dict[str, list[str]] = {}
        for header in response.headers:
            values.setdefault(header.name.lower(), []).append(header.value)
        return values

    @staticmethod
    def _is_api_route(url: str) -> bool:
        path = urlsplit(url).path or url
        return bool(API_PATH_RE.search(path))

    @staticmethod
    def _route_key(url: str) -> str:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        return f"{host}{path}".lower()

    @staticmethod
    def _route_display(url: str) -> str:
        parsed = urlsplit(url)
        if not parsed.scheme and not parsed.netloc:
            return parsed.path or url.split("?", 1)[0]
        return urlunsplit((parsed.scheme.lower(), (parsed.netloc or "").lower(), parsed.path or "/", "", ""))

    @staticmethod
    def _add_route(routes: dict[str, dict[str, Any]], key: str, url: str, method: str, content_type: str | None, confidence: float, source: str, status_code: int | None, scope_status: str | None, page_id: UUID | None) -> None:
        route = routes.setdefault(key, {"key": key, "display": APIAgent._route_display(url), "path": urlsplit(url).path or url, "host": (urlsplit(url).hostname or "").lower(), "methods": set(), "content_types": set(), "sources": set(), "source_types": set(), "status_codes": set(), "scope_statuses": set(), "page_ids": set(), "confidence": 0.0, "parameters": [], "responses": []})
        if method and method != "UNKNOWN":
            route["methods"].add(method.upper())
        if content_type:
            route["content_types"].add(content_type)
        route["sources"].add(source)
        route["source_types"].add(source)
        if status_code is not None:
            route["status_codes"].add(status_code)
        if scope_status:
            route["scope_statuses"].add(scope_status)
        if page_id:
            route["page_ids"].add(str(page_id))
        route["confidence"] = max(route["confidence"], float(confidence or 0) * (100 if float(confidence or 0) <= 1 else 1))
        route["is_schema"] = route.get("is_schema", False) or bool(SCHEMA_PATH_RE.search(route["path"]))

    @staticmethod
    def _route_dict(route: dict[str, Any]) -> dict[str, Any]:
        return {"route": route["display"], "path": route["path"], "host": route["host"], "methods": sorted(route["methods"]), "content_types": sorted(route["content_types"]), "sources": sorted(route["sources"]), "status_codes": sorted(route["status_codes"]), "scope_statuses": sorted(route["scope_statuses"]), "confidence": round(route["confidence"], 2), "parameter_names": sorted({item["name"] for item in route.get("parameters", [])}), "documented": bool(route.get("documented")), "observed": bool(route.get("responses")), "is_schema": bool(route.get("is_schema"))}

    @staticmethod
    def _method_counts(routes: dict[str, dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for route in routes.values():
            for method in route["methods"]:
                counts[method] = counts.get(method, 0) + 1
        return dict(sorted(counts.items()))

    @staticmethod
    def _method_observations(routes: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        return [{"route": route["display"], "methods": sorted(route["methods"])} for route in routes.values() if route["methods"]]

    @staticmethod
    def _evidence(kind: str, source: str, observation: str, page_id: UUID | str | None = None) -> dict[str, Any]:
        return {"id": f"api-agent:{kind}:{source}:{page_id or 'scan'}"[:200], "type": kind, "source": str(source), "observation": observation}

    @staticmethod
    def _candidate(rule_id: str, subject: str, statement: str, classification: str, confidence: int, severity: str, evidence: dict[str, Any] | list[dict[str, Any]], page_id: UUID | str | None = None) -> dict[str, Any]:
        return {"rule_id": rule_id, "subject": subject[:2048], "statement": statement, "classification": classification, "confidence": confidence, "severity": severity, "evidence": evidence if isinstance(evidence, list) else [evidence], "page_id": page_id}

    @staticmethod
    def _validate_candidate(candidate: dict[str, Any]) -> None:
        if candidate["classification"] not in {"OBSERVED", "INFERRED"}:
            raise ValueError("API finding classification must be OBSERVED or INFERRED")
        if not candidate["statement"].strip() or not candidate["evidence"]:
            raise ValueError("API finding requires statement and evidence")
        if not 0 <= candidate["confidence"] <= 100:
            raise ValueError("API finding confidence must be between 0 and 100")
        for item in candidate["evidence"]:
            if not item.get("id") or not item.get("type") or not item.get("source") or not item.get("observation"):
                raise ValueError("API finding evidence requires id, type, source, and observation")

    @staticmethod
    def _confidence_band(confidence: float) -> str:
        if confidence >= 90:
            return "high"
        if confidence >= 70:
            return "medium"
        return "low"

    @staticmethod
    def _finding_dict(finding: SecurityFinding) -> dict[str, Any]:
        return {"id": str(finding.id), "category": finding.category, "subject": finding.subject, "statement": finding.statement, "classification": finding.classification, "confidence": finding.confidence, "confidence_band": finding.confidence_band, "severity": finding.severity, "rule_id": finding.rule_id, "rule_version": finding.rule_version, "evidence": finding.evidence or [], "limitations": finding.limitations, "page_id": str(finding.page_id) if finding.page_id else None, "created_at": finding.created_at.isoformat()}


__all__ = ["APIAgent", "API_AGENT_RULES", "APIRule", "LIMITATIONS", "RULE_VERSION"]
