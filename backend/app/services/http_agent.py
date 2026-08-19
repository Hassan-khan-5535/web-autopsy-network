from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.scan import HTTPObservation, HTTPResponse, Header, Page, Scan


class HTTPAgent:
    """Analyze persisted HTTP behavior without issuing additional target requests."""

    RULE_VERSION = "phase3-http-v1"
    MAX_VALUE_BYTES = 8 * 1024
    MAX_TEXT_BYTES = 512
    SECRET_NAME_RE = re.compile(
        r"(?:authorization|proxy-authorization|cookie|set-cookie|token|secret|password|passwd|api[-_]?key|csrf|session)",
        re.IGNORECASE,
    )
    SECURITY_POLICY_HEADERS = (
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "x-xss-protection",
    )
    CACHE_HEADERS = (
        "cache-control",
        "etag",
        "last-modified",
        "expires",
        "age",
        "vary",
        "x-cache",
        "cf-cache-status",
        "cdn-cache-control",
    )
    CORS_HEADERS = (
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-expose-headers",
        "access-control-max-age",
        "access-control-request-method",
        "access-control-request-headers",
    )

    def __init__(self, db: Session, scan_id: UUID) -> None:
        self.db = db
        self.scan_id = scan_id
        self.scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not self.scan:
            raise ValueError(f"Scan {scan_id} not found")

    def analyze(self) -> list[HTTPObservation]:
        self.db.query(HTTPObservation).filter(HTTPObservation.scan_id == self.scan_id).delete(
            synchronize_session=False
        )
        self.db.flush()
        observations: list[HTTPObservation] = []
        pages = self.db.query(Page).filter(Page.scan_id == self.scan_id).order_by(Page.canonical_url).all()
        for page in pages:
            response = (
                self.db.query(HTTPResponse)
                .filter(HTTPResponse.page_id == page.id)
                .order_by(HTTPResponse.created_at.desc())
                .first()
            )
            if response is None:
                observations.append(
                    self._emit(
                        page,
                        None,
                        "response_anomaly",
                        "HTTP response unavailable",
                        {"anomaly": "no_persisted_response", "status_code": None},
                    )
                )
                continue
            headers = self._header_map(response)
            observations.extend(
                [
                    self._emit(page, response, "status_code", page.canonical_url, self._status_value(page, response)),
                    self._emit(page, response, "content_type", page.canonical_url, self._content_type_value(response, headers)),
                    self._emit(page, response, "tls", page.canonical_url, self._tls_value(response)),
                    self._emit(page, response, "compression", page.canonical_url, self._compression_value(response, headers)),
                    self._emit(page, response, "cache", page.canonical_url, self._cache_value(headers)),
                    self._emit(page, response, "cors", page.canonical_url, self._cors_value(headers)),
                ]
            )
            observations.extend(self._header_observations(page, response, headers))
            observations.extend(self._cookie_observations(page, response, headers))
            observations.extend(self._security_policy_observations(page, response, headers))
            observations.extend(self._redirect_observations(page, response))
            observations.extend(self._anomaly_observations(page, response, headers))
        self.db.commit()
        return observations

    @staticmethod
    def _header_map(response: HTTPResponse) -> dict[str, list[str]]:
        values: dict[str, list[str]] = defaultdict(list)
        for header in response.headers:
            values[header.name.lower()].append(header.value)
        return dict(values)

    def _header_observations(self, page: Page, response: HTTPResponse, headers: dict[str, list[str]]) -> list[HTTPObservation]:
        observations: list[HTTPObservation] = []
        for name, values in headers.items():
            if name == "set-cookie":
                continue
            redacted_values = [self._safe_header_value(name, value)[0] for value in values]
            redacted = bool(self.SECRET_NAME_RE.search(name))
            observations.append(
                self._emit(
                    page,
                    response,
                    "header",
                    f"{page.canonical_url}#{name}",
                    {"name": name, "values": redacted_values, "occurrences": len(values)},
                    redacted=redacted,
                )
            )
        return observations

    def _cookie_observations(self, page: Page, response: HTTPResponse, headers: dict[str, list[str]]) -> list[HTTPObservation]:
        observations: list[HTTPObservation] = []
        for raw_cookie in headers.get("set-cookie", []):
            cookie = self._parse_cookie(raw_cookie)
            observations.append(
                self._emit(
                    page,
                    response,
                    "cookie",
                    f"{page.canonical_url}#set-cookie:{cookie['name']}",
                    cookie,
                    redacted=True,
                )
            )
        return observations

    def _security_policy_observations(self, page: Page, response: HTTPResponse, headers: dict[str, list[str]]) -> list[HTTPObservation]:
        observations: list[HTTPObservation] = []
        for name in self.SECURITY_POLICY_HEADERS:
            values = headers.get(name, [])
            safe_values = [self._safe_header_value(name, value)[0] for value in values]
            observations.append(
                self._emit(
                    page,
                    response,
                    "security_policy",
                    f"{page.canonical_url}#{name}",
                    {"name": name, "present": bool(values), "values": safe_values},
                    redacted=False,
                )
            )
        return observations

    def _redirect_observations(self, page: Page, response: HTTPResponse) -> list[HTTPObservation]:
        chain = response.redirect_chain or []
        if not chain:
            return [
                self._emit(
                    page,
                    response,
                    "redirect",
                    page.canonical_url,
                    {"redirected": False, "hop_count": 0, "chain": [], "final_url": self._redact_url(response.final_url)},
                )
            ]
        safe_chain = []
        for item in chain:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                source, target = item
                safe_chain.append({"from": self._redact_url(str(source)), "to": self._redact_url(str(target))})
        return [
            self._emit(
                page,
                response,
                "redirect",
                page.canonical_url,
                {
                    "redirected": True,
                    "hop_count": len(safe_chain),
                    "chain": safe_chain,
                    "final_url": self._redact_url(response.final_url),
                    "same_host_as_requested": self._same_host(page.canonical_url, response.final_url),
                },
            )
        ]

    def _anomaly_observations(self, page: Page, response: HTTPResponse, headers: dict[str, list[str]]) -> list[HTTPObservation]:
        anomalies: list[tuple[str, dict[str, Any]]] = []
        if response.status_code >= 400:
            anomalies.append(("error_response", {"status_code": response.status_code, "status_band": self._status_band(response.status_code)}))
        if 200 <= response.status_code < 400 and not response.content_type:
            anomalies.append(("missing_content_type", {"status_code": response.status_code}))
        if response.body_truncated:
            anomalies.append(("response_body_truncated", {"body_capture_limit_bytes": 5 * 1024 * 1024, "captured_body_bytes": self._body_size(response)}))
        if not self._same_host(page.canonical_url, response.final_url):
            anomalies.append(("final_url_host_changed", {"requested_host": urlsplit(page.canonical_url).hostname, "final_host": urlsplit(response.final_url).hostname}))
        declared_length = self._first_int(headers.get("content-length", []))
        if declared_length is not None and declared_length < 0:
            anomalies.append(("invalid_content_length", {"content_length": declared_length}))
        return [
            self._emit(
                page,
                response,
                "response_anomaly",
                f"{page.canonical_url}#{kind}",
                {"anomaly": kind, **value},
            )
            for kind, value in anomalies
        ]

    def _status_value(self, page: Page, response: HTTPResponse) -> dict[str, Any]:
        return {
            "status_code": response.status_code,
            "status_band": self._status_band(response.status_code),
            "requested_url": self._redact_url(page.canonical_url),
            "final_url": self._redact_url(response.final_url),
            "elapsed_ms": response.timings_ms,
            "body_available": bool(response.raw_body),
            "body_bytes_captured": self._body_size(response),
        }

    def _content_type_value(self, response: HTTPResponse, headers: dict[str, list[str]]) -> dict[str, Any]:
        raw = (headers.get("content-type") or [response.content_type or ""])[0]
        media_type, _, charset = raw.partition(";")
        return {
            "raw": self._truncate(media_type.strip(), self.MAX_TEXT_BYTES),
            "media_type": media_type.strip().lower() or None,
            "charset": charset.split("=", 1)[1].strip() if "=" in charset else None,
            "body_bytes_captured": self._body_size(response),
            "body_truncated": bool(response.body_truncated),
        }

    def _tls_value(self, response: HTTPResponse) -> dict[str, Any]:
        parsed = urlsplit(response.final_url)
        return {
            "scheme": parsed.scheme.lower(),
            "https_observed": parsed.scheme.lower() == "https",
            "certificate_details_captured": False,
            "cipher_details_captured": False,
            "limitation": "Static HTTP collection records transport scheme only; no second TLS handshake was performed.",
        }

    def _compression_value(self, response: HTTPResponse, headers: dict[str, list[str]]) -> dict[str, Any]:
        content_length = self._first_int(headers.get("content-length", []))
        return {
            "content_encoding": self._safe_value(headers.get("content-encoding", [])),
            "transfer_encoding": self._safe_value(headers.get("transfer-encoding", [])),
            "content_length": content_length,
            "body_bytes_captured": self._body_size(response),
            "body_truncated": bool(response.body_truncated),
        }

    def _cache_value(self, headers: dict[str, list[str]]) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for name in self.CACHE_HEADERS:
            if name in headers:
                values[name] = [self._safe_header_value(name, item)[0] for item in headers[name]]
        directives = self._cache_directives((headers.get("cache-control") or [""])[0])
        return {"headers": values, "cache_control_directives": directives, "validators_observed": bool(headers.get("etag") or headers.get("last-modified"))}

    def _cors_value(self, headers: dict[str, list[str]]) -> dict[str, Any]:
        values = {name: [self._safe_header_value(name, item)[0] for item in headers.get(name, [])] for name in self.CORS_HEADERS if name in headers}
        return {
            "headers": values,
            "cors_headers_observed": bool(values),
            "origin_matrix_tested": False,
            "limitation": "CORS observation is based on stored response headers; no origin-variation request was issued.",
        }

    def _emit(self, page: Page, response: HTTPResponse | None, observation_type: str, subject: str, value: dict[str, Any], *, redacted: bool = False) -> HTTPObservation:
        safe_subject = self._redact_url(subject) if "://" in subject else self._truncate(subject, 2048)
        safe_value, truncated = self._bounded_json(value)
        dedupe_key = hashlib.sha256(
            "|".join([str(self.scan_id), str(page.id), observation_type, safe_subject, json.dumps(safe_value, sort_keys=True)])
            .encode("utf-8")
        ).hexdigest()
        observation = HTTPObservation(
            scan_id=self.scan_id,
            page_id=page.id,
            http_response_id=response.id if response else None,
            observation_type=observation_type,
            subject=safe_subject,
            source=f"HTTPResponse:{response.id}" if response else f"Page:{page.id}",
            classification="OBSERVED",
            confidence=1.0,
            value=safe_value,
            redacted=redacted,
            truncated=truncated,
            dedupe_key=dedupe_key,
        )
        self.db.add(observation)
        return observation

    @classmethod
    def _parse_cookie(cls, raw_cookie: str) -> dict[str, Any]:
        parts = [part.strip() for part in raw_cookie.split(";")]
        name = parts[0].split("=", 1)[0].strip() if parts else "unknown"
        attrs: dict[str, Any] = {}
        for part in parts[1:]:
            key, separator, value = part.partition("=")
            attrs[key.strip().lower()] = value.strip() if separator else True
        return {
            "name": cls._truncate(name, 255),
            "secure": "secure" in attrs,
            "httponly": "httponly" in attrs,
            "samesite": attrs.get("samesite", "absent"),
            "domain": cls._truncate(str(attrs.get("domain", "host-only")), 255),
            "path": cls._truncate(str(attrs.get("path", "/")), 255),
            "value_redacted": True,
        }

    @classmethod
    def _safe_header_value(cls, name: str, value: str) -> tuple[Any, bool]:
        if cls.SECRET_NAME_RE.search(name):
            return {"present": bool(value), "length": len(value), "value_redacted": True}, True
        if name.lower() in {"location", "content-location", "link"}:
            return cls._redact_url(value), False
        return cls._truncate(value, cls.MAX_TEXT_BYTES), False

    @classmethod
    def _safe_value(cls, values: list[str]) -> Any:
        return [cls._truncate(item, cls.MAX_TEXT_BYTES) for item in values]

    @classmethod
    def _cache_directives(cls, raw: str) -> dict[str, Any]:
        directives: dict[str, Any] = {}
        for part in raw.split(","):
            key, separator, value = part.strip().partition("=")
            if not key:
                continue
            directives[key.lower()] = cls._truncate(value.strip(' "'), 128) if separator else True
        return directives

    @staticmethod
    def _status_band(status: int | None) -> str:
        if status is None:
            return "unknown"
        if 200 <= status < 300:
            return "2xx_success"
        if 300 <= status < 400:
            return "3xx_redirect"
        if 400 <= status < 500:
            return "4xx_client_error"
        if 500 <= status < 600:
            return "5xx_server_error"
        return "non_standard"

    @staticmethod
    def _first_int(values: list[str]) -> int | None:
        try:
            return int(values[0]) if values else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _body_size(response: HTTPResponse) -> int:
        return len((response.raw_body or "").encode("utf-8", errors="ignore"))

    @classmethod
    def _bounded_json(cls, value: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) <= cls.MAX_VALUE_BYTES:
            return value, False
        return {"truncated": True, "keys": sorted(value.keys())[:50]}, True

    @staticmethod
    def _truncate(value: str, limit: int) -> str:
        value = str(value)
        return value if len(value) <= limit else value[: max(limit - 1, 0)] + "…"

    @classmethod
    def _redact_url(cls, url: str) -> str:
        try:
            parsed = urlsplit(str(url))
            query = [(key, "[REDACTED]") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
            return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))
        except Exception:
            return cls._truncate(str(url), 2048)

    @staticmethod
    def _same_host(left: str, right: str) -> bool:
        return (urlsplit(left).hostname or "").lower().rstrip(".") == (urlsplit(right).hostname or "").lower().rstrip(".")


__all__ = ["HTTPAgent"]
