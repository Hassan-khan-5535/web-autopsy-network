"""Shared fail-closed transport and data-boundary controls for Extension 17."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

from app.core.config import get_settings
from app.services.admission import AdmissionError, AdmissionService


class ScannerSecurityError(AdmissionError):
    """A scanner isolation or resource boundary was violated."""


def revalidate_egress(
    url: str,
    *,
    assessment_profile: str | None,
    explicit_allowlist: bool,
    allowed_ports: set[int] | None = None,
) -> str:
    """Resolve immediately before every outbound attempt to detect unsafe DNS changes."""
    try:
        canonical, _ = AdmissionService.validate_and_resolve(
            url, assessment_profile=assessment_profile, explicit_allowlist=explicit_allowlist
        )
    except TypeError as exc:
        if "unexpected keyword argument" not in str(exc):
            raise
        canonical, _ = AdmissionService.validate_and_resolve(url)
    parsed = urlsplit(canonical)
    settings = get_settings()
    permitted_ports = {int(item) for item in settings.scanner_allowed_egress_ports.split(",") if item.strip().isdigit()}
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    authorized_extra_ports = {int(item) for item in (allowed_ports or set()) if 1 <= int(item) <= 65535}
    if assessment_profile in {"safe", "normal", "aggressive"} and port not in permitted_ports | authorized_extra_ports:
        raise ScannerSecurityError(f"Outbound port {port} is not permitted by scanner egress policy; explicit authorized ports are required for nonstandard lab ports.")
    return canonical


def bounded_headers(response: httpx.Response, maximum_bytes: int) -> list[tuple[str, str]]:
    values = list(response.headers.multi_items())
    if len(values) > 200:
        raise ScannerSecurityError("Response contains too many headers.")
    encoded = sum(len(name.encode("utf-8", "ignore")) + len(value.encode("utf-8", "ignore")) + 4 for name, value in values)
    if encoded > maximum_bytes:
        raise ScannerSecurityError("Response headers exceed scanner safety limit.")
    return values


def bounded_body(response: httpx.Response, maximum_bytes: int) -> tuple[bytes, bool]:
    """Read at most a decompressed-body budget using streamed chunks."""
    content_length = response.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > maximum_bytes:
                raise ScannerSecurityError("Declared response size exceeds scanner safety limit.")
        except ValueError:
            raise ScannerSecurityError("Response content-length is malformed.")
    content_encoding = response.headers.get("content-encoding", "identity").lower().strip()
    if content_encoding not in {"", "identity", "gzip", "deflate", "br"}:
        raise ScannerSecurityError("Unsupported response compression encoding was blocked.")
    chunks: list[bytes] = []
    used = 0
    truncated = False
    for chunk in response.iter_bytes(chunk_size=65536):
        if not chunk:
            continue
        remaining = maximum_bytes - used
        if remaining <= 0:
            truncated = True
            break
        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            used += remaining
            truncated = True
            break
        chunks.append(chunk)
        used += len(chunk)
    return b"".join(chunks), truncated


def bounded_html_body(response: httpx.Response, maximum_bytes: int) -> tuple[str, bool]:
    content_type = response.headers.get("content-type", "")
    if "html" not in content_type.lower():
        return "", False
    body, truncated = bounded_body(response, maximum_bytes)
    return body.decode(response.encoding or "utf-8", errors="replace"), truncated


def redact_sensitive_text(value: object, maximum_length: int = 512) -> str:
    text = str(value)
    text = re.sub(r"(?i)(authorization|cookie|token|secret|password|api[-_]?key)\s*[:=]\s*[^,;\s]+", r"\1=[REDACTED]", text)
    return text[:maximum_length]
