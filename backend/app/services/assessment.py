from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any, Mapping
from urllib.parse import urlsplit
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.scan import AssessmentAuditEvent, AssessmentAuthorization, Scan

PROFILE_CAPS: dict[str, dict[str, int]] = {
    "safe": {
        "max_depth": 2,
        "max_requests": 30,
        "max_concurrency": 2,
        "min_rate_limit_per_host_ms": 1000,
    },
    "normal": {
        "max_depth": 3,
        "max_requests": 50,
        "max_concurrency": 3,
        "min_rate_limit_per_host_ms": 500,
    },
    "aggressive": {
        "max_depth": 5,
        "max_requests": 100,
        "max_concurrency": 4,
        "min_rate_limit_per_host_ms": 250,
    },
}
PROFILE_DESCRIPTIONS = {
    "safe": "Passive and low-volume assessment with conservative depth and pacing.",
    "normal": "Bounded passive assessment with moderate depth and pacing.",
    "aggressive": "Highest bounded profile; explicit domain allowlisting is required and robots override remains opt-in.",
}
AUTH_TYPES = {"cookie", "header", "basic"}
_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$", re.IGNORECASE)


class AssessmentPolicyError(ValueError):
    """Raised when a requested assessment policy cannot be admitted safely."""


def utc_now() -> datetime:
    return datetime.now(UTC)


def _settings_key() -> bytes:
    settings = get_settings()
    configured = (settings.assessment_encryption_key or "").strip()
    if configured:
        try:
            key = configured.encode("ascii")
            Fernet(key)
            return key
        except (ValueError, UnicodeEncodeError) as exc:
            raise AssessmentPolicyError("ASSESSMENT_ENCRYPTION_KEY must be a valid Fernet key.") from exc
    if settings.app_env.lower() in {"prod", "production"}:
        raise AssessmentPolicyError("ASSESSMENT_ENCRYPTION_KEY is required in production when authentication secrets are supplied.")
    # Development-safe compatibility fallback. Production should set a dedicated key.
    digest = hashlib.sha256(settings.jwt_secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _fernet() -> Fernet:
    return Fernet(_settings_key())


def encrypt_secret(value: Mapping[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _fernet().encrypt(payload).decode("ascii")


def decrypt_secret(value: str | None) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        payload = _fernet().decrypt(value.encode("ascii"))
        decoded = json.loads(payload.decode("utf-8"))
    except (InvalidToken, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise AssessmentPolicyError("Stored assessment credentials could not be decrypted.") from exc
    return decoded if isinstance(decoded, dict) else None


def _normalize_path(value: str) -> str:
    path = value.strip()
    if not path:
        raise AssessmentPolicyError("Scope paths must not be empty.")
    if not path.startswith("/"):
        path = f"/{path}"
    return path if path == "/" else path.rstrip("/") or "/"


def normalize_paths(values: list[str] | None) -> list[str]:
    return list(dict.fromkeys(_normalize_path(value) for value in (values or [])))


def _normalize_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    if not domain or not _DOMAIN_RE.fullmatch(domain) or ".." in domain:
        raise AssessmentPolicyError(f"Invalid allowed domain: {value}")
    return domain


def normalize_domains(values: list[str] | None) -> list[str]:
    return list(dict.fromkeys(_normalize_domain(value) for value in (values or [])))


def hostname_allowed(hostname: str, allowed_domains: list[str]) -> bool:
    host = hostname.lower().rstrip(".")
    if not allowed_domains:
        return False
    return any(host == domain or host.endswith(f".{domain}") for domain in allowed_domains)


def path_allowed(url: str, allowed_paths: list[str], excluded_paths: list[str]) -> bool:
    path = urlsplit(url).path or "/"
    for pattern in excluded_paths:
        if path == pattern or path.startswith(f"{pattern.rstrip('/')}/") or fnmatch.fnmatch(path, pattern):
            return False
    if not allowed_paths:
        return True
    return any(
        path == pattern
        or path.startswith(f"{pattern.rstrip('/')}/")
        or fnmatch.fnmatch(path, pattern)
        for pattern in allowed_paths
    )


def url_in_scope(url: str, authorization: AssessmentAuthorization) -> bool:
    hostname = (urlsplit(url).hostname or "").lower().rstrip(".")
    return hostname_allowed(hostname, list(authorization.allowed_domains or [])) and path_allowed(
        url,
        list(authorization.allowed_paths or []),
        list(authorization.excluded_paths or []),
    )


def profile_caps() -> dict[str, dict[str, int]]:
    settings = get_settings()
    return {
        "safe": {
            "max_depth": settings.assessment_safe_max_depth,
            "max_requests": settings.assessment_safe_max_requests,
            "max_concurrency": settings.assessment_safe_max_concurrency,
            "min_rate_limit_per_host_ms": settings.assessment_safe_min_rate_limit_ms,
        },
        "normal": {
            "max_depth": settings.assessment_normal_max_depth,
            "max_requests": settings.assessment_normal_max_requests,
            "max_concurrency": settings.assessment_normal_max_concurrency,
            "min_rate_limit_per_host_ms": settings.assessment_normal_min_rate_limit_ms,
        },
        "aggressive": {
            "max_depth": settings.assessment_aggressive_max_depth,
            "max_requests": settings.assessment_aggressive_max_requests,
            "max_concurrency": settings.assessment_aggressive_max_concurrency,
            "min_rate_limit_per_host_ms": settings.assessment_aggressive_min_rate_limit_ms,
        },
    }


def profile_policy(
    profile: str,
    *,
    max_depth: int | None,
    max_requests: int | None,
    max_concurrency: int | None,
    rate_limit_per_host_ms: int | None,
) -> dict[str, int]:
    if profile not in PROFILE_CAPS:
        raise AssessmentPolicyError(f"Unknown assessment profile: {profile}")
    caps = profile_caps()[profile]
    requested = {
        "max_depth": caps["max_depth"] if max_depth is None else max_depth,
        "max_requests": caps["max_requests"] if max_requests is None else max_requests,
        "max_concurrency": caps["max_concurrency"] if max_concurrency is None else max_concurrency,
        "rate_limit_per_host_ms": caps["min_rate_limit_per_host_ms"] if rate_limit_per_host_ms is None else rate_limit_per_host_ms,
    }
    if requested["max_depth"] < 0 or requested["max_requests"] < 1 or requested["max_concurrency"] < 1 or requested["rate_limit_per_host_ms"] < 1:
        raise AssessmentPolicyError("Assessment limits must be positive.")
    requested["max_depth"] = min(requested["max_depth"], caps["max_depth"])
    requested["max_requests"] = min(requested["max_requests"], caps["max_requests"])
    requested["max_concurrency"] = min(requested["max_concurrency"], caps["max_concurrency"])
    requested["rate_limit_per_host_ms"] = max(requested["rate_limit_per_host_ms"], caps["min_rate_limit_per_host_ms"])
    return requested


def normalize_authentication(authentication: Mapping[str, Any] | None) -> tuple[str, dict[str, Any] | None]:
    if not authentication:
        return "none", None
    auth_type = str(authentication.get("type", "")).strip().lower()
    if auth_type not in AUTH_TYPES:
        raise AssessmentPolicyError("Authentication type must be cookie, header, or basic.")
    if auth_type == "cookie":
        name = str(authentication.get("name", "")).strip()
        value = str(authentication.get("value", ""))
        if not name or not value:
            raise AssessmentPolicyError("Cookie authentication requires a name and value.")
        if any(char in name for char in "\r\n;=") or "\r" in value or "\n" in value:
            raise AssessmentPolicyError("Cookie authentication contains invalid characters.")
        return auth_type, {"type": auth_type, "name": name, "value": value}
    if auth_type == "header":
        name = str(authentication.get("name", "")).strip()
        value = str(authentication.get("value", ""))
        if not name or not value or name.lower() in {"host", "content-length", "transfer-encoding"}:
            raise AssessmentPolicyError("Header authentication requires a safe header name and value.")
        if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
            raise AssessmentPolicyError("Header authentication contains invalid characters.")
        return auth_type, {"type": auth_type, "name": name, "value": value}
    username = str(authentication.get("username", ""))
    password = str(authentication.get("password", ""))
    if not username or not password:
        raise AssessmentPolicyError("Basic authentication requires username and password.")
    return auth_type, {"type": auth_type, "username": username, "password": password}


def credentials_headers(authentication: Mapping[str, Any] | None) -> dict[str, str]:
    if not authentication:
        return {}
    auth_type = authentication.get("type")
    if auth_type == "cookie":
        return {"Cookie": f"{authentication['name']}={authentication['value']}"}
    if auth_type == "header":
        return {str(authentication["name"]): str(authentication["value"])}
    if auth_type == "basic":
        token = base64.b64encode(
            f"{authentication['username']}:{authentication['password']}".encode("utf-8")
        ).decode("ascii")
        return {"Authorization": f"Basic {token}"}
    return {}


def consent_hash(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append_audit_event(
    db: Session,
    *,
    scan_id: UUID,
    event_type: str,
    actor_id: str,
    payload: Mapping[str, Any],
    authorization_id: UUID | None = None,
) -> AssessmentAuditEvent:
    previous = (
        db.query(AssessmentAuditEvent)
        .filter(AssessmentAuditEvent.scan_id == scan_id)
        .order_by(AssessmentAuditEvent.sequence_number.desc())
        .first()
    )
    sequence = (previous.sequence_number + 1) if previous else 1
    previous_hash = previous.event_hash if previous else "GENESIS"
    event_payload = dict(payload)
    event_payload.pop("secret", None)
    event_payload.pop("password", None)
    material = {
        "scan_id": str(scan_id),
        "authorization_id": str(authorization_id) if authorization_id else None,
        "sequence_number": sequence,
        "event_type": event_type,
        "actor_id": actor_id,
        "payload": event_payload,
        "previous_hash": previous_hash,
    }
    event_hash = consent_hash(material)
    event = AssessmentAuditEvent(
        scan_id=scan_id,
        authorization_id=authorization_id,
        sequence_number=sequence,
        event_type=event_type,
        actor_id=actor_id,
        payload=event_payload,
        previous_hash=previous_hash,
        event_hash=event_hash,
    )
    db.add(event)
    db.flush()
    return event


def authorization_public(authorization: AssessmentAuthorization | None) -> dict[str, Any] | None:
    if authorization is None:
        return None
    scope = dict(authorization.scope_json or {})
    scope.pop("authentication_secret", None)
    scope.pop("password", None)
    return {
        "id": str(authorization.id),
        "scan_id": str(authorization.scan_id),
        "authorization_type": authorization.authorization_type,
        "actor_id": authorization.actor_id,
        "target_url": authorization.target_url,
        "allowed_paths": authorization.allowed_paths or [],
        "excluded_paths": authorization.excluded_paths or [],
        "allowed_domains": authorization.allowed_domains or [],
        "allowed_ports": scope.get("allowed_ports", []),
        "assessment_profile": authorization.assessment_profile,
        "robots_override": bool(authorization.robots_override),
        "max_depth": authorization.max_depth,
        "max_pages": authorization.max_pages,
        "max_requests": authorization.max_requests,
        "max_concurrency": authorization.max_concurrency,
        "rate_limit_per_host_ms": authorization.rate_limit_per_host_ms,
        "test_account_ref": authorization.test_account_ref,
        "authentication_type": scope.get("authentication_type", "none"),
        "authentication_configured": bool(authorization.auth_secret_encrypted),
        "secret_fingerprint": authorization.auth_secret_fingerprint,
        "consent_hash": authorization.consent_hash,
        "authorized_at": authorization.authorized_at.isoformat() if authorization.authorized_at else None,
        "expires_at": authorization.expires_at.isoformat() if authorization.expires_at else None,
        "policy_version": authorization.policy_version,
        "scope_json": scope,
    }


def get_authorization(db: Session, scan_id: UUID) -> AssessmentAuthorization | None:
    return (
        db.query(AssessmentAuthorization)
        .filter(AssessmentAuthorization.scan_id == scan_id)
        .order_by(AssessmentAuthorization.authorized_at.desc())
        .first()
    )


def get_credentials(db: Session, scan_id: UUID) -> dict[str, Any] | None:
    authorization = get_authorization(db, scan_id)
    if not authorization:
        return None
    return decrypt_secret(authorization.auth_secret_encrypted)


def scope_summary(authorization: AssessmentAuthorization) -> dict[str, Any]:
    return {
        "target": authorization.target_url,
        "allowed_domains": authorization.allowed_domains or [],
        "allowed_paths": authorization.allowed_paths or [],
        "excluded_paths": authorization.excluded_paths or [],
        "profile": authorization.assessment_profile,
        "max_depth": authorization.max_depth,
        "max_requests": authorization.max_requests,
        "max_concurrency": authorization.max_concurrency,
        "rate_limit_per_host_ms": authorization.rate_limit_per_host_ms,
        "robots_override": bool(authorization.robots_override),
    }


__all__ = [
    "AUTH_TYPES",
    "PROFILE_CAPS",
    "PROFILE_DESCRIPTIONS",
    "AssessmentPolicyError",
    "append_audit_event",
    "authorization_public",
    "consent_hash",
    "credentials_headers",
    "decrypt_secret",
    "encrypt_secret",
    "get_authorization",
    "get_credentials",
    "hostname_allowed",
    "normalize_authentication",
    "normalize_domains",
    "normalize_paths",
    "path_allowed",
    "profile_caps",
    "profile_policy",
    "scope_summary",
    "url_in_scope",
]
