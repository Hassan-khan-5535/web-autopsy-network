"""Versioned, verified, offline-safe signature and template update packages."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.update_package import UpdatePackage

UPDATE_VERSION = "extension16-v1"
COMPONENTS = {"technology_signatures", "configuration_rules", "vulnerability_checks", "secret_patterns", "cve_intelligence", "remediation_metadata"}


class UpdatePackageError(ValueError):
    """Raised when a package cannot be safely installed or activated."""


def utc_now() -> datetime:
    return datetime.now(UTC)


class UpdatePackageService:
    """Manage local signed update packages without making runtime network requests."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.settings = get_settings()
        self.cache_dir = Path(self.settings.update_package_cache_dir).expanduser().resolve()

    @staticmethod
    def canonical_bytes(package: dict[str, Any]) -> bytes:
        payload = {key: value for key, value in package.items() if key != "signature"}
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    def sign_for_local_test(self, package: dict[str, Any]) -> str:
        return hmac.new(self.settings.update_package_hmac_key.encode(), self.canonical_bytes(package), hashlib.sha256).hexdigest()

    def install(self, package: dict[str, Any], *, activate: bool = False, note: str | None = None) -> UpdatePackage:
        report = self.validate(package)
        canonical = self.canonical_bytes(package)
        digest = hashlib.sha256(canonical).hexdigest()
        manifest = package["manifest"]
        existing = self.db.query(UpdatePackage).filter(UpdatePackage.package_name == manifest["name"], UpdatePackage.version == manifest["version"]).first()
        if existing:
            if existing.sha256 != digest:
                raise UpdatePackageError("Package name and version already exist with different content.")
            return self.activate(existing.id) if activate and existing.status != "active" else existing
        item = UpdatePackage(
            package_name=manifest["name"], version=manifest["version"], status="staged", manifest=manifest,
            components=package["components"], compatibility=manifest["compatibility"], provenance=manifest.get("provenance", {}),
            sha256=digest, signature_algorithm=(package.get("signature") or {}).get("algorithm"), signature_verified=report["signature_verified"], validation_report=report, note=note,
        )
        self.db.add(item)
        self.db.commit()
        self.db.refresh(item)
        self._cache(item)
        return self.activate(item.id) if activate else item

    def validate(self, package: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(package, dict) or set(package) - {"manifest", "components", "signature"}:
            raise UpdatePackageError("Package must contain only manifest, components, and optional signature.")
        manifest, components = package.get("manifest"), package.get("components")
        if not isinstance(manifest, dict) or not isinstance(components, dict):
            raise UpdatePackageError("Package manifest and components must be objects.")
        required_manifest = {"name", "version", "compatibility", "created_at", "provenance"}
        if missing := required_manifest - set(manifest):
            raise UpdatePackageError(f"Manifest missing required fields: {', '.join(sorted(missing))}.")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,119}", str(manifest["name"])):
            raise UpdatePackageError("Manifest name must be a lowercase package identifier.")
        self._compatible(manifest["compatibility"])
        unknown = set(components) - COMPONENTS
        if unknown:
            raise UpdatePackageError(f"Unsupported component types: {', '.join(sorted(unknown))}.")
        if not components:
            raise UpdatePackageError("Package contains no update components.")
        signature_verified = self._verify_signature(package)
        regression = self._regression_check(components)
        return {"update_version": UPDATE_VERSION, "signature_verified": signature_verified, "schema_valid": True, "compatibility_valid": True, "regression": regression, "validated_at": utc_now().isoformat()}

    def activate(self, package_id: Any) -> UpdatePackage:
        item = self.db.query(UpdatePackage).filter(UpdatePackage.id == package_id).first()
        if not item:
            raise UpdatePackageError("Update package not found.")
        if not item.signature_verified or not item.validation_report.get("regression", {}).get("passed"):
            raise UpdatePackageError("Package cannot activate until signature and regression checks pass.")
        for prior in self.db.query(UpdatePackage).filter(UpdatePackage.package_name == item.package_name, UpdatePackage.status == "active", UpdatePackage.id != item.id).all():
            prior.status, prior.rolled_back_at = "rolled_back", utc_now()
        item.status, item.activated_at, item.rolled_back_at = "active", utc_now(), None
        self.db.commit()
        self.db.refresh(item)
        self._cache(item)
        return item

    def rollback(self, package_name: str) -> UpdatePackage | None:
        active = self.db.query(UpdatePackage).filter(UpdatePackage.package_name == package_name, UpdatePackage.status == "active").order_by(UpdatePackage.activated_at.desc()).first()
        previous = self.db.query(UpdatePackage).filter(UpdatePackage.package_name == package_name, UpdatePackage.status == "rolled_back").order_by(UpdatePackage.rolled_back_at.desc()).first()
        if not active or not previous:
            if active:
                active.status, active.rolled_back_at = "rolled_back", utc_now()
                self.db.commit()
            self._remove_active_cache(package_name)
            return None
        active.status, active.rolled_back_at = "rolled_back", utc_now()
        previous.status, previous.activated_at, previous.rolled_back_at, previous.rollback_of_id = "active", utc_now(), None, active.id
        self.db.commit()
        self.db.refresh(previous)
        self._cache(previous)
        return previous

    def resolve_component(self, component_name: str) -> dict[str, Any] | None:
        if component_name not in COMPONENTS:
            raise UpdatePackageError("Unsupported component type.")
        active = self.db.query(UpdatePackage).filter(UpdatePackage.status == "active").order_by(UpdatePackage.activated_at.desc()).all()
        for package in active:
            component = (package.components or {}).get(component_name)
            if component is not None:
                return {"package_name": package.package_name, "package_version": package.version, "sha256": package.sha256, "provenance": package.provenance, "activated_at": package.activated_at.isoformat() if package.activated_at else None, "component": component}
        return None

    def status(self) -> dict[str, Any]:
        packages = self.db.query(UpdatePackage).order_by(UpdatePackage.installed_at.desc()).all()
        return {"update_version": UPDATE_VERSION, "offline_safe": True, "external_feed_required": False, "cache_dir": str(self.cache_dir), "packages": [self._public(item) for item in packages], "fallback": "Built-in signatures and rule sets remain active whenever no verified local package is active."}

    def _verify_signature(self, package: dict[str, Any]) -> bool:
        signature = package.get("signature")
        if not signature:
            if self.settings.update_package_require_signature:
                raise UpdatePackageError("A signed update package is required by current policy.")
            return False
        if not isinstance(signature, dict) or signature.get("algorithm") != "hmac-sha256" or not isinstance(signature.get("value"), str):
            raise UpdatePackageError("Signature must use hmac-sha256 with a hexadecimal value.")
        expected = self.sign_for_local_test(package)
        if not hmac.compare_digest(expected, signature["value"]):
            raise UpdatePackageError("Update package signature verification failed.")
        return True

    def _compatible(self, compatibility: Any) -> None:
        if not isinstance(compatibility, dict) or not isinstance(compatibility.get("min_scanner_version"), str):
            raise UpdatePackageError("Manifest compatibility requires min_scanner_version.")
        current, minimum = self._version_tuple(self.settings.update_package_scanner_version), self._version_tuple(compatibility["min_scanner_version"])
        if current < minimum or current[0] != minimum[0]:
            raise UpdatePackageError("Package is not compatible with this scanner version.")

    @staticmethod
    def _version_tuple(value: str) -> tuple[int, int, int]:
        match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", value)
        if not match:
            raise UpdatePackageError("Versions must use major.minor.patch format.")
        return tuple(int(item) for item in match.groups())

    @staticmethod
    def _regression_check(components: dict[str, Any]) -> dict[str, Any]:
        checked_rules = 0
        disabled: list[str] = []
        for component_name, component in components.items():
            if not isinstance(component, dict) or not isinstance(component.get("version"), str):
                raise UpdatePackageError(f"{component_name} requires a component version.")
            rules = component.get("rules", component.get("records", component.get("items", [])))
            if not isinstance(rules, (list, dict)):
                raise UpdatePackageError(f"{component_name} rules, records, or items must be a list or object.")
            if isinstance(rules, list):
                ids: set[str] = set()
                for rule in rules:
                    if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
                        raise UpdatePackageError(f"{component_name} rule entries require string ids.")
                    if rule["id"] in ids:
                        raise UpdatePackageError(f"{component_name} contains duplicate rule id {rule['id']}.")
                    ids.add(rule["id"])
                    if "pattern" in rule:
                        try:
                            re.compile(str(rule["pattern"]))
                        except re.error as exc:
                            raise UpdatePackageError(f"{component_name} rule {rule['id']} has invalid regex: {exc}") from exc
                checked_rules += len(rules)
            disabled.extend(component.get("disabled_rule_ids", []))
        if any(not isinstance(item, str) for item in disabled):
            raise UpdatePackageError("disabled_rule_ids must contain only strings.")
        return {"passed": True, "checked_component_count": len(components), "checked_rule_count": checked_rules, "disabled_rule_ids": sorted(set(disabled))}

    def _cache(self, item: UpdatePackage) -> None:
        target = self.cache_dir / item.package_name / item.version
        target.mkdir(parents=True, exist_ok=True)
        (target / "package.json").write_text(json.dumps({"manifest": item.manifest, "components": item.components, "sha256": item.sha256, "signature_verified": item.signature_verified}, sort_keys=True, indent=2), encoding="utf-8")
        active = self.cache_dir / item.package_name / "active.json"
        if item.status == "active":
            active.write_text(json.dumps({"version": item.version, "sha256": item.sha256, "activated_at": item.activated_at.isoformat() if item.activated_at else None}, sort_keys=True), encoding="utf-8")

    def _remove_active_cache(self, package_name: str) -> None:
        path = self.cache_dir / package_name / "active.json"
        if path.exists():
            path.unlink()

    @staticmethod
    def _public(item: UpdatePackage) -> dict[str, Any]:
        return {"id": str(item.id), "name": item.package_name, "version": item.version, "status": item.status, "signature_verified": item.signature_verified, "sha256": item.sha256, "components": sorted((item.components or {}).keys()), "provenance": item.provenance, "installed_at": item.installed_at.isoformat(), "activated_at": item.activated_at.isoformat() if item.activated_at else None, "rolled_back_at": item.rolled_back_at.isoformat() if item.rolled_back_at else None, "validation_report": item.validation_report}
