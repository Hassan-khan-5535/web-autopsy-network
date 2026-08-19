import copy

import pytest

from app.services.updates import UpdatePackageError, UpdatePackageService


def package(service: UpdatePackageService, version: str = "1.0.0", disabled: list[str] | None = None):
    value = {
        "manifest": {
            "name": "community-security-rules",
            "version": version,
            "created_at": "2026-08-19T00:00:00Z",
            "compatibility": {"min_scanner_version": "0.16.0"},
            "provenance": {"publisher": "test-maintainer", "source": "local-fixture"},
        },
        "components": {
            "technology_signatures": {
                "version": f"tech-{version}",
                "rules": [{"id": "TECH-DEMO-001", "technology": "Demo CMS", "category": "cms", "signal_type": "html", "pattern": "demo-cms", "weight": 60, "field": "html"}],
                "disabled_rule_ids": disabled or [],
            },
            "configuration_rules": {"version": f"config-{version}", "rules": [{"id": "CFG-DEMO-001"}], "disabled_rule_ids": ["CFG-HEADERS-001"]},
            "secret_patterns": {"version": f"secret-{version}", "rules": [{"id": "SECRET-DEMO-001", "pattern": "demo_secret_[0-9]+"}], "disabled_rule_ids": ["SECRET-ENTROPY-001"]},
            "vulnerability_checks": {"version": f"vuln-{version}", "rules": [{"id": "VULN-DEMO-001"}]},
            "cve_intelligence": {"version": f"cve-{version}", "records": []},
            "remediation_metadata": {"version": f"remediation-{version}", "items": {}},
        },
    }
    value["signature"] = {"algorithm": "hmac-sha256", "value": service.sign_for_local_test(value)}
    return value


def test_signed_package_activation_tracks_provenance_cache_and_disabled_rules(db, tmp_path, monkeypatch):
    monkeypatch.setenv("UPDATE_PACKAGE_CACHE_DIR", str(tmp_path / "cache"))
    from app.core.config import get_settings
    get_settings.cache_clear()
    service = UpdatePackageService(db)

    installed = service.install(package(service), activate=True)
    active = service.resolve_component("technology_signatures")
    status = service.status()

    assert installed.status == "active"
    assert installed.signature_verified is True
    assert active["component"]["disabled_rule_ids"] == []
    assert status["offline_safe"] is True
    assert (tmp_path / "cache" / "community-security-rules" / "active.json").exists()
    get_settings.cache_clear()


def test_rejects_tampered_or_invalid_package_before_activation(db):
    service = UpdatePackageService(db)
    tampered = package(service)
    tampered["components"]["technology_signatures"]["rules"][0]["pattern"] = "changed-after-signing"
    with pytest.raises(UpdatePackageError, match="signature"):
        service.install(tampered)

    invalid = package(service)
    invalid["components"]["secret_patterns"]["rules"][0]["pattern"] = "(unclosed"
    invalid["signature"]["value"] = service.sign_for_local_test(invalid)
    with pytest.raises(UpdatePackageError, match="invalid regex"):
        service.install(invalid)


def test_rollback_restores_prior_verified_local_package_and_no_package_falls_back(db):
    service = UpdatePackageService(db)
    first = service.install(package(service, "1.0.0"), activate=True)
    second = service.install(package(service, "1.1.0"), activate=True)

    restored = service.rollback("community-security-rules")

    assert restored is not None
    assert restored.id == first.id
    assert restored.status == "active"
    assert service.resolve_component("technology_signatures")["package_version"] == "1.0.0"
    assert second.status == "rolled_back"
    assert UpdatePackageService(db).resolve_component("remediation_metadata") is not None
