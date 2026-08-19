# Extension 16 — Template and Signature Update System

## Purpose

Extension 16 introduces a local, versioned update lifecycle for technology signatures, configuration rules, vulnerability checks, secret patterns, CVE intelligence, and remediation metadata. The scanner does not depend on any external feed at scan time.

## Package Contract

Each package carries a manifest, named components, and an `hmac-sha256` signature over canonical JSON excluding the signature field. The manifest contains a package name, semantic version, creation time, provenance, and minimum scanner compatibility. Packages are staged before activation.

| Gate | Activation behavior |
| --- | --- |
| Schema | Rejects malformed manifests, unsupported components, invalid rule ids, malformed disabled-rule lists, and invalid regular expressions. |
| Signature | Verifies HMAC integrity using the locally configured update key. Unsigned packages are rejected by default. |
| Compatibility | Requires a matching scanner major version and an installed scanner version at least as new as the package minimum. |
| Regression | Rejects duplicate rule IDs and malformed patterns before activation. |
| Provenance | Stores manifest provenance, digest, signature state, validation report, installation, activation, and rollback timestamps. |

## Offline Operation and Rollback

Verified packages are written to a local cache and are persisted in the database. An active package can be rolled back to the prior local package; if no prior package exists, the system falls back to built-in rules. Temporary external-feed outages do not affect scans because package resolution is local and built-in signatures remain available whenever no verified package is active.

## Disabled Rules

Components can declare `disabled_rule_ids`. The active package’s metadata is exposed to agents and UI status while built-in behavior remains unchanged until a component-specific adapter consumes that rule source. This keeps disabling auditable and prevents a malformed package from silently changing unrelated scanner behavior.
