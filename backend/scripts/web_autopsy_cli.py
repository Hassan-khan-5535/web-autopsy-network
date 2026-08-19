"""Scope-safe command-line client for the Web Autopsy Network public API.

The CLI never contacts assessment targets directly; it only calls the platform API.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_BASE_URL = os.environ.get("WEB_AUTOPSY_API_URL", "http://127.0.0.1:8000")
RESOURCE_PATHS = {
    "status": "/v1/scans/{scan_id}", "progress": "/v1/scans/{scan_id}/progress",
    "assets": "/v1/scans/{scan_id}/recon", "evidence": "/v1/scans/{scan_id}/evidence",
    "findings": "/v1/platform/scans/{scan_id}/findings", "graph": "/v1/scans/{scan_id}/attack-surface-graph",
    "report": "/v1/scans/{scan_id}/report",
}


def comma_values(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def load_auth_file(path_value: str | None) -> dict[str, Any] | None:
    if not path_value:
        return None
    path = Path(path_value).expanduser().resolve()
    mode = path.stat().st_mode
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        raise ValueError("Authentication configuration file must not be group- or world-readable.")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("type") not in {"cookie", "header", "basic"}:
        raise ValueError("Authentication configuration must be a JSON object with type cookie, header, or basic.")
    return value


def create_payload(args: argparse.Namespace) -> dict[str, Any]:
    if not args.authorized:
        raise ValueError("Refusing to create a scan without --authorized confirmation.")
    if args.profile == "aggressive" and not comma_values(args.allowed_domain):
        raise ValueError("Aggressive profile requires at least one --allowed-domain.")
    return {
        "url": args.url, "authorization_acknowledged": True, "assessment_profile": args.profile,
        "recon_mode": args.recon_mode, "allowed_domains": comma_values(args.allowed_domain),
        "allowed_paths": comma_values(args.allowed_path), "excluded_paths": comma_values(args.excluded_path),
        "max_depth": args.max_depth, "max_pages": args.max_pages, "max_requests": args.max_requests,
        "max_concurrency": args.max_concurrency, "rate_limit_per_host_ms": args.rate_limit_ms,
        "robots_override": args.robots_override, "authentication": load_auth_file(args.auth_json_file),
        "test_account_ref": args.test_account_ref or None,
    }


def request_json(base_url: str, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(f"{base_url.rstrip('/')}{path}", method=method, data=body, headers={"Accept": "application/json", **({"Content-Type": "application/json"} if body else {})})
    try:
        with urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"API request failed ({exc.code}): {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"API connection failed: {exc.reason}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scope-safe Web Autopsy Network API client")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Platform API base URL, defaulting to WEB_AUTOPSY_API_URL or local API")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("capabilities", help="Show the public API capability catalog")
    create = subparsers.add_parser("create", help="Create an authorization-gated bounded scan")
    create.add_argument("--url", required=True)
    create.add_argument("--authorized", action="store_true", help="Required confirmation that you are authorized to assess the target")
    create.add_argument("--profile", choices=["safe", "normal", "aggressive"], default="safe")
    create.add_argument("--recon-mode", choices=["passive_only", "active_safe"], default="passive_only")
    create.add_argument("--allowed-domain", default="")
    create.add_argument("--allowed-path", default="")
    create.add_argument("--excluded-path", default="")
    create.add_argument("--max-depth", type=int)
    create.add_argument("--max-pages", type=int)
    create.add_argument("--max-requests", type=int)
    create.add_argument("--max-concurrency", type=int)
    create.add_argument("--rate-limit-ms", type=int)
    create.add_argument("--robots-override", action="store_true")
    create.add_argument("--auth-json-file", help="Owner-readable JSON authentication configuration file; never printed by the CLI")
    create.add_argument("--test-account-ref")
    for resource in RESOURCE_PATHS:
        command = subparsers.add_parser(resource, help=f"Retrieve persisted {resource} data for a scan")
        command.add_argument("scan_id")
        if resource == "findings":
            command.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"])
            command.add_argument("--min-confidence", type=float)
    compare = subparsers.add_parser("compare", help="Compare two persisted scans of the same target")
    compare.add_argument("--scan-a", required=True)
    compare.add_argument("--scan-b", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "capabilities":
            result = request_json(args.base_url, "GET", "/v1/capabilities")
        elif args.command == "create":
            result = request_json(args.base_url, "POST", "/v1/scans", create_payload(args))
        elif args.command == "compare":
            result = request_json(args.base_url, "POST", "/v1/scans/compare", {"scan_a": args.scan_a, "scan_b": args.scan_b})
        else:
            path = RESOURCE_PATHS[args.command].format(scan_id=args.scan_id)
            if args.command == "findings":
                query = [f"severity={args.severity}" if args.severity else "", f"min_confidence={args.min_confidence}" if args.min_confidence is not None else ""]
                path += "?" + "&".join(item for item in query if item) if any(query) else ""
            result = request_json(args.base_url, "GET", path)
    except (RuntimeError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
