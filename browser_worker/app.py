import asyncio
import base64
import ipaddress
import os
import logging
import re
import socket
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("browser_worker")

app = FastAPI(title="Web Autopsy Browser Worker", version="0.6.0")

PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("2001:2::/48"),
    ipaddress.ip_network("2001:10::/28"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or any(ip in net for net in PRIVATE_NETWORKS)
        )
    except ValueError:
        return True


def _hostname_allowed(hostname: str, allowed_domains: list[str]) -> bool:
    canonical = hostname.lower().rstrip(".")
    return any(canonical == domain.lower().rstrip(".") or canonical.endswith("." + domain.lower().rstrip(".")) for domain in allowed_domains)


def _path_allowed(path: str, allowed_paths: list[str], excluded_paths: list[str]) -> bool:
    if any(path.startswith(prefix) for prefix in excluded_paths):
        return False
    return not allowed_paths or any(path.startswith(prefix) for prefix in allowed_paths)


def is_url_allowed(url: str, *, allowed_domains: list[str] | None = None, allowed_paths: list[str] | None = None, excluded_paths: list[str] | None = None, allowed_ports: list[int] | None = None) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        return False

    hostname = parsed.hostname
    if not hostname:
        return False
    if parsed.username or parsed.password:
        return False
    if allowed_domains and not _hostname_allowed(hostname, allowed_domains):
        return False
    if not _path_allowed(parsed.path or "/", allowed_paths or [], excluded_paths or []):
        return False
    default_ports = {80, 443}
    explicit_ports = {int(port) for port in (allowed_ports or []) if 1 <= int(port) <= 65535}
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in default_ports | explicit_ports:
        return False

    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if is_private_ip(ip_str):
                return False
        return True
    except socket.gaierror:
        return False


class EgressPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_domains: list[str] = Field(default_factory=list, max_length=100)
    allowed_paths: list[str] = Field(default_factory=list, max_length=100)
    excluded_paths: list[str] = Field(default_factory=list, max_length=100)
    blocked_private_networks: bool = True
    allowed_ports: list[int] = Field(default_factory=list, max_length=20)


class ResourceLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_cpu_seconds: int = Field(default=20, ge=1, le=60)
    max_memory_mb: int = Field(default=512, ge=64, le=2048)
    max_rendered_bytes: int = Field(default=2 * 1024 * 1024, ge=1024, le=8 * 1024 * 1024)
    max_network_events: int = Field(default=250, ge=1, le=1000)
    max_console_events: int = Field(default=250, ge=1, le=1000)
    max_screenshot_bytes: int = Field(default=1024 * 1024, ge=65536, le=2 * 1024 * 1024)


class RenderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    scan_id: str | None = Field(default=None, max_length=64)
    page_id: str | None = Field(default=None, max_length=64)
    timeout_ms: int = Field(default=15000, ge=1000, le=30000)
    headers: dict[str, str] = Field(default_factory=dict, max_length=25)
    egress_policy: EgressPolicy = Field(default_factory=EgressPolicy)
    resource_limits: ResourceLimits = Field(default_factory=ResourceLimits)


class NetworkRequestItem(BaseModel):
    url: str
    method: str
    resource_type: str
    status_code: int | None = None
    timing_ms: float | None = None
    capture_source: str = "browser_runtime"


class RenderResponse(BaseModel):
    status: str
    final_url: str | None = None
    status_code: int | None = None
    rendered_html: str | None = None
    network_requests: list[NetworkRequestItem] = []
    timing_data: dict[str, Any] | None = None
    console_logs: list[dict[str, str]] = []
    screenshot_png_base64: str | None = None
    screenshot_skipped_reason: str | None = None
    error: str | None = None


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "browser-worker"}


@app.post("/render", response_model=RenderResponse)
async def render_page(req: RenderRequest):
    policy = req.egress_policy
    limits = req.resource_limits
    if not is_url_allowed(req.url, allowed_domains=policy.allowed_domains, allowed_paths=policy.allowed_paths, excluded_paths=policy.excluded_paths, allowed_ports=policy.allowed_ports):
        return RenderResponse(
            status="failed",
            error=f"SSRF Check blocked target URL: {req.url}"
        )

    captured_requests: list[dict[str, Any]] = []
    console_logs: list[dict[str, str]] = []

    try:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            executable_path = os.getenv("BROWSER_EXECUTABLE_PATH")
            launch_options = {"headless": True}
            if executable_path:
                launch_options["executable_path"] = executable_path
            browser = await p.chromium.launch(**launch_options)
            context = await browser.new_context(
                accept_downloads=False,
                permissions=[],
                ignore_https_errors=False,
                extra_http_headers=req.headers,
            )

            page = await context.new_page()
            page.set_default_navigation_timeout(req.timeout_ms)
            page.set_default_timeout(req.timeout_ms)
            page.on("dialog", lambda d: asyncio.create_task(d.dismiss()))
            page.on("console", lambda msg: console_logs.append({"type": msg.type, "text": _redact(msg.text)[:2048]}) if len(console_logs) < limits.max_console_events else None)

            async def route_interceptor(route, request):
                if not is_url_allowed(request.url, allowed_domains=policy.allowed_domains, allowed_paths=policy.allowed_paths, excluded_paths=policy.excluded_paths, allowed_ports=policy.allowed_ports):
                    await route.abort("blockedbyclient")
                elif len(captured_requests) >= limits.max_network_events:
                    await route.abort("blockedbyclient")
                else:
                    captured_requests.append({
                        "url": request.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                    })
                    await route.continue_()

            await page.route("**/*", route_interceptor)

            try:
                response = await page.goto(req.url, timeout=req.timeout_ms, wait_until="commit")
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=min(req.timeout_ms, 5000))
                except Exception as load_state_error:
                    logger.info("DOM content load did not complete before the bounded wait: %s", _redact(load_state_error))
                await asyncio.sleep(min(1.0, max(0.1, req.timeout_ms / 10000)))

                rendered_html = await page.content()
                final_url = page.url
                if not is_url_allowed(final_url, allowed_domains=policy.allowed_domains, allowed_paths=policy.allowed_paths, excluded_paths=policy.excluded_paths, allowed_ports=policy.allowed_ports):
                    await browser.close()
                    return RenderResponse(status="failed", error="Browser final URL was blocked by current egress policy.")
                if len(rendered_html.encode("utf-8", errors="ignore")) > limits.max_rendered_bytes:
                    rendered_html = rendered_html.encode("utf-8", errors="ignore")[: limits.max_rendered_bytes].decode("utf-8", errors="ignore")
                status_code = response.status if response else 200

                screenshot_b64 = None
                screenshot_skipped_reason = None
                if req.headers:
                    screenshot_skipped_reason = "Screenshot skipped because forwarded authorization headers could expose authenticated content."
                else:
                    screenshot_bytes = await page.screenshot(type="png", full_page=False, animations="disabled")
                    if len(screenshot_bytes) <= limits.max_screenshot_bytes:
                        screenshot_b64 = base64.b64encode(screenshot_bytes).decode("ascii")
                    else:
                        screenshot_skipped_reason = "Screenshot exceeded the bounded screenshot-size limit."

                timing_json = await page.evaluate("""() => {
                    const nav = performance.getEntriesByType('navigation')[0] || {};
                    return {
                        domInteractive: nav.domInteractive || 0,
                        domComplete: nav.domComplete || 0,
                        loadEventEnd: nav.loadEventEnd || 0
                    };
                }""")

                await browser.close()

                return RenderResponse(
                    status="success",
                    final_url=final_url,
                    status_code=status_code,
                    rendered_html=rendered_html,
                    network_requests=[
                        NetworkRequestItem(
                            url=item["url"],
                            method=item["method"],
                            resource_type=item["resource_type"],
                            status_code=200
                        ) for item in captured_requests
                    ],
                    timing_data={"navigation": timing_json},
                    console_logs=console_logs[: limits.max_console_events],
                    screenshot_png_base64=screenshot_b64,
                    screenshot_skipped_reason=screenshot_skipped_reason,
                )
            except Exception as exc:
                await browser.close()
                return RenderResponse(
                    status="failed",
                    error=f"Browser execution failed: {_redact(exc)}"
                )
    except Exception as exc:
        return RenderResponse(
            status="failed",
            error=f"Playwright worker initialization failed: {_redact(exc)}"
        )


def _redact(value: object) -> str:
    return re.sub(r"(?i)(authorization|cookie|token|secret|password|api[-_]?key)\s*[:=]\s*[^,;\s]+", r"\1=[REDACTED]", str(value))
