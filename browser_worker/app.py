import asyncio
import ipaddress
import os
import logging
import socket
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("browser_worker")

app = FastAPI(title="Web Autopsy Browser Worker", version="0.6.0")

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return True


def is_url_allowed(url: str) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        return False

    hostname = parsed.hostname
    if not hostname:
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


class RenderRequest(BaseModel):
    url: str
    timeout_ms: int = Field(default=20000, ge=1000, le=60000)


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
    error: str | None = None


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "browser-worker"}


@app.post("/render", response_model=RenderResponse)
async def render_page(req: RenderRequest):
    if not is_url_allowed(req.url):
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
                ignore_https_errors=False
            )

            page = await context.new_page()
            page.on("dialog", lambda d: asyncio.create_task(d.dismiss()))
            page.on("console", lambda msg: console_logs.append({"type": msg.type, "text": msg.text}))

            async def route_interceptor(route, request):
                if not is_url_allowed(request.url):
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
                response = await page.goto(req.url, timeout=15000, wait_until="domcontentloaded")
                await asyncio.sleep(1.0)  # Allow JS execution to settle

                rendered_html = await page.content()
                final_url = page.url
                status_code = response.status if response else 200

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
                    console_logs=console_logs
                )
            except Exception as exc:
                await browser.close()
                return RenderResponse(
                    status="failed",
                    error=f"Browser execution failed: {str(exc)}"
                )
    except Exception as exc:
        return RenderResponse(
            status="failed",
            error=f"Playwright worker initialization failed: {str(exc)}"
        )
