"""Synthetic local-only benchmark target and measurement harness for Extension 18."""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from time import perf_counter
from urllib.parse import urlsplit
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.scan import Base, Page, Resource, Scan, Website
from app.services.admission import AdmissionService
from app.services.browser_client import BrowserWorkerClient
from app.services.benchmarking import set_metrics
from app.services.crawler import CrawlerService


class _State:
    active = 0
    max_active = 0
    lock = threading.Lock()


class BenchmarkTargetHandler(BaseHTTPRequestHandler):
    state = _State()

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        with self.state.lock:
            self.state.active += 1
            self.state.max_active = max(self.state.max_active, self.state.active)
        try:
            if path in {"/api/status", "/public"}:
                time.sleep(0.02)
            if path == "/robots.txt":
                body, content_type, status = "User-agent: *\n", "text/plain", 200
            elif path == "/":
                body = "<html><script src='/static/benchmark.js'></script><img src='/static/asset.png'><a href='/api/status'>status</a><a href='/public'>public</a><!-- synthetic benchmark secret marker: AKIAAAAAAAAAAAAAAAAA --></html>"
                content_type, status = "text/html", 200
            elif path == "/api/status":
                body, content_type, status = "<html>status</html>", "text/html", 200
            elif path == "/public":
                body, content_type, status = "<html>public</html>", "text/html", 200
            else:
                body, content_type, status = "not found", "text/plain", 404
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
        finally:
            with self.state.lock:
                self.state.active -= 1

    def log_message(self, *_args: object) -> None:
        return


def run_local_target_benchmark() -> dict:
    """Run only against an in-process synthetic host; no external network is used."""
    state = _State()
    BenchmarkTargetHandler.state = state
    server = ThreadingHTTPServer(("127.0.0.1", 0), BenchmarkTargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original_resolver = AdmissionService.validate_and_resolve
    original_browser = BrowserWorkerClient.analyze_page
    base_url = f"http://127.0.0.1:{server.server_port}"
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    started = perf_counter()
    try:
        AdmissionService.validate_and_resolve = staticmethod(lambda url, **_kwargs: (AdmissionService.normalize_url(url), "93.184.216.34"))
        BrowserWorkerClient.analyze_page = lambda *_args, **_kwargs: False
        with Session(engine) as db:
            website = Website(id=uuid4(), tenant_id="benchmark", canonical_origin="benchmark.local")
            db.add(website)
            db.flush()
            scan = Scan(id=uuid4(), website_id=website.id, state="CREATED", requested_url=base_url, max_depth=1, max_pages=3, max_concurrency=2, max_requests=8, request_delay_ms=0, same_domain_mode="hostname")
            db.add(scan)
            db.commit()
            CrawlerService(db, scan, base_url).crawl()
            pages = db.query(Page).filter(Page.scan_id == scan.id).all()
            resources = db.query(Resource).join(Page).filter(Page.scan_id == scan.id).all()
            elapsed_ms = round((perf_counter() - started) * 1000, 2)
            expected_pages = {"/", "/api/status", "/public"}
            observed_pages = {urlsplit(page.canonical_url).path or "/" for page in pages}
            expected_assets = {"/static/benchmark.js", "/static/asset.png"}
            observed_assets = {urlsplit(resource.url or "").path for resource in resources if resource.url}
            return {
                "case_id": "local-intentionally-vulnerable-discovery-v1",
                "ground_truth_revision": "fixture-1",
                "metrics": {
                    "assets": {"status": "measured", **set_metrics(expected_assets, observed_assets, expected_assets).as_dict()},
                    "endpoints": {"status": "measured", **set_metrics(expected_pages, observed_pages, expected_pages).as_dict()},
                    "execution": {"status": "measured", "scan_duration_ms": elapsed_ms, "requests_used": scan.requests_used, "max_concurrency_observed": state.max_active, "reliability": "completed" if scan.state == "COMPLETED" else "failed"},
                    "findings": {"status": "not_measured", "reason": "This passive discovery target does not assert a vulnerability-check ground truth."},
                    "cve_matches": {"status": "not_measured", "reason": "No versioned CVE fixture is included."},
                    "secrets": {"status": "not_measured", "reason": "The target contains only an inert synthetic marker; secret-agent accuracy requires a dedicated redaction oracle."},
                    "differential_changes": {"status": "not_measured", "reason": "Differential accuracy requires paired fixture executions."},
                },
                "limitations": ["In-process synthetic benchmark target only.", "No external or unauthorized network request was issued.", "The synthetic marker is inert and is not a credential."],
            }
    finally:
        AdmissionService.validate_and_resolve = original_resolver
        BrowserWorkerClient.analyze_page = original_browser
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
