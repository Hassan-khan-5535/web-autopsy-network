from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.scan import Base, Observation, Page, PageLink, Scan, Website
from app.services.admission import AdmissionError, AdmissionService
from app.services.crawler import CrawlerService


class SiteState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.requested: list[str] = []


class CrawlHandler(BaseHTTPRequestHandler):
    state = SiteState()

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        with self.state.lock:
            self.state.active += 1
            self.state.max_active = max(self.state.max_active, self.state.active)
            self.state.requested.append(path)
        try:
            if path in {"/one", "/two", "/three"}:
                time.sleep(0.05)
            pages = {
                "/": (
                    "<title>Home</title><link rel='stylesheet' href='/site.css'>"
                    "<script src='/app.js'></script><img src='/hero.png'>"
                    "<a href='/one'>one</a><a href='/one#fragment'>duplicate</a>"
                    "<a href='/two'>two</a><a href='/three'>three</a>"
                    "<a href='/blocked'>blocked</a><a href='/private'>private</a>"
                    "<a href='https://external.example/out'>external</a>"
                ),
                "/one": "<title>One</title><a href='/'>home</a>",
                "/two": "<title>Two</title>",
                "/three": "<title>Three</title>",
                "/blocked": "<title>Should not be fetched</title>",
                "/private": "<title>Should not be fetched</title>",
            }
            if path == "/robots.txt":
                body = "User-agent: *\nDisallow: /blocked\n"
                content_type = "text/plain"
                status = 200
            elif path in pages:
                body = pages[path]
                content_type = "text/html"
                status = 200
            else:
                body = "not found"
                content_type = "text/plain"
                status = 404
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(body.encode())
        finally:
            with self.state.lock:
                self.state.active -= 1

    def log_message(self, *_args: object) -> None:
        return


@pytest.fixture
def local_site(monkeypatch: pytest.MonkeyPatch):
    state = SiteState()
    CrawlHandler.state = state
    server = ThreadingHTTPServer(("127.0.0.1", 0), CrawlHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    def admit(url: str) -> tuple[str, str]:
        normalized = AdmissionService.normalize_url(url)
        if urlsplit(normalized).path == "/private":
            raise AdmissionError("Non-public IP address 10.0.0.1 is blocked.")
        return normalized, "93.184.216.34"

    monkeypatch.setattr(AdmissionService, "validate_and_resolve", staticmethod(admit))
    try:
        yield base_url, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def make_scan(
    db: Session, base_url: str, *, max_depth: int, max_pages: int, concurrency: int
) -> Scan:
    website = Website(
        id=uuid4(), tenant_id="default", canonical_origin=urlsplit(base_url).hostname or "localhost"
    )
    db.add(website)
    db.flush()
    scan = Scan(
        id=uuid4(),
        website_id=website.id,
        state="CREATED",
        requested_url=base_url,
        max_depth=max_depth,
        max_pages=max_pages,
        max_concurrency=concurrency,
        request_delay_ms=0,
        same_domain_mode="hostname",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def test_crawler_persists_pages_resources_links_and_honors_policy(local_site, db: Session) -> None:
    base_url, state = local_site
    scan = make_scan(db, base_url, max_depth=1, max_pages=10, concurrency=2)

    CrawlerService(db, scan, base_url).crawl()

    db.refresh(scan)
    pages = db.query(Page).filter(Page.scan_id == scan.id).all()
    links = (
        db.query(PageLink).filter(PageLink.source_page_id.in_([page.id for page in pages])).all()
    )
    urls = {page.canonical_url for page in pages}

    assert scan.state == "COMPLETED"
    assert len(pages) == 4
    assert all(page.depth <= 1 for page in pages)
    assert not any("external.example" in url for url in urls)
    assert not any(path == "/blocked" for path in state.requested)
    assert not any(path == "/private" for path in state.requested)
    assert any(link.is_external and "external.example" in link.target_url for link in links)
    observations = db.query(Observation).filter(Observation.scan_id == scan.id).all()
    assert any(
        "/private" in observation.subject or "/private" in observation.observation
        for observation in observations
    )
    assert any(resource.type == "script" for page in pages for resource in page.resources)
    assert any(resource.type == "font" for page in pages for resource in page.resources) is False
    assert state.max_active <= 2


def test_crawler_deduplicates_normalized_urls_and_enforces_page_ceiling(
    local_site, db: Session
) -> None:
    base_url, _ = local_site
    scan = make_scan(db, base_url, max_depth=2, max_pages=2, concurrency=1)

    CrawlerService(db, scan, base_url).crawl()

    pages = db.query(Page).filter(Page.scan_id == scan.id).all()
    assert len(pages) == 2
    assert len({page.canonical_url for page in pages}) == len(pages)
    assert all(page.depth <= 2 for page in pages)
    assert any(
        "Maximum page count reached" in observation.observation for observation in scan.observations
    )


def test_admission_normalization_removes_fragments_and_sorts_query_parameters() -> None:
    assert (
        AdmissionService.normalize_url("HTTPS://Example.COM/a/?z=2&a=1#section")
        == "https://example.com/a?a=1&z=2"
    )
