from unittest.mock import MagicMock, patch

from sqlalchemy.orm import Session

from app.models.scan import HTTPResponse, Page, Resource, Scan, Website
from app.services.browser_client import BrowserWorkerClient


def test_browser_client_updates_page_response(db: Session):
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.commit()

    scan = Scan(website_id=website.id, requested_url="https://example.com", state="COLLECTING")
    db.add(scan)
    db.commit()

    page = Page(scan_id=scan.id, canonical_url="https://example.com/", depth=0)
    db.add(page)
    db.commit()

    resp = HTTPResponse(
        page_id=page.id,
        status_code=200,
        final_url="https://example.com/",
        raw_body="<html>Static</html>",
    )
    db.add(resp)
    db.commit()

    mock_render = {
        "status": "success",
        "final_url": "https://example.com/",
        "status_code": 200,
        "rendered_html": "<html><body><h1>Rendered JS</h1></body></html>",
        "network_requests": [
            {
                "url": "https://example.com/api/dynamic",
                "method": "GET",
                "resource_type": "fetch",
                "status_code": 200,
                "capture_source": "browser_runtime",
            }
        ],
        "timing_data": {"navigation": {"domComplete": 350}},
        "console_logs": [{"type": "warning", "text": "Console log test"}]
    }

    with patch("httpx.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200, json=lambda: mock_render)
        client = BrowserWorkerClient(db)
        success = client.analyze_page(scan.id, page.id, "https://example.com/")

    assert success is True
    db.refresh(resp)
    assert resp.rendered_body == "<html><body><h1>Rendered JS</h1></body></html>"
    assert resp.timing_data == {"navigation": {"domComplete": 350}}

    resources = db.query(Resource).filter(Resource.page_id == page.id).all()
    assert len(resources) == 1
    assert resources[0].capture_source == "browser_runtime"
