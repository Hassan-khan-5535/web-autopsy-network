from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.scan import ApiEndpoint, HTTPResponse, Page, Resource, Scan, Website
from app.services.api_intelligence import ApiIntelligenceAgent


def test_api_intelligence_agent_detection(db: Session):
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.commit()

    scan = Scan(website_id=website.id, requested_url="https://example.com", state="COLLECTING")
    db.add(scan)
    db.commit()

    page = Page(scan_id=scan.id, canonical_url="https://example.com/app", depth=0, title="App")
    db.add(page)
    db.commit()

    # Add resource URL pointing to API
    db.add(Resource(page_id=page.id, url="https://example.com/api/v1/config.json", type="script"))
    db.commit()

    # Add HTML response with inline fetch and form action
    html_body = """
    <html>
      <body>
        <form action="https://example.com/api/v1/auth/login" method="post">
          <input type="text" name="user" />
        </form>
        <script>
          async function loadData() {
            const res = await fetch('/api/v1/users/list', { method: 'POST' });
            const data = await res.json();
          }
        </script>
      </body>
    </html>
    """
    db.add(
        HTTPResponse(
            page_id=page.id,
            status_code=200,
            final_url="https://example.com/app",
            raw_body=html_body,
        )
    )
    db.commit()

    agent = ApiIntelligenceAgent(db, scan.id)
    endpoints = agent.analyze()

    assert len(endpoints) >= 3

    urls = {ep.url_or_path: ep for ep in endpoints}
    assert "https://example.com/api/v1/auth/login" in urls
    assert urls["https://example.com/api/v1/auth/login"].http_method == "POST"

    assert "https://example.com/api/v1/users/list" in urls
    assert urls["https://example.com/api/v1/users/list"].http_method == "POST"

    assert "https://example.com/api/v1/config.json" in urls
    assert urls["https://example.com/api/v1/config.json"].http_method == "GET"

    # Verify persisted in database
    db_endpoints = db.query(ApiEndpoint).filter(ApiEndpoint.scan_id == scan.id).all()
    assert len(db_endpoints) == len(endpoints)
