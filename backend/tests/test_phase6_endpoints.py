from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.main import app
from app.models.scan import HTTPResponse, Page, Scan, Website

client = TestClient(app)

def test_get_page_rendered_endpoint(db: Session):
    app.dependency_overrides[get_db] = lambda: db

    website = Website(canonical_origin="example.com")
    db.add(website)
    db.commit()

    scan = Scan(website_id=website.id, requested_url="https://example.com", state="COMPLETED")
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
        rendered_body="<html>Rendered</html>",
        timing_data={"navigation": {"domComplete": 250}}
    )
    db.add(resp)
    db.commit()

    res = client.get(f"/v1/scans/{scan.id}/pages/{page.id}/rendered")
    assert res.status_code == 200
    data = res.json()
    assert data["raw_body"] == "<html>Static</html>"
    assert data["rendered_body"] == "<html>Rendered</html>"
    assert data["timing_data"] == {"navigation": {"domComplete": 250}}
