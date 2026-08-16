import pytest
from sqlalchemy.orm import Session
from app.models.scan import Website, Scan, Page, HTTPResponse, Resource

def test_phase6_model_fields(db: Session):
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.commit()

    scan = Scan(website_id=website.id, requested_url="https://example.com", state="COMPLETED")
    db.add(scan)
    db.commit()

    page = Page(scan_id=scan.id, canonical_url="https://example.com/", depth=0)
    db.add(page)
    db.commit()

    response = HTTPResponse(
        page_id=page.id,
        status_code=200,
        final_url="https://example.com/",
        raw_body="<html>Static</html>",
        rendered_body="<html>Rendered DOM</html>",
        timing_data={"navigation": {"domComplete": 450}}
    )
    db.add(response)
    db.commit()

    resource = Resource(
        page_id=page.id,
        url="https://example.com/api/data",
        type="fetch",
        capture_source="browser_runtime"

    )
    db.add(resource)
    db.commit()

    saved_resp = db.query(HTTPResponse).filter(HTTPResponse.id == response.id).first()
    assert saved_resp.rendered_body == "<html>Rendered DOM</html>"
    assert saved_resp.timing_data == {"navigation": {"domComplete": 450}}

    saved_res = db.query(Resource).filter(Resource.id == resource.id).first()
    assert saved_res.capture_source == "browser_runtime"
