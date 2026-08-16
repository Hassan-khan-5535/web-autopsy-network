from __future__ import annotations

from uuid import uuid4
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.models.scan import HTTPResponse, Page, PageLink, Scan, Website
from app.services.structure import StructureAgent


def test_structure_agent_hierarchy_and_forms(db: Session):
    website = Website(canonical_origin="example.com")
    db.add(website)
    db.commit()

    scan = Scan(website_id=website.id, requested_url="https://example.com", state="COLLECTING")
    db.add(scan)
    db.commit()

    root_page = Page(scan_id=scan.id, canonical_url="https://example.com/", depth=0, title="Home")
    db.add(root_page)
    db.commit()

    contact_page = Page(
        scan_id=scan.id,
        canonical_url="https://example.com/contact",
        depth=1,
        discovered_from_page_id=root_page.id,
        title="Contact Us",
    )
    db.add(contact_page)
    db.commit()

    # Add page links
    db.add(PageLink(source_page_id=root_page.id, target_url="https://example.com/contact", is_external=False))
    db.add(PageLink(source_page_id=root_page.id, target_url="https://twitter.com/example", is_external=True))
    db.commit()

    # Add HTML response with a form on contact page
    html_body = """
    <html>
      <head><title>Contact Us</title></head>
      <body>
        <h1>Contact Us</h1>
        <form action="/api/submit-contact" method="post">
          <input type="text" name="username" required placeholder="Your Name" />
          <input type="email" name="email" required />
          <textarea name="message"></textarea>
          <button type="submit">Send</button>
        </form>
      </body>
    </html>
    """
    db.add(HTTPResponse(page_id=contact_page.id, status_code=200, final_url="https://example.com/contact", raw_body=html_body))
    db.commit()

    agent = StructureAgent(db, scan.id)
    result = agent.analyze()

    assert "site_tree" in result
    assert "link_summary" in result
    assert "form_inventory" in result
    assert "page_types" in result

    # Check link summary
    assert result["link_summary"]["total_internal_links"] == 1
    assert result["link_summary"]["total_external_links"] == 1

    # Check form inventory
    forms = result["form_inventory"]
    assert len(forms) == 1
    assert forms[0]["action"] == "https://example.com/api/submit-contact"
    assert forms[0]["method"] == "POST"
    assert len(forms[0]["fields"]) == 4

    # Check inferred page types
    types = {item["url"]: item["inferred_type"] for item in result["page_types"]}
    assert types["https://example.com/"] == "homepage"
    assert types["https://example.com/contact"] == "contact_or_form"
