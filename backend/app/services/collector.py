import time
from urllib.parse import urljoin
from uuid import UUID
import httpx
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.models.scan import Scan, Page, HTTPResponse, Header, Resource, Observation
from app.services.admission import AdmissionService, AdmissionError


class HTTPCollectorService:
    MAX_REDIRECTS = 5
    TIMEOUT = 10.0

    @staticmethod
    def collect(db: Session, scan_id: UUID, initial_url: str):
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.state = "COLLECTING"
        db.commit()

        try:
            canonical_url, _ = AdmissionService.validate_and_resolve(initial_url)
        except AdmissionError as e:
            scan.state = "FAILED"
            scan.error_reason = str(e)
            db.commit()
            return

        current_url = canonical_url
        redirect_count = 0

        # We create a single page for this collection since it's single-URL focus
        page = Page(scan_id=scan.id, canonical_url=current_url, depth=0)
        db.add(page)
        db.flush() # get page.id

        try:
            with httpx.Client(timeout=HTTPCollectorService.TIMEOUT) as client:
                while redirect_count <= HTTPCollectorService.MAX_REDIRECTS:
                    start_time = time.perf_counter()
                    
                    try:
                        resp = client.get(current_url, follow_redirects=False)
                    except httpx.RequestError as e:
                        raise AdmissionError(f"Network request failed: {e}")

                    elapsed_ms = (time.perf_counter() - start_time) * 1000

                    # Save HTTP Response
                    http_response = HTTPResponse(
                        page_id=page.id,
                        status_code=resp.status_code,
                        final_url=str(resp.url),
                        content_type=resp.headers.get("content-type"),
                        timings_ms=elapsed_ms
                    )
                    db.add(http_response)
                    db.flush()

                    # Save Headers
                    for name, value in resp.headers.multi_items():
                        db.add(Header(http_response_id=http_response.id, name=name.lower(), value=value))

                    # Save Observation for Status
                    db.add(Observation(
                        scan_id=scan.id,
                        category="HTTP",
                        subject=current_url,
                        observation=f"Returned status code {resp.status_code}",
                        classification="OBSERVED"
                    ))

                    if 300 <= resp.status_code < 400 and "location" in resp.headers:
                        location = resp.headers["location"]
                        next_url = urljoin(current_url, location)
                        
                        db.add(Observation(
                            scan_id=scan.id,
                            category="HTTP",
                            subject=current_url,
                            observation=f"Redirects to {next_url}",
                            classification="OBSERVED"
                        ))

                        # Validate the next hop IP to prevent DNS rebinding or redirect-based SSRF
                        try:
                            next_url, _ = AdmissionService.validate_and_resolve(next_url)
                        except AdmissionError as e:
                            raise AdmissionError(f"Redirect blocked by SSRF policy: {e}")

                        current_url = next_url
                        redirect_count += 1
                        continue
                    
                    # If not a redirect, break the loop
                    # Parse HTML if applicable
                    if resp.headers.get("content-type", "").startswith("text/html"):
                        HTTPCollectorService._parse_html(db, scan.id, page.id, resp.text, current_url)

                    break
                else:
                    raise AdmissionError(f"Exceeded maximum redirects ({HTTPCollectorService.MAX_REDIRECTS})")

            scan.state = "COMPLETED"
            db.commit()

        except Exception as e:
            scan.state = "FAILED"
            scan.error_reason = str(e)
            db.commit()

    @staticmethod
    def _parse_html(db: Session, scan_id: UUID, page_id: UUID, html_content: str, base_url: str):
        soup = BeautifulSoup(html_content, "html.parser")

        # Extract basic structural elements
        tags_to_find = {
            "link": "href",
            "script": "src",
            "img": "src",
            "a": "href",
            "form": "action"
        }

        counts = {tag: 0 for tag in tags_to_find.keys()}

        for tag_name, attr_name in tags_to_find.items():
            elements = soup.find_all(tag_name)
            counts[tag_name] = len(elements)
            for el in elements:
                url_attr = el.get(attr_name)
                # Keep attributes as a simple dict mapping
                attrs_dict = {k: v for k, v in el.attrs.items()}
                db.add(Resource(
                    page_id=page_id,
                    url=urljoin(base_url, url_attr) if url_attr else None,
                    type=tag_name,
                    attributes=attrs_dict
                ))
        
        # Save structural observations
        for tag_name, count in counts.items():
            db.add(Observation(
                scan_id=scan_id,
                category="HTML_STRUCTURE",
                subject=base_url,
                observation=f"Found {count} <{tag_name}> elements",
                classification="OBSERVED"
            ))

