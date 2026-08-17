import re
import uuid
from collections import defaultdict
from typing import Any

from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.models.scan import ContentFinding, HTTPResponse, Page, PageLink, Scan


class ContentEngine:
    def __init__(self, db: Session, scan_id: uuid.UUID):
        self.db = db
        self.scan_id = scan_id

    def analyze(self) -> None:
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            return

        titles_map = defaultdict(list)
        descriptions_map = defaultdict(list)

        pages = {page.canonical_url: page for page in scan.pages}

        for page in scan.pages:
            response = self.db.query(HTTPResponse).filter(HTTPResponse.page_id == page.id).first()
            if not response or (not response.rendered_body and not response.raw_body):
                continue

            html_content = response.rendered_body or response.raw_body
            soup = BeautifulSoup(html_content, "html.parser")
            
            self._check_metadata(page.id, soup, titles_map, descriptions_map)
            self._check_headings_seo(page.id, soup)
            self._check_content_metrics(page.id, soup)
            self._check_broken_links(page, pages)
            
        self._check_duplicates(titles_map, descriptions_map)
        self.db.commit()

    def _add_finding(
        self,
        page_id: uuid.UUID | None,
        subject: str,
        statement: str,
        classification: str,
        evidence: list[dict[str, Any]]
    ):
        finding = ContentFinding(
            scan_id=self.scan_id,
            page_id=page_id,
            category="CONTENT",
            subject=subject,
            statement=statement,
            classification=classification,
            evidence=evidence
        )
        self.db.add(finding)

    def _check_metadata(self, page_id: uuid.UUID, soup: BeautifulSoup, titles_map: dict, descriptions_map: dict):
        issues = []
        
        # Title
        title = soup.find("title")
        title_text = title.string.strip() if title and title.string else ""
        if not title_text:
            issues.append({"type": "missing_tag", "observation": "Missing or empty <title> tag.", "source": "DOM"})
        else:
            titles_map[title_text.lower()].append(page_id)
            if len(title_text) < 10 or len(title_text) > 70:
                issues.append({"type": "length_warning", "observation": f"Title length ({len(title_text)} chars) is outside optimal 10-70 range. Title: {title_text}", "source": "DOM"})

        # Description
        desc = soup.find("meta", attrs={"name": "description"})
        desc_text = desc.get("content", "").strip() if desc else ""
        if not desc_text:
            issues.append({"type": "missing_tag", "observation": "Missing <meta name='description'>.", "source": "DOM"})
        else:
            descriptions_map[desc_text.lower()].append(page_id)
            if len(desc_text) < 50 or len(desc_text) > 160:
                issues.append({"type": "length_warning", "observation": f"Meta description length ({len(desc_text)} chars) is outside optimal 50-160 range. Desc: {desc_text}", "source": "DOM"})

        # Canonical
        canonical = soup.find("link", attrs={"rel": "canonical"})
        if not canonical or not canonical.get("href"):
            issues.append({"type": "missing_tag", "observation": "Missing canonical tag.", "source": "DOM"})

        # Lang
        html = soup.find("html")
        if not html or not html.get("lang"):
            issues.append({"type": "missing_tag", "observation": "Missing 'lang' attribute on <html>.", "source": "DOM"})

        # OpenGraph
        og_title = soup.find("meta", attrs={"property": "og:title"})
        if not og_title:
            issues.append({"type": "missing_tag", "observation": "Missing og:title tag.", "source": "DOM"})

        if issues:
            self._add_finding(
                page_id=page_id,
                subject="Metadata Analysis",
                statement=f"Found {len(issues)} SEO metadata issue(s).",
                classification="OBSERVED",
                evidence=issues
            )

    def _check_headings_seo(self, page_id: uuid.UUID, soup: BeautifulSoup):
        headings = soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
        if not headings:
            return
            
        h1_count = len([h for h in headings if h.name == "h1"])
        if h1_count == 0:
            self._add_finding(
                page_id=page_id,
                subject="Heading SEO",
                statement="Missing <h1> tag, impacting SEO hierarchy.",
                classification="OBSERVED",
                evidence=[{"type": "missing_tag", "observation": "No H1 tags found", "source": "DOM"}]
            )

    def _check_content_metrics(self, page_id: uuid.UUID, soup: BeautifulSoup):
        # Word count
        text = soup.get_text(separator=" ", strip=True)
        words = re.findall(r'\b\w+\b', text)
        word_count = len(words)
        
        self._add_finding(
            page_id=page_id,
            subject="Word Count & Language",
            statement=f"Visible word count is {word_count}.",
            classification="OBSERVED",
            evidence=[{"type": "metric", "observation": f"{word_count} words", "source": "DOM text extraction"}]
        )

    def _check_broken_links(self, page: Page, pages: dict):
        links = self.db.query(PageLink).filter(PageLink.source_page_id == page.id, PageLink.is_external == False).all()
        broken = []
        for link in links:
            target = link.target_url
            if target in pages:
                status = pages[target].status_code
                if status and status >= 400:
                    broken.append({"url": target, "status": status})
            
        if broken:
            self._add_finding(
                page_id=page.id,
                subject="Internal Broken Links",
                statement=f"Found {len(broken)} internal link(s) pointing to error pages.",
                classification="OBSERVED",
                evidence=[{"type": "broken_link", "observation": f"Link to {b['url']} returned {b['status']}", "source": "Crawl Data"} for b in broken]
            )

    def _check_duplicates(self, titles_map: dict, descriptions_map: dict):
        duplicate_titles = {k: v for k, v in titles_map.items() if len(v) > 1 and k != ""}
        for title, pages in duplicate_titles.items():
            self._add_finding(
                page_id=None,
                subject="Duplicate Content (Title)",
                statement=f"Found identical title across {len(pages)} pages.",
                classification="INFERRED",
                evidence=[{"type": "duplicate", "observation": f"Title: '{title}' shared by {len(pages)} pages.", "source": "Metadata extraction"}]
            )
            
        duplicate_descs = {k: v for k, v in descriptions_map.items() if len(v) > 1 and k != ""}
        for desc, pages in duplicate_descs.items():
            self._add_finding(
                page_id=None,
                subject="Duplicate Content (Meta Description)",
                statement=f"Found identical meta description across {len(pages)} pages.",
                classification="INFERRED",
                evidence=[{"type": "duplicate", "observation": f"Description: '{desc}' shared by {len(pages)} pages.", "source": "Metadata extraction"}]
            )
