from typing import Any
import uuid
from sqlalchemy.orm import Session
from bs4 import BeautifulSoup

from app.models.scan import Scan, Page, HTTPResponse, AccessibilityFinding

class AccessibilityEngine:
    def __init__(self, db: Session, scan_id: uuid.UUID):
        self.db = db
        self.scan_id = scan_id

    def analyze(self) -> None:
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if not scan:
            return

        for page in scan.pages:
            response = self.db.query(HTTPResponse).filter(HTTPResponse.page_id == page.id).first()
            if not response or (not response.rendered_body and not response.raw_body):
                continue

            html_content = response.rendered_body or response.raw_body
            soup = BeautifulSoup(html_content, "html.parser")
            
            self._check_images(page.id, soup)
            self._check_forms(page.id, soup)
            self._check_headings(page.id, soup)
            self._check_semantics(page.id, soup)
            self._check_aria(page.id, soup)
            
        self._check_untestable()
        self.db.commit()

    def _add_finding(
        self,
        page_id: uuid.UUID | None,
        subject: str,
        statement: str,
        classification: str,
        evidence: list[dict[str, Any]]
    ):
        finding = AccessibilityFinding(
            scan_id=self.scan_id,
            page_id=page_id,
            category="ACCESSIBILITY",
            subject=subject,
            statement=statement,
            classification=classification,
            evidence=evidence
        )
        self.db.add(finding)

    def _check_images(self, page_id: uuid.UUID, soup: BeautifulSoup):
        images = soup.find_all("img")
        missing_alt = []
        for img in images:
            if not img.has_attr("alt"):
                src = img.get("src", "unknown src")
                missing_alt.append(str(img)[:100] + "...")

        if missing_alt:
            self._add_finding(
                page_id=page_id,
                subject="Image Accessibility",
                statement=f"Found {len(missing_alt)} image(s) missing the 'alt' attribute entirely.",
                classification="OBSERVED",
                evidence=[{"type": "html_snippet", "observation": snippet, "source": "DOM"} for snippet in missing_alt]
            )

    def _check_forms(self, page_id: uuid.UUID, soup: BeautifulSoup):
        inputs = soup.find_all(["input", "textarea", "select"])
        unlabeled = []
        for inp in inputs:
            itype = inp.get("type", "").lower()
            if itype in ["hidden", "submit", "button", "reset", "image"]:
                continue
            
            has_label = False
            # Check aria
            if inp.has_attr("aria-label") or inp.has_attr("aria-labelledby") or inp.has_attr("title"):
                has_label = True
            
            # Check implicit label (wrapped)
            if not has_label and inp.find_parent("label"):
                has_label = True
            
            # Check explicit label (for=id)
            inp_id = inp.get("id")
            if not has_label and inp_id:
                label = soup.find("label", attrs={"for": inp_id})
                if label:
                    has_label = True
                    
            if not has_label:
                unlabeled.append(str(inp)[:100] + "...")
                
        if unlabeled:
            self._add_finding(
                page_id=page_id,
                subject="Form Accessibility",
                statement=f"Found {len(unlabeled)} form input(s) without an associated label or ARIA name.",
                classification="OBSERVED",
                evidence=[{"type": "html_snippet", "observation": snippet, "source": "DOM"} for snippet in unlabeled]
            )

    def _check_headings(self, page_id: uuid.UUID, soup: BeautifulSoup):
        headings = soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])
        if not headings:
            return
            
        h1_count = len([h for h in headings if h.name == "h1"])
        if h1_count != 1:
            self._add_finding(
                page_id=page_id,
                subject="Heading Structure",
                statement=f"Page contains {h1_count} <h1> elements. Exactly one is recommended for structural clarity.",
                classification="OBSERVED",
                evidence=[{"type": "count", "observation": f"{h1_count} H1 tags", "source": "DOM"}]
            )
            
        # Check skipped levels
        issues = []
        current_level = 1 # assume start at 1
        for h in headings:
            level = int(h.name[1])
            if level - current_level > 1:
                issues.append(f"Skipped from H{current_level} directly to H{level}")
            current_level = level
            
        if issues:
            self._add_finding(
                page_id=page_id,
                subject="Heading Structure",
                statement="Heading levels are skipped, which likely harms screen-reader navigation.",
                classification="INFERRED",
                evidence=[{"type": "structure_gap", "observation": issue, "source": "DOM"} for issue in issues]
            )

    def _check_semantics(self, page_id: uuid.UUID, soup: BeautifulSoup):
        landmarks = ["main", "nav", "header", "footer", "aside"]
        found = []
        for lm in landmarks:
            if soup.find(lm):
                found.append(lm)
                
        if not found:
            self._add_finding(
                page_id=page_id,
                subject="Semantic Structure",
                statement="No semantic HTML5 landmarks (main, nav, header, footer, aside) were found.",
                classification="OBSERVED",
                evidence=[{"type": "element_search", "observation": "Missing landmark tags", "source": "DOM"}]
            )

    def _check_aria(self, page_id: uuid.UUID, soup: BeautifulSoup):
        # Find aria-hidden="true" on focusable elements
        focusable_selectors = ["a[href]", "button", "input:not([type='hidden'])", "select", "textarea", "[tabindex]"]
        misused = []
        for selector in focusable_selectors:
            elements = soup.select(selector)
            for el in elements:
                if el.get("aria-hidden") == "true":
                    # Check if tabindex is negative
                    if el.get("tabindex") != "-1":
                        misused.append(str(el)[:100] + "...")
                        
        if misused:
            self._add_finding(
                page_id=page_id,
                subject="ARIA Usage",
                statement=f"Found {len(misused)} focusable element(s) with aria-hidden='true', hiding them from screen readers but not keyboard users.",
                classification="OBSERVED",
                evidence=[{"type": "html_snippet", "observation": snippet, "source": "DOM"} for snippet in misused]
            )

    def _check_untestable(self):
        # Keyboard Navigation / Contrast cannot be reliably tested statically
        self._add_finding(
            page_id=None,
            subject="Keyboard Navigation & Color Contrast",
            statement="Keyboard navigability and color contrast ratios require interactive runtime simulation or manual testing.",
            classification="UNKNOWN",
            evidence=[{"type": "system_limitation", "observation": "Static analysis cannot verify focus management or actual rendered CSS contrast without visual bounding boxes.", "source": "Engine Constraint"}]
        )
