from __future__ import annotations

# Evidence statements intentionally preserve readable, explicit performance language.
# ruff: noqa: E501
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from bs4 import BeautifulSoup
from sqlalchemy.orm import Session

from app.models.scan import (
    Dependency,
    HTTPResponse,
    Page,
    PerformanceMetric,
    Resource,
    Scan,
)

RULE_VERSION = "phase8-v1"
PASSIVE_LIMITATIONS = (
    "Pure computation over persisted Phase 2, 3, and 6 evidence; no new target requests "
    "or browser sessions are issued."
)


class PerformanceEvidenceError(ValueError):
    """Raised when a performance metric or diagnosis lacks required evidence."""


@dataclass(frozen=True)
class MetricCandidate:
    scope: str
    metric_name: str
    value: float | None
    unit: str
    classification: str
    confidence: float
    confidence_band: str
    capture_mode: str
    statement: str
    evidence: tuple[dict[str, Any], ...]
    page_id: Any | None = None
    limitations: str = PASSIVE_LIMITATIONS


@dataclass
class PageAnalysis:
    page: Page
    metrics: list[MetricCandidate]
    blocking_resources: list[dict[str, Any]]
    runtime_resources: list[Resource]
    static_resources: list[Resource]


class PerformanceEngine:
    """Deterministic, passive analysis of persisted performance evidence."""

    RESOURCE_TYPES = {
        "script": "js",
        "stylesheet": "css",
        "link": "css",
        "img": "image",
        "image": "image",
        "source": "image",
        "font": "font",
    }
    SIZE_KEYS = (
        "transfer_size_bytes",
        "encoded_body_size",
        "decoded_body_size",
        "content_length",
        "content-length",
        "size_bytes",
        "bytes",
        "size",
    )

    def __init__(self, db: Session, scan_id: Any) -> None:
        self.db = db
        self.scan_id = scan_id
        self.scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not self.scan:
            raise ValueError("Scan not found")
        self.seed_host = (urlsplit(self.scan.requested_url).hostname or "").lower()
        self.dependencies = {
            dependency.domain.lower(): dependency.category or "Unclassified"
            for dependency in db.query(Dependency).filter(Dependency.scan_id == scan_id).all()
        }

    def analyze(self) -> list[PerformanceMetric]:
        self.db.query(PerformanceMetric).filter(PerformanceMetric.scan_id == self.scan_id).delete(
            synchronize_session=False
        )
        self.db.flush()

        pages = (
            self.db.query(Page)
            .filter(Page.scan_id == self.scan_id)
            .order_by(Page.depth, Page.canonical_url)
            .all()
        )
        page_analyses = [self._analyze_page(page) for page in pages]
        candidates: list[MetricCandidate] = [
            metric for analysis in page_analyses for metric in analysis.metrics
        ]
        candidates.extend(self._site_metrics(page_analyses))
        candidates.extend(self._diagnoses(page_analyses))

        metrics = [self._persist_candidate(candidate) for candidate in candidates]
        self.db.commit()
        return metrics

    def _analyze_page(self, page: Page) -> PageAnalysis:
        response: HTTPResponse | None = page.http_responses[0] if page.http_responses else None
        raw_body = response.raw_body if response and response.raw_body else ""
        soup = BeautifulSoup(raw_body, "html.parser")
        static_resources = [
            resource for resource in page.resources if resource.capture_source != "browser_runtime"
        ]
        runtime_resources = [
            resource for resource in page.resources if resource.capture_source == "browser_runtime"
        ]
        context = {
            "page": page,
            "response": response,
            "raw_body": raw_body,
            "soup": soup,
            "static_resources": static_resources,
            "runtime_resources": runtime_resources,
        }
        blocking_resources = self._blocking_resources(context)
        metrics = self._page_metrics(context, blocking_resources)
        return PageAnalysis(
            page=page,
            metrics=metrics,
            blocking_resources=blocking_resources,
            runtime_resources=runtime_resources,
            static_resources=static_resources,
        )

    def _page_metrics(
        self, context: dict[str, Any], blocking_resources: list[dict[str, Any]]
    ) -> list[MetricCandidate]:
        page: Page = context["page"]
        response: HTTPResponse | None = context["response"]
        raw_body: str = context["raw_body"]
        static_resources: list[Resource] = context["static_resources"]
        runtime_resources: list[Resource] = context["runtime_resources"]
        metrics: list[MetricCandidate] = []
        document_source = response.final_url if response else page.canonical_url
        document_size = len(raw_body.encode("utf-8")) if raw_body else 0
        metrics.append(
            self._observed(
                page=page,
                metric_name="document_size_bytes",
                value=float(document_size),
                unit="bytes",
                capture_mode="static_http",
                statement=f"Captured raw HTML body size was {document_size} bytes for {document_source}.",
                evidence=[
                    self._evidence(
                        "document_body",
                        document_source,
                        f"Captured raw HTML body encoded length: {document_size} bytes.",
                        page.id,
                    )
                ],
            )
        )
        metrics.append(
            self._observed(
                page=page,
                metric_name="static_resource_reference_count",
                value=float(len(static_resources)),
                unit="references",
                capture_mode="static_http",
                statement=f"The stored HTML exposed {len(static_resources)} static resource reference(s).",
                evidence=[
                    self._evidence(
                        "resource_inventory",
                        page.canonical_url,
                        f"Persisted static resource rows: {len(static_resources)}.",
                        page.id,
                    )
                ],
            )
        )
        for resource_type, label in (
            ("script", "script"),
            ("link", "link"),
            ("img", "image"),
            ("font", "font"),
            ("other", "other"),
        ):
            matching = []
            for resource in static_resources:
                raw_type = resource.type.lower() if resource.type else "other"
                if raw_type == resource_type or (
                    resource_type == "other" and raw_type not in {"script", "link", "img", "font"}
                ):
                    matching.append(resource)
            metrics.append(
                self._observed(
                    page=page,
                    metric_name=f"{resource_type}_resource_count",
                    value=float(len(matching)),
                    unit="resources",
                    capture_mode="static_http",
                    statement=f"The stored resource inventory contained {len(matching)} {label} resource reference(s).",
                    evidence=[
                        self._evidence(
                            "resource_inventory",
                            str(resource.url or page.canonical_url),
                            f"Resource classified as {resource_type}.",
                            page.id,
                        )
                        for resource in matching
                    ]
                    or [
                        self._evidence(
                            "resource_inventory",
                            page.canonical_url,
                            f"No stored {label} resource rows were found.",
                            page.id,
                        )
                    ],
                )
            )

        known_sizes_by_type: dict[str, list[tuple[Resource, int]]] = {}
        unknown_sized_by_type: dict[str, list[Resource]] = {}
        for resource in static_resources:
            resource_type = self._resource_type(resource)
            if resource_type not in {"js", "css", "image", "font"}:
                continue
            size = self._resource_size(resource)
            if size is None:
                unknown_sized_by_type.setdefault(resource_type, []).append(resource)
            else:
                known_sizes_by_type.setdefault(resource_type, []).append((resource, size))

        for resource_type, label in (
            ("js", "JS"),
            ("css", "CSS"),
            ("image", "image"),
            ("font", "font"),
        ):
            known = known_sizes_by_type.get(resource_type, [])
            unknown = unknown_sized_by_type.get(resource_type, [])
            all_resources = [resource for resource, _ in known] + unknown
            metric_name = f"{resource_type}_payload_size_bytes"
            if not all_resources:
                metrics.append(
                    self._observed(
                        page=page,
                        metric_name=metric_name,
                        value=0.0,
                        unit="bytes",
                        capture_mode="static_http",
                        statement=f"No {label} resources were present in the stored resource inventory.",
                        evidence=[
                            self._evidence(
                                "resource_inventory",
                                page.canonical_url,
                                f"No stored {label} resource rows were found.",
                                page.id,
                            )
                        ],
                    )
                )
            elif unknown:
                metrics.append(
                    self._unknown(
                        page=page,
                        metric_name=metric_name,
                        unit="bytes",
                        capture_mode="static_http",
                        statement=(
                            f"{label} payload size is UNKNOWN because {len(unknown)} referenced "
                            f"resource(s) had no captured byte-size evidence."
                        ),
                        evidence=[
                            self._evidence(
                                "resource_size_unknown",
                                str(resource.url or page.canonical_url),
                                "No transfer, encoded-body, content-length, or byte-size field was persisted.",
                                page.id,
                            )
                            for resource in unknown
                        ],
                    )
                )
            else:
                total = sum(size for _, size in known)
                metrics.append(
                    self._observed(
                        page=page,
                        metric_name=metric_name,
                        value=float(total),
                        unit="bytes",
                        capture_mode="static_http",
                        statement=f"Captured {label} resource size evidence totals {total} bytes.",
                        evidence=[
                            self._evidence(
                                "resource_size",
                                str(resource.url or page.canonical_url),
                                f"Captured resource size: {size} bytes.",
                                page.id,
                            )
                            for resource, size in known
                        ],
                    )
                )

        metrics.extend(self._request_metrics(page, static_resources, runtime_resources))
        metrics.extend(self._timing_metrics(page, response))
        metrics.append(
            self._observed(
                page=page,
                metric_name="render_blocking_resource_count",
                value=float(len(blocking_resources)),
                unit="resources",
                capture_mode="static_http",
                statement=f"Stored HTML contained {len(blocking_resources)} deterministic render-blocking resource(s) in the document head.",
                evidence=[
                    self._evidence(
                        "blocking_resource",
                        item["source"],
                        item["observation"],
                        page.id,
                    )
                    for item in blocking_resources
                ]
                or [
                    self._evidence(
                        "html_structure",
                        page.canonical_url,
                        "No synchronous head script or blocking stylesheet was observed in stored HTML.",
                        page.id,
                    )
                ],
            )
        )
        for item in blocking_resources:
            metrics.append(
                self._observed(
                    page=page,
                    metric_name="blocking_resource",
                    value=1.0,
                    unit="resource",
                    capture_mode="static_http",
                    statement=item["observation"],
                    evidence=[
                        self._evidence(
                            "blocking_resource",
                            item["source"],
                            item["observation"],
                            page.id,
                        )
                    ],
                )
            )
        return metrics

    def _request_metrics(
        self, page: Page, static_resources: list[Resource], runtime_resources: list[Resource]
    ) -> list[MetricCandidate]:
        metrics: list[MetricCandidate] = []
        runtime_count = len(runtime_resources)
        if runtime_count:
            metrics.append(
                self._observed(
                    page=page,
                    metric_name="request_count",
                    value=float(runtime_count),
                    unit="requests",
                    capture_mode="browser_runtime",
                    statement=f"Browser runtime evidence captured {runtime_count} network request resource(s).",
                    evidence=[
                        self._evidence(
                            "browser_network_request",
                            str(resource.url or page.canonical_url),
                            "Resource persisted with capture_source=browser_runtime.",
                            page.id,
                        )
                        for resource in runtime_resources
                    ],
                )
            )
        else:
            metrics.append(
                self._unknown(
                    page=page,
                    metric_name="request_count",
                    unit="requests",
                    capture_mode="browser_runtime",
                    statement="Actual request count is UNKNOWN because no browser runtime network evidence was persisted for this page.",
                    evidence=[
                        self._evidence(
                            "browser_network_coverage",
                            page.canonical_url,
                            "No Resource rows with capture_source=browser_runtime were persisted.",
                            page.id,
                        )
                    ],
                )
            )
        metrics.append(
            self._observed(
                page=page,
                metric_name="first_party_static_reference_count",
                value=float(
                    sum(not self._is_external(resource.url) for resource in static_resources)
                ),
                unit="references",
                capture_mode="static_http",
                statement="Static first-party resource references were counted from stored HTML resource rows.",
                evidence=[
                    self._evidence(
                        "resource_inventory",
                        str(resource.url or page.canonical_url),
                        f"Resource classified as {'first-party' if not self._is_external(resource.url) else 'third-party'} by hostname comparison.",
                        page.id,
                    )
                    for resource in static_resources
                ]
                or [
                    self._evidence(
                        "resource_inventory",
                        page.canonical_url,
                        "No static resource rows were persisted.",
                        page.id,
                    )
                ],
            )
        )
        external_static = [
            resource for resource in static_resources if self._is_external(resource.url)
        ]
        known_external_sizes = [
            (resource, size)
            for resource in external_static
            if (size := self._resource_size(resource)) is not None
        ]
        if not external_static:
            metrics.append(
                self._observed(
                    page=page,
                    metric_name="third_party_payload_size_bytes",
                    value=0.0,
                    unit="bytes",
                    capture_mode="static_http",
                    statement="No third-party static resource references were observed.",
                    evidence=[
                        self._evidence(
                            "resource_inventory",
                            page.canonical_url,
                            "No external-host resource rows were persisted.",
                            page.id,
                        )
                    ],
                )
            )
        elif len(known_external_sizes) == len(external_static):
            total_external = sum(size for _, size in known_external_sizes)
            metrics.append(
                self._observed(
                    page=page,
                    metric_name="third_party_payload_size_bytes",
                    value=float(total_external),
                    unit="bytes",
                    capture_mode="static_http",
                    statement=f"Third-party static resource size evidence totals {total_external} bytes.",
                    evidence=[
                        self._evidence(
                            "third_party_resource_size",
                            str(resource.url),
                            f"Captured third-party resource size: {size} bytes.",
                            page.id,
                        )
                        for resource, size in known_external_sizes
                    ],
                )
            )
        else:
            metrics.append(
                self._unknown(
                    page=page,
                    metric_name="third_party_payload_size_bytes",
                    unit="bytes",
                    capture_mode="static_http",
                    statement="Third-party payload size is UNKNOWN because one or more external resource sizes were not captured.",
                    evidence=[
                        self._evidence(
                            "third_party_resource_inventory",
                            str(resource.url or page.canonical_url),
                            "External resource was observed but its byte size was not persisted.",
                            page.id,
                        )
                        for resource in external_static
                    ],
                )
            )
        if runtime_count:
            external_runtime = [
                resource for resource in runtime_resources if self._is_external(resource.url)
            ]
            metrics.append(
                self._observed(
                    page=page,
                    metric_name="third_party_request_count",
                    value=float(len(external_runtime)),
                    unit="requests",
                    capture_mode="browser_runtime",
                    statement=f"Browser runtime evidence contained {len(external_runtime)} third-party request(s).",
                    evidence=[
                        self._evidence(
                            "third_party_network_request",
                            str(resource.url or page.canonical_url),
                            "Runtime resource classified as third-party by hostname comparison.",
                            page.id,
                        )
                        for resource in external_runtime
                    ]
                    or [
                        self._evidence(
                            "third_party_network_request",
                            page.canonical_url,
                            "No third-party runtime requests were observed.",
                            page.id,
                        )
                    ],
                )
            )
        else:
            metrics.append(
                self._unknown(
                    page=page,
                    metric_name="third_party_request_count",
                    unit="requests",
                    capture_mode="browser_runtime",
                    statement="Third-party request count is UNKNOWN because browser runtime network evidence was unavailable.",
                    evidence=[
                        self._evidence(
                            "browser_network_coverage",
                            page.canonical_url,
                            "No browser runtime request rows were persisted.",
                            page.id,
                        )
                    ],
                )
            )
        return metrics

    def _timing_metrics(self, page: Page, response: HTTPResponse | None) -> list[MetricCandidate]:
        metrics: list[MetricCandidate] = []
        if response and response.timings_ms is not None:
            metrics.append(
                self._observed(
                    page=page,
                    metric_name="ttfb_ms",
                    value=float(response.timings_ms),
                    unit="ms",
                    capture_mode="static_http",
                    statement=f"HTTP collector response timing was {response.timings_ms} ms.",
                    evidence=[
                        self._evidence(
                            "http_timing",
                            response.final_url,
                            f"Persisted HTTPResponse.timings_ms={response.timings_ms}.",
                            page.id,
                        )
                    ],
                )
            )
        else:
            metrics.append(
                self._unknown(
                    page=page,
                    metric_name="ttfb_ms",
                    unit="ms",
                    capture_mode="static_http",
                    statement="TTFB is UNKNOWN because no HTTP collector timing was persisted.",
                    evidence=[
                        self._evidence(
                            "http_timing_coverage",
                            page.canonical_url,
                            "HTTPResponse.timings_ms was absent.",
                            page.id,
                        )
                    ],
                )
            )

        timing_data = response.timing_data if response else None
        navigation = timing_data.get("navigation", {}) if isinstance(timing_data, dict) else {}
        metrics.extend(
            [
                self._browser_timing_metric(
                    page,
                    "page_load_time_ms",
                    navigation.get("loadEventEnd"),
                    "loadEventEnd",
                    "Page load time",
                ),
                self._browser_timing_metric(
                    page,
                    "dom_interactive_ms",
                    navigation.get("domInteractive"),
                    "domInteractive",
                    "DOM interactive time",
                ),
                self._browser_timing_metric(
                    page,
                    "dom_complete_ms",
                    navigation.get("domComplete"),
                    "domComplete",
                    "DOM complete time",
                ),
            ]
        )
        metrics.append(
            self._unknown(
                page=page,
                metric_name="dom_content_loaded_ms",
                unit="ms",
                capture_mode="browser_runtime",
                statement="DOMContentLoaded timing is UNKNOWN because the browser worker did not persist that timing mark.",
                evidence=[
                    self._evidence(
                        "browser_timing_coverage",
                        page.canonical_url,
                        "Persisted timing contract exposes domInteractive, domComplete, and loadEventEnd but not domContentLoaded.",
                        page.id,
                    )
                ],
            )
        )
        return metrics

    def _browser_timing_metric(
        self,
        page: Page,
        metric_name: str,
        value: Any,
        timing_key: str,
        label: str,
    ) -> MetricCandidate:
        if isinstance(value, int | float) and value > 0:
            return self._observed(
                page=page,
                metric_name=metric_name,
                value=float(value),
                unit="ms",
                capture_mode="browser_runtime",
                statement=f"{label} was {value} ms in persisted browser navigation timing.",
                evidence=[
                    self._evidence(
                        "browser_navigation_timing",
                        page.canonical_url,
                        f"Persisted navigation.{timing_key}={value}.",
                        page.id,
                    )
                ],
            )
        return self._unknown(
            page=page,
            metric_name=metric_name,
            unit="ms",
            capture_mode="browser_runtime",
            statement=f"{label} is UNKNOWN because persisted browser timing did not contain a positive {timing_key} value.",
            evidence=[
                self._evidence(
                    "browser_timing_coverage",
                    page.canonical_url,
                    f"Persisted navigation.{timing_key} was absent, zero, or unavailable.",
                    page.id,
                )
            ],
        )

    def _blocking_resources(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        page: Page = context["page"]
        soup: BeautifulSoup = context["soup"]
        blockers: list[dict[str, Any]] = []
        head = soup.find("head")
        if not head:
            return blockers
        for script in head.find_all("script", src=True):
            if not script.has_attr("async") and not script.has_attr("defer"):
                url = str(script.get("src"))
                blockers.append(
                    {
                        "source": f"{page.canonical_url}#script:{url}",
                        "observation": f"Synchronous head script `{url}` lacks async and defer attributes and is render-blocking by static rule.",
                    }
                )
        for link in head.find_all("link", href=True):
            rel = {str(value).lower() for value in link.get("rel", [])}
            if "stylesheet" in rel:
                url = str(link.get("href"))
                blockers.append(
                    {
                        "source": f"{page.canonical_url}#stylesheet:{url}",
                        "observation": f"Head stylesheet `{url}` is render-blocking by static rule.",
                    }
                )
        return blockers

    def _site_metrics(self, page_analyses: list[PageAnalysis]) -> list[MetricCandidate]:
        if not page_analyses:
            return []
        metrics: list[MetricCandidate] = []
        page_metric_map = {
            analysis.page.id: {metric.metric_name: metric for metric in analysis.metrics}
            for analysis in page_analyses
        }
        document_metrics = [
            page_metric_map[analysis.page.id]["document_size_bytes"] for analysis in page_analyses
        ]
        metrics.append(
            self._site_observed(
                metric_name="site_total_document_size_bytes",
                value=sum(metric.value or 0 for metric in document_metrics),
                unit="bytes",
                statement=f"Captured document bodies total {sum(metric.value or 0 for metric in document_metrics)} bytes across {len(page_analyses)} page(s).",
                evidence=self._metric_evidence(document_metrics),
            )
        )
        metrics.append(
            self._site_observed(
                metric_name="site_average_document_size_bytes",
                value=sum(metric.value or 0 for metric in document_metrics) / len(document_metrics),
                unit="bytes",
                statement="Average captured document body size was computed from every crawled page.",
                evidence=self._metric_evidence(document_metrics),
            )
        )
        static_counts = [
            page_metric_map[analysis.page.id]["static_resource_reference_count"]
            for analysis in page_analyses
        ]
        metrics.append(
            self._site_observed(
                metric_name="site_total_static_resource_reference_count",
                value=sum(metric.value or 0 for metric in static_counts),
                unit="references",
                statement=f"Stored HTML exposed {sum(metric.value or 0 for metric in static_counts)} static resource references across the crawl.",
                evidence=self._metric_evidence(static_counts),
            )
        )
        for resource_type, label in (
            ("js", "JS"),
            ("css", "CSS"),
            ("image", "image"),
            ("font", "font"),
        ):
            payload_metrics = [
                page_metric_map[analysis.page.id][f"{resource_type}_payload_size_bytes"]
                for analysis in page_analyses
            ]
            known_payloads = [metric for metric in payload_metrics if metric.value is not None]
            if len(known_payloads) == len(payload_metrics):
                total_payload = sum(metric.value or 0 for metric in known_payloads)
                metrics.append(
                    self._site_observed(
                        metric_name=f"site_total_{resource_type}_payload_size_bytes",
                        value=total_payload,
                        unit="bytes",
                        statement=f"Captured {label} payload evidence totals {total_payload:.0f} bytes across the crawl.",
                        evidence=self._metric_evidence(known_payloads),
                    )
                )
            else:
                metrics.append(
                    self._site_unknown(
                        metric_name=f"site_total_{resource_type}_payload_size_bytes",
                        unit="bytes",
                        statement=f"Total {label} payload is UNKNOWN because at least one page lacked captured resource-size evidence.",
                        evidence=self._metric_evidence(payload_metrics),
                    )
                )

        for metric_name, label in (
            ("request_count", "browser request"),
            ("page_load_time_ms", "page load time"),
        ):
            values = [
                page_metric_map[analysis.page.id][metric_name]
                for analysis in page_analyses
                if page_metric_map[analysis.page.id][metric_name].value is not None
            ]
            if values:
                metrics.append(
                    self._site_derived(
                        metric_name=f"site_average_{metric_name}",
                        value=sum(metric.value or 0 for metric in values) / len(values),
                        unit=values[0].unit,
                        statement=f"Average {label} was computed across {len(values)} page(s) with captured values; {len(page_analyses) - len(values)} page(s) remain UNKNOWN.",
                        evidence=self._metric_evidence(values),
                        limitations=(
                            PASSIVE_LIMITATIONS
                            + f" {len(page_analyses) - len(values)} page(s) lacked this captured metric."
                            if len(values) != len(page_analyses)
                            else PASSIVE_LIMITATIONS
                        ),
                    )
                )
            else:
                metrics.append(
                    self._site_unknown(
                        metric_name=f"site_average_{metric_name}",
                        unit="requests" if metric_name == "request_count" else "ms",
                        statement=f"Average {label} is UNKNOWN because no page contained captured browser values.",
                        evidence=[
                            self._evidence(
                                "coverage",
                                self.scan.requested_url,
                                f"No page contained a persisted {metric_name} value.",
                                None,
                            )
                        ],
                    )
                )
        return metrics

    def _diagnoses(self, page_analyses: list[PageAnalysis]) -> list[MetricCandidate]:
        findings: list[MetricCandidate] = []
        for analysis in page_analyses:
            page_metrics = {metric.metric_name: metric for metric in analysis.metrics}
            js_metric = page_metrics.get("js_payload_size_bytes")
            # A captured JS payload >200 KB is a deterministic large-payload concern.
            if js_metric and js_metric.value is not None and js_metric.value >= 200_000:
                findings.append(
                    self._inferred(
                        scope="page",
                        page_id=analysis.page.id,
                        metric_name="diagnosis:large_js_payload",
                        value=js_metric.value,
                        unit="bytes",
                        statement=f"JS payload of {js_metric.value:.0f} bytes is likely a primary contributor to page weight based on captured resource sizes.",
                        evidence=self._metric_evidence([js_metric])
                        + self._resource_evidence(analysis, "js"),
                    )
                )
            # More than five synchronous head resources is the render-blocking concern threshold.
            if len(analysis.blocking_resources) > 5:
                findings.append(
                    self._inferred(
                        scope="page",
                        page_id=analysis.page.id,
                        metric_name="diagnosis:render_blocking_resources",
                        value=float(len(analysis.blocking_resources)),
                        unit="resources",
                        statement=f"{len(analysis.blocking_resources)} render-blocking resource(s) were identified in the stored head and may delay rendering.",
                        evidence=[
                            self._evidence(
                                "blocking_resource",
                                item["source"],
                                item["observation"],
                                analysis.page.id,
                            )
                            for item in analysis.blocking_resources
                        ],
                    )
                )
            request_metric = page_metrics.get("request_count")
            third_party_metric = page_metrics.get("third_party_request_count")
            if (
                request_metric
                and third_party_metric
                and request_metric.value
                and third_party_metric.value is not None
                # A third-party share above 50% with at least two requests is high overhead.
                and third_party_metric.value / request_metric.value > 0.5
                and third_party_metric.value >= 2
            ):
                ratio = third_party_metric.value / request_metric.value * 100
                findings.append(
                    self._inferred(
                        scope="page",
                        page_id=analysis.page.id,
                        metric_name="diagnosis:third_party_request_overhead",
                        value=ratio,
                        unit="percent",
                        statement=f"Third-party requests account for {ratio:.1f}% of captured browser requests, a disproportionate request overhead.",
                        evidence=self._metric_evidence([request_metric, third_party_metric])
                        + self._resource_evidence(analysis, "third_party"),
                    )
                )
                category_resources: dict[str, list[Resource]] = {}
                for resource in analysis.runtime_resources:
                    if self._is_external(resource.url):
                        category_resources.setdefault(
                            self._dependency_category(resource.url), []
                        ).append(resource)
                for category, resources in category_resources.items():
                    if len(resources) / request_metric.value > 0.5 and len(resources) >= 2:
                        category_ratio = len(resources) / request_metric.value * 100
                        category_slug = category.lower().replace(" ", "_")
                        findings.append(
                            self._inferred(
                                scope="page",
                                page_id=analysis.page.id,
                                metric_name=f"diagnosis:third_party_category_overhead:{category_slug}",
                                value=category_ratio,
                                unit="percent",
                                statement=f"Dependency category {category} accounts for {category_ratio:.1f}% of captured browser requests and is a disproportionate third-party category overhead.",
                                evidence=self._resource_evidence(analysis, "third_party")
                                + [
                                    self._evidence(
                                        "dependency_category",
                                        str(resource.url or analysis.page.canonical_url),
                                        f"Persisted dependency category: {category}.",
                                        analysis.page.id,
                                    )
                                    for resource in resources
                                ],
                            )
                        )
        return findings

    def _persist_candidate(self, candidate: MetricCandidate) -> PerformanceMetric:
        self._validate_candidate(candidate)
        metric = PerformanceMetric(
            scan_id=self.scan_id,
            page_id=candidate.page_id,
            scope=candidate.scope,
            metric_name=candidate.metric_name,
            value=candidate.value,
            unit=candidate.unit,
            classification=candidate.classification,
            confidence=candidate.confidence,
            confidence_band=candidate.confidence_band,
            capture_mode=candidate.capture_mode,
            statement=candidate.statement,
            evidence=[dict(item) for item in candidate.evidence],
            limitations=candidate.limitations,
        )
        self.db.add(metric)
        self.db.flush()
        return metric

    @staticmethod
    def _validate_candidate(candidate: MetricCandidate) -> None:
        if candidate.classification not in {"OBSERVED", "INFERRED", "UNKNOWN"}:
            raise PerformanceEvidenceError("Performance classification is invalid.")
        if not candidate.metric_name or not candidate.statement.strip():
            raise PerformanceEvidenceError("Performance metric requires a name and statement.")
        if not candidate.evidence:
            raise PerformanceEvidenceError("Performance metric rejected: evidence list is empty.")
        if not 0 <= candidate.confidence <= 100:
            raise PerformanceEvidenceError("Performance confidence must be between 0 and 100.")
        if candidate.classification == "INFERRED" and not RULE_VERSION:
            raise PerformanceEvidenceError("Inferred performance metric requires a rule version.")
        for item in candidate.evidence:
            if not item.get("id") or not item.get("type") or not item.get("source"):
                raise PerformanceEvidenceError(
                    "Performance evidence requires id, type, and source."
                )
            if not item.get("observation"):
                raise PerformanceEvidenceError("Performance evidence requires an observation.")

    def _resource_type(self, resource: Resource) -> str:
        if resource.type == "link":
            attributes = resource.attributes or {}
            rel = attributes.get("rel", []) if isinstance(attributes, dict) else []
            if isinstance(rel, str):
                rel = [rel]
            if "stylesheet" in {str(item).lower() for item in rel}:
                return "css"
        return self.RESOURCE_TYPES.get(resource.type, "other")

    def _resource_size(self, resource: Resource) -> int | None:
        attributes = resource.attributes or {}
        if not isinstance(attributes, dict):
            return None
        for key in self.SIZE_KEYS:
            value = attributes.get(key)
            if isinstance(value, bool):
                continue
            if isinstance(value, int | float) and value >= 0:
                return int(value)
            if isinstance(value, str):
                try:
                    parsed = int(float(value.strip()))
                except ValueError:
                    continue
                if parsed >= 0:
                    return parsed
        return None

    def _is_external(self, url: str | None) -> bool:
        hostname = (urlsplit(url or "").hostname or "").lower()
        return bool(hostname and self.seed_host and hostname != self.seed_host)

    def _dependency_category(self, url: str | None) -> str:
        hostname = (urlsplit(url or "").hostname or "").lower()
        return self.dependencies.get(hostname, "Unclassified")

    def _resource_evidence(self, analysis: PageAnalysis, kind: str) -> list[dict[str, Any]]:
        resources = analysis.static_resources
        if kind == "js":
            resources = [
                resource for resource in resources if self._resource_type(resource) == "js"
            ]
        elif kind == "third_party":
            resources = [
                resource
                for resource in analysis.runtime_resources
                if self._is_external(resource.url)
            ]
        return [
            self._evidence(
                "resource_reference",
                str(resource.url or analysis.page.canonical_url),
                f"Resource type={self._resource_type(resource)}; capture_source={resource.capture_source}; dependency_category={self._dependency_category(resource.url)}.",
                analysis.page.id,
            )
            for resource in resources
        ] or [
            self._evidence(
                "resource_coverage",
                analysis.page.canonical_url,
                "No matching resource rows were persisted beyond the cited metric evidence.",
                analysis.page.id,
            )
        ]

    @staticmethod
    def _metric_evidence(metrics: list[MetricCandidate]) -> list[dict[str, Any]]:
        evidence: list[dict[str, Any]] = []
        for metric in metrics:
            evidence.extend(dict(item) for item in metric.evidence)
        return evidence

    def _observed(
        self,
        *,
        page: Page,
        metric_name: str,
        value: float,
        unit: str,
        capture_mode: str,
        statement: str,
        evidence: list[dict[str, Any]],
    ) -> MetricCandidate:
        return MetricCandidate(
            scope="page",
            metric_name=metric_name,
            value=value,
            unit=unit,
            classification="OBSERVED",
            confidence=100,
            confidence_band="high",
            capture_mode=capture_mode,
            statement=statement,
            evidence=tuple(evidence),
            page_id=page.id,
        )

    def _unknown(
        self,
        *,
        page: Page,
        metric_name: str,
        unit: str,
        capture_mode: str,
        statement: str,
        evidence: list[dict[str, Any]],
    ) -> MetricCandidate:
        return MetricCandidate(
            scope="page",
            metric_name=metric_name,
            value=None,
            unit=unit,
            classification="UNKNOWN",
            confidence=0,
            confidence_band="unknown",
            capture_mode=capture_mode,
            statement=statement,
            evidence=tuple(evidence),
            page_id=page.id,
        )

    def _site_observed(
        self,
        *,
        metric_name: str,
        value: float,
        unit: str,
        statement: str,
        evidence: list[dict[str, Any]],
    ) -> MetricCandidate:
        return MetricCandidate(
            scope="site",
            metric_name=metric_name,
            value=value,
            unit=unit,
            classification="OBSERVED",
            confidence=100,
            confidence_band="high",
            capture_mode="derived",
            statement=statement,
            evidence=tuple(evidence),
        )

    def _site_unknown(
        self,
        *,
        metric_name: str,
        unit: str,
        statement: str,
        evidence: list[dict[str, Any]],
    ) -> MetricCandidate:
        return MetricCandidate(
            scope="site",
            metric_name=metric_name,
            value=None,
            unit=unit,
            classification="UNKNOWN",
            confidence=0,
            confidence_band="unknown",
            capture_mode="derived",
            statement=statement,
            evidence=tuple(evidence),
        )

    def _site_derived(
        self,
        *,
        metric_name: str,
        value: float,
        unit: str,
        statement: str,
        evidence: list[dict[str, Any]],
        limitations: str,
    ) -> MetricCandidate:
        return MetricCandidate(
            scope="site",
            metric_name=metric_name,
            value=value,
            unit=unit,
            classification="INFERRED",
            confidence=100,
            confidence_band="high",
            capture_mode="derived",
            statement=statement,
            evidence=tuple(evidence),
            limitations=limitations,
        )

    def _inferred(
        self,
        *,
        scope: str,
        page_id: Any,
        metric_name: str,
        value: float,
        unit: str,
        statement: str,
        evidence: list[dict[str, Any]],
    ) -> MetricCandidate:
        return MetricCandidate(
            scope=scope,
            metric_name=metric_name,
            value=value,
            unit=unit,
            classification="INFERRED",
            confidence=80,
            confidence_band="high",
            capture_mode="derived",
            statement=statement,
            evidence=tuple(evidence),
            page_id=page_id,
        )

    @staticmethod
    def _evidence(
        evidence_type: str, source: str, observation: str, page_id: Any | None
    ) -> dict[str, Any]:
        return {
            "id": str(uuid4()),
            "type": evidence_type,
            "source": source,
            "observation": observation[:2000],
            "page_id": str(page_id) if page_id else None,
            "captured_at": datetime.now(UTC).isoformat(),
        }


__all__ = ["MetricCandidate", "PerformanceEngine", "PerformanceEvidenceError"]
