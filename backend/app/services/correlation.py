"""Deterministic, evidence-backed Correlation Agent for Extension 10.

The agent correlates already-persisted observations only. It does not make network
requests, attempt authentication, submit forms, generate payloads, or infer proof
of exploitability from graph connectivity.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.scan import (
    ApiEndpoint,
    AttackSurfaceGraphEdge,
    AttackSurfaceGraphNode,
    AttackSurfaceGraphUpdate,
    Dependency,
    EvidenceReview,
    HTTPObservation,
    Page,
    ReconAsset,
    ReconEndpoint,
    ReconParameter,
    Scan,
    SecurityFinding,
    Technology,
    TechnologyCVEMatch,
)

CORRELATION_VERSION = "extension10-v1"
ENTITY_TYPES = {
    "Domain", "Host", "Service", "Technology", "Application", "Endpoint",
    "API", "Parameter", "Authentication Boundary", "Finding", "Evidence", "Cloud Asset",
}
RELATIONSHIP_TYPES = {
    "OWNS", "ASSOCIATED_WITH", "EXPOSES", "DEPENDS_ON", "SHARES_CONFIGURATION_WITH",
    "AFFECTS", "DUPLICATES", "RELATED_VULNERABILITY", "HAS_EVIDENCE", "POTENTIAL_ESCALATION_PRIORITY",
}
PRIORITY_SEVERITIES = {"critical", "high"}
SAFE_SHARED_CONFIGURATION_SUBJECTS = {"server", "x-powered-by", "strict-transport-security", "content-security-policy"}


def utc_now() -> datetime:
    return datetime.now(UTC)


class CorrelationAgent:
    """Build and incrementally refresh an investigation graph from persisted evidence."""

    def __init__(self, db: Session, scan_id: UUID):
        self.db = db
        self.scan_id = scan_id
        self._nodes: dict[tuple[str, str], AttackSurfaceGraphNode] = {}
        self._stats = Counter()

    def analyze(self, source_event: str = "task:correlation") -> dict[str, Any]:
        scan = self.db.query(Scan).filter(Scan.id == self.scan_id).first()
        if scan is None:
            raise ValueError("Scan not found")
        self._stats = Counter()
        self._nodes = {
            (node.entity_type, node.natural_key): node
            for node in self.db.query(AttackSurfaceGraphNode).filter(AttackSurfaceGraphNode.scan_id == self.scan_id).all()
        }

        application, host, domain = self._seed_scan_identity(scan)
        page_nodes = self._correlate_pages(application)
        endpoint_nodes = self._correlate_recon(application, host, page_nodes)
        self._correlate_api_endpoints(application, host, endpoint_nodes)
        technology_nodes = self._correlate_technologies(application)
        self._correlate_dependencies(application, domain)
        self._correlate_observations(application, page_nodes)
        finding_nodes = self._correlate_findings(application, page_nodes)
        self._correlate_evidence_reviews(finding_nodes)
        self._correlate_cve_matches(technology_nodes)
        self._correlate_duplicate_findings(finding_nodes)
        self._correlate_shared_configuration(page_nodes)
        self._correlate_priority_paths(application, page_nodes, finding_nodes)

        summary = self._summary()
        update = AttackSurfaceGraphUpdate(
            scan_id=self.scan_id,
            source_event=source_event[:120],
            correlation_version=CORRELATION_VERSION,
            inserted_node_count=self._stats["inserted_nodes"],
            refreshed_node_count=self._stats["refreshed_nodes"],
            inserted_edge_count=self._stats["inserted_edges"],
            refreshed_edge_count=self._stats["refreshed_edges"],
            summary=summary,
        )
        self.db.add(update)
        self.db.commit()
        return {
            "source_event": update.source_event,
            "update_id": str(update.id),
            "inserted_node_count": update.inserted_node_count,
            "refreshed_node_count": update.refreshed_node_count,
            "inserted_edge_count": update.inserted_edge_count,
            "refreshed_edge_count": update.refreshed_edge_count,
            "summary": summary,
        }

    def report(self) -> dict[str, Any]:
        nodes = (
            self.db.query(AttackSurfaceGraphNode)
            .filter(AttackSurfaceGraphNode.scan_id == self.scan_id)
            .order_by(AttackSurfaceGraphNode.entity_type, AttackSurfaceGraphNode.label)
            .all()
        )
        edges = (
            self.db.query(AttackSurfaceGraphEdge)
            .filter(AttackSurfaceGraphEdge.scan_id == self.scan_id)
            .order_by(AttackSurfaceGraphEdge.relationship_type, AttackSurfaceGraphEdge.created_at)
            .all()
        )
        updates = (
            self.db.query(AttackSurfaceGraphUpdate)
            .filter(AttackSurfaceGraphUpdate.scan_id == self.scan_id)
            .order_by(AttackSurfaceGraphUpdate.created_at.desc())
            .limit(25)
            .all()
        )
        node_by_id = {node.id: node for node in nodes}
        priority_paths = []
        for edge in edges:
            if edge.relationship_type != "POTENTIAL_ESCALATION_PRIORITY":
                continue
            source = node_by_id.get(edge.source_node_id)
            target = node_by_id.get(edge.target_node_id)
            if source and target:
                priority_paths.append({
                    "finding": self._node_dict(source),
                    "affected_asset": self._node_dict(target),
                    "relationship": self._edge_dict(edge),
                    "disclaimer": "Prioritization only — not an exploit path or proof of exploitability.",
                })
        return {
            "scan_id": str(self.scan_id),
            "correlation_version": CORRELATION_VERSION,
            "nodes": [self._node_dict(node) for node in nodes],
            "edges": [self._edge_dict(edge) for edge in edges],
            "updates": [self._update_dict(item) for item in updates],
            "summary": {
                "node_count": len(nodes),
                "edge_count": len(edges),
                "entity_counts": dict(sorted(Counter(node.entity_type for node in nodes).items())),
                "relationship_counts": dict(sorted(Counter(edge.relationship_type for edge in edges).items())),
                "priority_path_count": len(priority_paths),
            },
            "priority_paths": priority_paths,
            "safety_contract": {
                "prioritization_only": True,
                "autonomous_exploitation_supported": False,
                "network_requests_performed": False,
                "secret_values_excluded": True,
                "inferred_relationships_are_not_proof": True,
            },
        }

    def _seed_scan_identity(self, scan: Scan) -> tuple[AttackSurfaceGraphNode, AttackSurfaceGraphNode, AttackSurfaceGraphNode]:
        parsed = urlsplit(scan.requested_url)
        host_name = (parsed.hostname or scan.requested_url).lower()
        domain_name = self._domain_for_host(host_name)
        service_label = f"{parsed.scheme.lower() or 'https'}://{parsed.netloc.lower() or host_name}"
        domain = self._node("Domain", domain_name, domain_name, provenance=self._provenance("scan", str(scan.id), "requested_url"))
        host = self._node("Host", host_name, host_name, provenance=self._provenance("scan", str(scan.id), "requested_url"))
        service = self._node("Service", service_label, service_label, provenance=self._provenance("scan", str(scan.id), "requested_url"))
        application = self._node("Application", scan.requested_url, scan.requested_url, provenance=self._provenance("scan", str(scan.id), "requested_url"))
        self._edge(domain, host, "OWNS", provenance=self._provenance("scan", str(scan.id), "canonical_origin"))
        self._edge(host, service, "EXPOSES", provenance=self._provenance("scan", str(scan.id), "requested_url"))
        self._edge(service, application, "ASSOCIATED_WITH", provenance=self._provenance("scan", str(scan.id), "requested_url"))
        return application, host, domain

    def _correlate_pages(self, application: AttackSurfaceGraphNode) -> dict[UUID, AttackSurfaceGraphNode]:
        page_nodes: dict[UUID, AttackSurfaceGraphNode] = {}
        for page in self.db.query(Page).filter(Page.scan_id == self.scan_id).all():
            node = self._node("Endpoint", page.canonical_url, page.canonical_url, attributes={"status_code": page.status_code, "depth": page.depth, "title": page.title}, provenance=self._provenance("page", str(page.id), "crawl"))
            page_nodes[page.id] = node
            self._edge(application, node, "EXPOSES", provenance=self._provenance("page", str(page.id), "crawl"))
            if page.discovered_from_page_id and page.discovered_from_page_id in page_nodes:
                self._edge(page_nodes[page.discovered_from_page_id], node, "ASSOCIATED_WITH", classification="OBSERVED", provenance=self._provenance("page_link", str(page.id), "discovered_from"))
        return page_nodes

    def _correlate_recon(self, application: AttackSurfaceGraphNode, host: AttackSurfaceGraphNode, page_nodes: dict[UUID, AttackSurfaceGraphNode]) -> dict[UUID, AttackSurfaceGraphNode]:
        endpoint_nodes: dict[UUID, AttackSurfaceGraphNode] = {}
        for asset in self.db.query(ReconAsset).filter(ReconAsset.scan_id == self.scan_id).all():
            entity_type = "Cloud Asset" if self._is_cloud_asset(asset.asset_type, asset.value) else "Host"
            node = self._node(entity_type, asset.value, asset.value, classification=asset.classification, confidence=asset.confidence, attributes={"asset_type": asset.asset_type, "scope_status": asset.scope_status, "discovery_mode": asset.discovery_mode}, provenance=self._provenance("recon_asset", str(asset.id), asset.source))
            self._edge(host, node, "ASSOCIATED_WITH", classification=asset.classification, confidence=asset.confidence, provenance=self._provenance("recon_asset", str(asset.id), asset.source))
        recon_endpoints = self.db.query(ReconEndpoint).filter(ReconEndpoint.scan_id == self.scan_id).all()
        for endpoint in recon_endpoints:
            entity_type = "API" if endpoint.endpoint_kind.lower() in {"api", "schema", "graphql", "rpc"} else "Endpoint"
            node = self._node(entity_type, endpoint.url_or_path, endpoint.url_or_path, classification=endpoint.classification, confidence=endpoint.confidence, attributes={"method": endpoint.http_method, "endpoint_kind": endpoint.endpoint_kind, "scope_status": endpoint.scope_status, "status_code": endpoint.status_code}, provenance=self._provenance("recon_endpoint", str(endpoint.id), endpoint.source))
            endpoint_nodes[endpoint.id] = node
            self._edge(application, node, "EXPOSES", classification=endpoint.classification, confidence=endpoint.confidence, provenance=self._provenance("recon_endpoint", str(endpoint.id), endpoint.source))
            if endpoint.page_id and endpoint.page_id in page_nodes:
                self._edge(page_nodes[endpoint.page_id], node, "EXPOSES", classification=endpoint.classification, confidence=endpoint.confidence, provenance=self._provenance("recon_endpoint", str(endpoint.id), endpoint.source))
        for parameter in self.db.query(ReconParameter).filter(ReconParameter.scan_id == self.scan_id).all():
            parameter_key = f"{parameter.endpoint_id or parameter.page_id or 'scan'}:{parameter.location}:{parameter.name}"
            node = self._node("Parameter", parameter_key, f"{parameter.location}:{parameter.name}", classification=parameter.classification, confidence=parameter.confidence, attributes={"location": parameter.location, "scope_status": parameter.scope_status, "example_value_retained": False}, provenance=self._provenance("recon_parameter", str(parameter.id), parameter.source))
            parent = endpoint_nodes.get(parameter.endpoint_id) if parameter.endpoint_id else page_nodes.get(parameter.page_id) if parameter.page_id else application
            self._edge(parent, node, "EXPOSES", classification=parameter.classification, confidence=parameter.confidence, provenance=self._provenance("recon_parameter", str(parameter.id), parameter.source))
        return endpoint_nodes

    def _correlate_api_endpoints(self, application: AttackSurfaceGraphNode, host: AttackSurfaceGraphNode, endpoint_nodes: dict[UUID, AttackSurfaceGraphNode]) -> None:
        for endpoint in self.db.query(ApiEndpoint).filter(ApiEndpoint.scan_id == self.scan_id).all():
            node = self._node("API", endpoint.url_or_path, endpoint.url_or_path, classification=endpoint.classification, confidence=endpoint.confidence, attributes={"method": endpoint.http_method, "content_type": endpoint.content_type}, provenance=self._provenance("api_endpoint", str(endpoint.id), endpoint.discovered_from_source))
            self._edge(application, node, "EXPOSES", classification=endpoint.classification, confidence=endpoint.confidence, provenance=self._provenance("api_endpoint", str(endpoint.id), endpoint.discovered_from_source))
            self._edge(host, node, "EXPOSES", classification=endpoint.classification, confidence=endpoint.confidence, provenance=self._provenance("api_endpoint", str(endpoint.id), endpoint.discovered_from_source))
        for endpoint in endpoint_nodes.values():
            if endpoint.entity_type == "API":
                self._edge(application, endpoint, "EXPOSES", provenance=self._provenance("correlation", str(endpoint.id), "recon_api"))

    def _correlate_technologies(self, application: AttackSurfaceGraphNode) -> dict[UUID, AttackSurfaceGraphNode]:
        nodes: dict[UUID, AttackSurfaceGraphNode] = {}
        for technology in self.db.query(Technology).filter(Technology.scan_id == self.scan_id).all():
            node = self._node("Technology", technology.canonical_name, technology.canonical_name, classification=technology.classification.upper(), confidence=technology.confidence, attributes={"category": technology.category, "confidence_band": technology.confidence_band, "rule_version": technology.rule_version}, provenance=self._provenance("technology", str(technology.id), technology.rule_version))
            nodes[technology.id] = node
            self._edge(application, node, "DEPENDS_ON", classification=technology.classification.upper(), confidence=technology.confidence, provenance=self._provenance("technology", str(technology.id), technology.rule_version))
        return nodes

    def _correlate_dependencies(self, application: AttackSurfaceGraphNode, domain: AttackSurfaceGraphNode) -> None:
        for dependency in self.db.query(Dependency).filter(Dependency.scan_id == self.scan_id).all():
            entity_type = "Cloud Asset" if self._is_cloud_asset(dependency.category, dependency.domain) else "Service"
            node = self._node(entity_type, dependency.domain, dependency.domain, classification=dependency.classification.upper(), confidence=dependency.confidence, attributes={"category": dependency.category, "reference_count": dependency.reference_count}, provenance=self._provenance("dependency", str(dependency.id), dependency.category))
            self._edge(application, node, "DEPENDS_ON", classification=dependency.classification.upper(), confidence=dependency.confidence, provenance=self._provenance("dependency", str(dependency.id), dependency.category))
            if entity_type == "Cloud Asset":
                self._edge(domain, node, "ASSOCIATED_WITH", classification=dependency.classification.upper(), confidence=dependency.confidence, provenance=self._provenance("dependency", str(dependency.id), dependency.category))

    def _correlate_observations(self, application: AttackSurfaceGraphNode, page_nodes: dict[UUID, AttackSurfaceGraphNode]) -> None:
        for observation in self.db.query(HTTPObservation).filter(HTTPObservation.scan_id == self.scan_id).all():
            label = f"{observation.observation_type}: {observation.subject}"
            node = self._node("Evidence", f"http:{observation.id}", label, classification=observation.classification, confidence=observation.confidence, attributes={"observation_type": observation.observation_type, "subject": observation.subject, "redacted": observation.redacted, "truncated": observation.truncated}, provenance=self._provenance("http_observation", str(observation.id), observation.source))
            parent = page_nodes.get(observation.page_id, application)
            self._edge(parent, node, "HAS_EVIDENCE", classification=observation.classification, confidence=observation.confidence, provenance=self._provenance("http_observation", str(observation.id), observation.source))

    def _correlate_findings(self, application: AttackSurfaceGraphNode, page_nodes: dict[UUID, AttackSurfaceGraphNode]) -> dict[UUID, AttackSurfaceGraphNode]:
        nodes: dict[UUID, AttackSurfaceGraphNode] = {}
        for finding in self.db.query(SecurityFinding).filter(SecurityFinding.scan_id == self.scan_id).all():
            node = self._node("Finding", f"finding:{finding.id}", finding.subject, classification=finding.classification, confidence=finding.confidence, attributes={"category": finding.category, "severity": finding.severity, "rule_id": finding.rule_id, "rule_version": finding.rule_version}, provenance=self._provenance("security_finding", str(finding.id), finding.rule_id))
            nodes[finding.id] = node
            target = page_nodes.get(finding.page_id, application)
            self._edge(node, target, "AFFECTS", classification=finding.classification, confidence=finding.confidence, attributes={"severity": finding.severity}, provenance=self._provenance("security_finding", str(finding.id), finding.rule_id))
            for item in finding.evidence or []:
                if isinstance(item, dict):
                    evidence_id = str(item.get("id") or hashlib.sha256(str(item).encode()).hexdigest())
                    evidence = self._node("Evidence", f"finding:{finding.id}:{evidence_id}", str(item.get("type") or "finding evidence"), classification=finding.classification, confidence=finding.confidence, attributes={"source": str(item.get("source") or "stored finding evidence"), "redacted": True}, provenance=self._provenance("security_finding", str(finding.id), finding.rule_id))
                    self._edge(node, evidence, "HAS_EVIDENCE", classification=finding.classification, confidence=finding.confidence, provenance=self._provenance("security_finding", str(finding.id), finding.rule_id))
        return nodes

    def _correlate_evidence_reviews(self, finding_nodes: dict[UUID, AttackSurfaceGraphNode]) -> None:
        for review in self.db.query(EvidenceReview).filter(EvidenceReview.scan_id == self.scan_id).all():
            evidence = self._node("Evidence", f"review:{review.id}", f"Evidence review: {review.rule_id}", classification="OBSERVED", confidence=review.confidence, attributes={"source_agent": review.source_agent, "finding_state": review.finding_state, "evidence_quality": review.evidence_quality, "redacted": True}, provenance=self._provenance("evidence_review", str(review.id), review.source_agent))
            finding = finding_nodes.get(review.security_finding_id) if review.security_finding_id else None
            if finding:
                self._edge(finding, evidence, "HAS_EVIDENCE", confidence=review.confidence, provenance=self._provenance("evidence_review", str(review.id), review.source_agent))

    def _correlate_cve_matches(self, technology_nodes: dict[UUID, AttackSurfaceGraphNode]) -> None:
        for match in self.db.query(TechnologyCVEMatch).filter(TechnologyCVEMatch.scan_id == self.scan_id).all():
            technology = technology_nodes.get(match.technology_id)
            if not technology:
                continue
            label = match.cve_intelligence_id and f"Related vulnerability: {match.product}" or f"Version evidence incomplete: {match.product}"
            vulnerability = self._node("Finding", f"technology-cve:{match.id}", label, classification="INFERRED", confidence=match.applicability_confidence, attributes={"product": match.product, "vendor": match.vendor, "applicability_state": match.applicability_state, "cve_id": str(match.cve_intelligence_id) if match.cve_intelligence_id else None, "version_retained": bool(match.detected_version)}, provenance=self._provenance("technology_cve_match", str(match.id), "cve_intelligence"))
            self._edge(technology, vulnerability, "RELATED_VULNERABILITY", classification="INFERRED", confidence=match.applicability_confidence, attributes={"applicability_state": match.applicability_state}, provenance=self._provenance("technology_cve_match", str(match.id), "cve_intelligence"))

    def _correlate_duplicate_findings(self, finding_nodes: dict[UUID, AttackSurfaceGraphNode]) -> None:
        grouped: dict[str, list[SecurityFinding]] = defaultdict(list)
        for finding in self.db.query(SecurityFinding).filter(SecurityFinding.scan_id == self.scan_id).all():
            grouped[f"{finding.rule_id.lower()}|{finding.subject.lower()}"] .append(finding)
        for matches in grouped.values():
            if len(matches) < 2:
                continue
            root = finding_nodes.get(matches[0].id)
            for finding in matches[1:]:
                duplicate = finding_nodes.get(finding.id)
                if root and duplicate:
                    self._edge(root, duplicate, "DUPLICATES", classification="INFERRED", confidence=min(root.confidence, duplicate.confidence), provenance=self._provenance("correlation", str(finding.id), "same_rule_and_subject"))

    def _correlate_shared_configuration(self, page_nodes: dict[UUID, AttackSurfaceGraphNode]) -> None:
        grouped: dict[tuple[str, str], list[HTTPObservation]] = defaultdict(list)
        for observation in self.db.query(HTTPObservation).filter(HTTPObservation.scan_id == self.scan_id).all():
            subject = observation.subject.lower()
            if observation.page_id and subject in SAFE_SHARED_CONFIGURATION_SUBJECTS:
                grouped[(subject, self._safe_value_key(observation.value))].append(observation)
        for (subject, _value_key), observations in grouped.items():
            pages = [page_nodes[item.page_id] for item in observations if item.page_id in page_nodes]
            if len(pages) < 2:
                continue
            root = pages[0]
            for page in pages[1:]:
                self._edge(root, page, "SHARES_CONFIGURATION_WITH", classification="OBSERVED", confidence=1.0, attributes={"configuration_subject": subject, "value_excluded": True}, provenance=self._provenance("http_observation", str(observations[0].id), subject))

    def _correlate_priority_paths(self, application: AttackSurfaceGraphNode, page_nodes: dict[UUID, AttackSurfaceGraphNode], finding_nodes: dict[UUID, AttackSurfaceGraphNode]) -> None:
        for finding in self.db.query(SecurityFinding).filter(SecurityFinding.scan_id == self.scan_id).all():
            if finding.severity.lower() not in PRIORITY_SEVERITIES:
                continue
            node = finding_nodes.get(finding.id)
            target = page_nodes.get(finding.page_id, application)
            if node:
                self._edge(node, target, "POTENTIAL_ESCALATION_PRIORITY", classification="INFERRED", confidence=finding.confidence, attributes={"severity": finding.severity, "priority_only": True, "not_exploit_path": True}, provenance=self._provenance("security_finding", str(finding.id), "prioritization"))

    def _node(self, entity_type: str, logical_value: str, label: str, *, classification: str = "OBSERVED", confidence: float = 1.0, attributes: dict[str, Any] | None = None, provenance: dict[str, Any] | None = None) -> AttackSurfaceGraphNode:
        if entity_type not in ENTITY_TYPES:
            raise ValueError(f"Unsupported graph entity type: {entity_type}")
        natural_key = hashlib.sha256(f"{entity_type}:{logical_value}".encode()).hexdigest()
        key = (entity_type, natural_key)
        now = utc_now()
        node = self._nodes.get(key)
        if node is None:
            node = AttackSurfaceGraphNode(scan_id=self.scan_id, entity_type=entity_type, natural_key=natural_key, label=label[:2048], classification=classification.upper()[:30], confidence=self._percentage(confidence), attributes=attributes or {}, provenance=[provenance] if provenance else [], first_seen_at=now, last_seen_at=now)
            try:
                with self.db.begin_nested():
                    self.db.add(node)
                    self.db.flush()
                self._nodes[key] = node
                self._stats["inserted_nodes"] += 1
            except IntegrityError:
                node = self.db.query(AttackSurfaceGraphNode).filter(
                    AttackSurfaceGraphNode.scan_id == self.scan_id,
                    AttackSurfaceGraphNode.entity_type == entity_type,
                    AttackSurfaceGraphNode.natural_key == natural_key,
                ).first()
                if node is None:
                    raise
                node.label = label[:2048]
                node.classification = classification.upper()[:30]
                node.confidence = max(node.confidence, self._percentage(confidence))
                node.attributes = self._merge_mapping(node.attributes, attributes)
                node.provenance = self._merge_provenance(node.provenance, provenance)
                node.last_seen_at = now
                self._nodes[key] = node
                self._stats["refreshed_nodes"] += 1
        else:
            node.label = label[:2048]
            node.classification = classification.upper()[:30]
            node.confidence = max(node.confidence, self._percentage(confidence))
            node.attributes = self._merge_mapping(node.attributes, attributes)
            node.provenance = self._merge_provenance(node.provenance, provenance)
            node.last_seen_at = now
            self._stats["refreshed_nodes"] += 1
        return node

    def _edge(self, source: AttackSurfaceGraphNode, target: AttackSurfaceGraphNode, relationship_type: str, *, classification: str = "OBSERVED", confidence: float = 1.0, attributes: dict[str, Any] | None = None, provenance: dict[str, Any] | None = None) -> AttackSurfaceGraphEdge:
        if relationship_type not in RELATIONSHIP_TYPES:
            raise ValueError(f"Unsupported graph relationship type: {relationship_type}")
        if relationship_type == "DUPLICATES" and str(source.id) > str(target.id):
            source, target = target, source
        edge = self.db.query(AttackSurfaceGraphEdge).filter(AttackSurfaceGraphEdge.scan_id == self.scan_id, AttackSurfaceGraphEdge.relationship_type == relationship_type, AttackSurfaceGraphEdge.source_node_id == source.id, AttackSurfaceGraphEdge.target_node_id == target.id).first()
        now = utc_now()
        if edge is None:
            edge = AttackSurfaceGraphEdge(scan_id=self.scan_id, source_node_id=source.id, target_node_id=target.id, relationship_type=relationship_type, classification=classification.upper()[:30], confidence=self._percentage(confidence), attributes=attributes or {}, provenance=[provenance] if provenance else [], first_seen_at=now, last_seen_at=now)
            try:
                with self.db.begin_nested():
                    self.db.add(edge)
                    self.db.flush()
                self._stats["inserted_edges"] += 1
            except IntegrityError:
                edge = self.db.query(AttackSurfaceGraphEdge).filter(
                    AttackSurfaceGraphEdge.scan_id == self.scan_id,
                    AttackSurfaceGraphEdge.relationship_type == relationship_type,
                    AttackSurfaceGraphEdge.source_node_id == source.id,
                    AttackSurfaceGraphEdge.target_node_id == target.id,
                ).first()
                if edge is None:
                    raise
                edge.classification = classification.upper()[:30]
                edge.confidence = max(edge.confidence, self._percentage(confidence))
                edge.attributes = self._merge_mapping(edge.attributes, attributes)
                edge.provenance = self._merge_provenance(edge.provenance, provenance)
                edge.last_seen_at = now
                self._stats["refreshed_edges"] += 1
        else:
            edge.classification = classification.upper()[:30]
            edge.confidence = max(edge.confidence, self._percentage(confidence))
            edge.attributes = self._merge_mapping(edge.attributes, attributes)
            edge.provenance = self._merge_provenance(edge.provenance, provenance)
            edge.last_seen_at = now
            self._stats["refreshed_edges"] += 1
        return edge

    def _summary(self) -> dict[str, Any]:
        nodes = self.db.query(AttackSurfaceGraphNode).filter(AttackSurfaceGraphNode.scan_id == self.scan_id).all()
        edges = self.db.query(AttackSurfaceGraphEdge).filter(AttackSurfaceGraphEdge.scan_id == self.scan_id).all()
        return {"node_count": len(nodes), "edge_count": len(edges), "entity_counts": dict(sorted(Counter(item.entity_type for item in nodes).items())), "relationship_counts": dict(sorted(Counter(item.relationship_type for item in edges).items()))}

    @staticmethod
    def _domain_for_host(host: str) -> str:
        labels = [item for item in host.split(".") if item]
        return ".".join(labels[-2:]) if len(labels) >= 2 else host

    @staticmethod
    def _is_cloud_asset(category: str, value: str) -> bool:
        marker = f"{category} {value}".lower()
        return any(item in marker for item in ("cloud", "aws", "amazon", "azure", "gcp", "googleusercontent", "cloudfront", "fastly"))

    @staticmethod
    def _percentage(value: float) -> float:
        value = float(value or 0)
        return round(value * 100 if value <= 1 else value, 2)

    @staticmethod
    def _provenance(source_type: str, source_id: str, source: str) -> dict[str, str]:
        return {"source_type": source_type, "source_id": source_id, "source": source}

    @staticmethod
    def _merge_mapping(existing: Any, incoming: dict[str, Any] | None) -> dict[str, Any]:
        merged = dict(existing) if isinstance(existing, dict) else {}
        if incoming:
            merged.update({key: value for key, value in incoming.items() if value is not None})
        return merged

    @staticmethod
    def _merge_provenance(existing: Any, incoming: dict[str, Any] | None) -> list[dict[str, Any]]:
        values = [item for item in existing if isinstance(item, dict)] if isinstance(existing, list) else []
        if incoming and incoming not in values:
            values.append(incoming)
        return values[-20:]

    @staticmethod
    def _safe_value_key(value: Any) -> str:
        return hashlib.sha256(repr(value).encode()).hexdigest()

    @staticmethod
    def _node_dict(node: AttackSurfaceGraphNode) -> dict[str, Any]:
        return {"id": str(node.id), "entity_type": node.entity_type, "label": node.label, "classification": node.classification, "confidence": node.confidence, "attributes": node.attributes or {}, "provenance": node.provenance or [], "first_seen_at": node.first_seen_at.isoformat(), "last_seen_at": node.last_seen_at.isoformat()}

    @staticmethod
    def _edge_dict(edge: AttackSurfaceGraphEdge) -> dict[str, Any]:
        return {"id": str(edge.id), "source_node_id": str(edge.source_node_id), "target_node_id": str(edge.target_node_id), "relationship_type": edge.relationship_type, "classification": edge.classification, "confidence": edge.confidence, "attributes": edge.attributes or {}, "provenance": edge.provenance or [], "first_seen_at": edge.first_seen_at.isoformat(), "last_seen_at": edge.last_seen_at.isoformat()}

    @staticmethod
    def _update_dict(update: AttackSurfaceGraphUpdate) -> dict[str, Any]:
        return {"id": str(update.id), "source_event": update.source_event, "correlation_version": update.correlation_version, "inserted_node_count": update.inserted_node_count, "refreshed_node_count": update.refreshed_node_count, "inserted_edge_count": update.inserted_edge_count, "refreshed_edge_count": update.refreshed_edge_count, "summary": update.summary or {}, "created_at": update.created_at.isoformat()}


__all__ = ["CORRELATION_VERSION", "CorrelationAgent"]
