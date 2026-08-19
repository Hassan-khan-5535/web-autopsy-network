from datetime import UTC, datetime
import uuid
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


class Website(Base):
    __tablename__ = "websites"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, default="default")
    canonical_origin: Mapped[str] = mapped_column(String(2048), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="website", cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    website_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("websites.id", ondelete="CASCADE"), index=True
    )
    state: Mapped[str] = mapped_column(String(50), index=True, default="CREATED")
    requested_url: Mapped[str] = mapped_column(String(2048))
    error_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    max_depth: Mapped[int] = mapped_column(Integer, default=2)
    max_pages: Mapped[int] = mapped_column(Integer, default=30)
    max_concurrency: Mapped[int] = mapped_column(Integer, default=2)
    request_delay_ms: Mapped[int] = mapped_column(Integer, default=1000)
    same_domain_mode: Mapped[str] = mapped_column(String(30), default="hostname")
    assessment_profile: Mapped[str | None] = mapped_column(String(30), nullable=True, default="legacy_passive", index=True)
    max_requests: Mapped[int | None] = mapped_column(Integer, nullable=True, default=30)
    recon_mode: Mapped[str] = mapped_column(String(30), default="passive_only", index=True)
    requests_used: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    website: Mapped["Website"] = relationship(back_populates="scans")
    pages: Mapped[list["Page"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    observations: Mapped[list["Observation"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    technologies: Mapped[list["Technology"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    dependencies: Mapped[list["Dependency"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    api_endpoints: Mapped[list["ApiEndpoint"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    security_findings: Mapped[list["SecurityFinding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    performance_metrics: Mapped[list["PerformanceMetric"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    accessibility_findings: Mapped[list["AccessibilityFinding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    content_findings: Mapped[list["ContentFinding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    ai_interpretations: Mapped[list["AIInterpretation"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    cause_of_death: Mapped[Optional["CauseOfDeathDiagnosis"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", uselist=False
    )
    agent_tasks: Mapped[list["AgentTask"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    agent_events: Mapped[list["AgentEvent"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    assessment_authorization: Mapped[Optional["AssessmentAuthorization"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", uselist=False
    )
    assessment_audit_events: Mapped[list["AssessmentAuditEvent"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="AssessmentAuditEvent.sequence_number"
    )
    recon_assets: Mapped[list["ReconAsset"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    recon_endpoints: Mapped[list["ReconEndpoint"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    recon_parameters: Mapped[list["ReconParameter"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    pause_requested: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AssessmentAuthorization(Base):
    __tablename__ = "assessment_authorizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), unique=True, index=True
    )
    authorization_type: Mapped[str] = mapped_column(String(50), default="acknowledged")
    actor_id: Mapped[str] = mapped_column(String(255), default="anonymous")
    target_url: Mapped[str] = mapped_column(String(2048))
    allowed_paths: Mapped[list] = mapped_column(JSON, default=list)
    excluded_paths: Mapped[list] = mapped_column(JSON, default=list)
    allowed_domains: Mapped[list] = mapped_column(JSON, default=list)
    assessment_profile: Mapped[str] = mapped_column(String(30), default="legacy_passive")
    robots_override: Mapped[bool] = mapped_column(Boolean, default=False)
    max_depth: Mapped[int] = mapped_column(Integer, default=2)
    max_pages: Mapped[int] = mapped_column(Integer, default=30)
    max_requests: Mapped[int] = mapped_column(Integer, default=30)
    max_concurrency: Mapped[int] = mapped_column(Integer, default=2)
    rate_limit_per_host_ms: Mapped[int] = mapped_column(Integer, default=1000)
    test_account_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    auth_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    auth_secret_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    consent_hash: Mapped[str] = mapped_column(String(64))
    authorized_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    policy_version: Mapped[str] = mapped_column(String(50), default="assessment-v1")
    scope_json: Mapped[dict] = mapped_column(JSON, default=dict)

    scan: Mapped["Scan"] = relationship(back_populates="assessment_authorization")
    audit_events: Mapped[list["AssessmentAuditEvent"]] = relationship(
        back_populates="authorization", cascade="all, delete-orphan", order_by="AssessmentAuditEvent.sequence_number"
    )


class AssessmentAuditEvent(Base):
    __tablename__ = "assessment_audit_events"
    __table_args__ = (UniqueConstraint("scan_id", "sequence_number", name="uq_assessment_audit_scan_sequence"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    authorization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assessment_authorizations.id", ondelete="SET NULL"), nullable=True, index=True
    )
    sequence_number: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    actor_id: Mapped[str] = mapped_column(String(255), default="system")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    previous_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)

    scan: Mapped["Scan"] = relationship(back_populates="assessment_audit_events")
    authorization: Mapped[Optional["AssessmentAuthorization"]] = relationship(back_populates="audit_events")


class ReconAsset(Base):
    __tablename__ = "recon_assets"
    __table_args__ = (UniqueConstraint("scan_id", "dedupe_key", name="uq_recon_assets_scan_dedupe"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    asset_type: Mapped[str] = mapped_column(String(50), index=True)
    value: Mapped[str] = mapped_column(String(2048), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(2048))
    discovery_mode: Mapped[str] = mapped_column(String(30), default="passive_only", index=True)
    classification: Mapped[str] = mapped_column(String(50), default="OBSERVED", index=True)
    scope_status: Mapped[str] = mapped_column(String(30), default="in_scope", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    attributes: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    evidence: Mapped[list | dict | None] = mapped_column(JSON, nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)

    scan: Mapped["Scan"] = relationship(back_populates="recon_assets")


class ReconEndpoint(Base):
    __tablename__ = "recon_endpoints"
    __table_args__ = (UniqueConstraint("scan_id", "dedupe_key", name="uq_recon_endpoints_scan_dedupe"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    endpoint_kind: Mapped[str] = mapped_column(String(50), index=True)
    url_or_path: Mapped[str] = mapped_column(String(2048), index=True)
    http_method: Mapped[str] = mapped_column(String(20), default="UNKNOWN")
    source: Mapped[str] = mapped_column(String(2048))
    discovery_mode: Mapped[str] = mapped_column(String(30), default="passive_only", index=True)
    classification: Mapped[str] = mapped_column(String(50), default="INFERRED", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    scope_status: Mapped[str] = mapped_column(String(30), default="in_scope", index=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    page_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("pages.id", ondelete="SET NULL"), nullable=True, index=True)
    attributes: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    evidence: Mapped[list | dict | None] = mapped_column(JSON, nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)

    scan: Mapped["Scan"] = relationship(back_populates="recon_endpoints")
    page: Mapped[Optional["Page"]] = relationship()
    parameters: Mapped[list["ReconParameter"]] = relationship(back_populates="endpoint", cascade="all, delete-orphan")


class ReconParameter(Base):
    __tablename__ = "recon_parameters"
    __table_args__ = (UniqueConstraint("scan_id", "dedupe_key", name="uq_recon_parameters_scan_dedupe"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("recon_endpoints.id", ondelete="CASCADE"), nullable=True, index=True)
    page_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("pages.id", ondelete="SET NULL"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    location: Mapped[str] = mapped_column(String(30), index=True)
    source: Mapped[str] = mapped_column(String(2048))
    discovery_mode: Mapped[str] = mapped_column(String(30), default="passive_only", index=True)
    classification: Mapped[str] = mapped_column(String(50), default="INFERRED", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    scope_status: Mapped[str] = mapped_column(String(30), default="in_scope", index=True)
    example_value: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    evidence: Mapped[list | dict | None] = mapped_column(JSON, nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)

    scan: Mapped["Scan"] = relationship(back_populates="recon_parameters")
    endpoint: Mapped[Optional["ReconEndpoint"]] = relationship(back_populates="parameters")
    page: Mapped[Optional["Page"]] = relationship()


class Page(Base):
    __tablename__ = "pages"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    canonical_url: Mapped[str] = mapped_column(String(2048))
    depth: Mapped[int] = mapped_column(Integer, default=0)
    discovered_from_page_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("pages.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    title: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped["Scan"] = relationship(back_populates="pages")
    discovered_from: Mapped[Optional["Page"]] = relationship(
        remote_side=[id], back_populates="discovered_pages"
    )
    discovered_pages: Mapped[list["Page"]] = relationship(back_populates="discovered_from")
    http_responses: Mapped[list["HTTPResponse"]] = relationship(
        back_populates="page", cascade="all, delete-orphan"
    )
    resources: Mapped[list["Resource"]] = relationship(
        back_populates="page", cascade="all, delete-orphan"
    )
    outgoing_links: Mapped[list["PageLink"]] = relationship(
        back_populates="source_page", cascade="all, delete-orphan"
    )


class PageLink(Base):
    __tablename__ = "page_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_page_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("pages.id", ondelete="CASCADE"), index=True
    )
    target_url: Mapped[str] = mapped_column(String(2048))
    is_external: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    source_page: Mapped["Page"] = relationship(back_populates="outgoing_links")


class HTTPResponse(Base):
    __tablename__ = "http_responses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    page_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("pages.id", ondelete="CASCADE"), index=True
    )
    status_code: Mapped[int] = mapped_column(Integer, index=True)
    final_url: Mapped[str] = mapped_column(String(2048))
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    timings_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    raw_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    rendered_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    timing_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    page: Mapped["Page"] = relationship(back_populates="http_responses")
    headers: Mapped[list["Header"]] = relationship(
        back_populates="http_response", cascade="all, delete-orphan"
    )


class Header(Base):
    __tablename__ = "headers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    http_response_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("http_responses.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(255), index=True)
    value: Mapped[str] = mapped_column(Text)

    http_response: Mapped["HTTPResponse"] = relationship(back_populates="headers")


class Resource(Base):
    __tablename__ = "resources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    page_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("pages.id", ondelete="CASCADE"), index=True
    )
    url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    type: Mapped[str] = mapped_column(String(50))
    attributes: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    capture_source: Mapped[str] = mapped_column(
        String(50), default="static_http", server_default="static_http", index=True
    )


    page: Mapped["Page"] = relationship(back_populates="resources")


class Technology(Base):
    __tablename__ = "technologies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    canonical_name: Mapped[str] = mapped_column(String(255), index=True)
    category: Mapped[str] = mapped_column(String(100), index=True)
    classification: Mapped[str] = mapped_column(String(30), default="inferred")
    confidence: Mapped[float] = mapped_column(Float)
    confidence_band: Mapped[str] = mapped_column(String(30))
    rule_version: Mapped[str] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped["Scan"] = relationship(back_populates="technologies")
    evidence: Mapped[list["TechnologyEvidence"]] = relationship(
        back_populates="technology", cascade="all, delete-orphan"
    )


class TechnologyEvidence(Base):
    __tablename__ = "technology_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    technology_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("technologies.id", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    page_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("pages.id", ondelete="SET NULL"), nullable=True, index=True
    )
    signal_type: Mapped[str] = mapped_column(String(50))
    match_rule: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(2048))
    observation: Mapped[str] = mapped_column(Text)
    match_weight: Mapped[float] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    technology: Mapped["Technology"] = relationship(back_populates="evidence")
    scan: Mapped["Scan"] = relationship()
    page: Mapped[Optional["Page"]] = relationship()


class Observation(Base):
    __tablename__ = "observations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    category: Mapped[str] = mapped_column(String(100), index=True)
    subject: Mapped[str] = mapped_column(String(2048), index=True)
    observation: Mapped[str] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(String(50), default="OBSERVED")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped["Scan"] = relationship(back_populates="observations")


class Dependency(Base):
    __tablename__ = "dependencies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    domain: Mapped[str] = mapped_column(String(255), index=True)
    category: Mapped[str] = mapped_column(String(100), index=True, default="Unclassified")
    classification: Mapped[str] = mapped_column(String(30), default="inferred")
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    reference_count: Mapped[int] = mapped_column(Integer, default=1)
    sample_resource_urls: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped["Scan"] = relationship(back_populates="dependencies")


class PerformanceMetric(Base):
    __tablename__ = "performance_metrics"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    page_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("pages.id", ondelete="SET NULL"), nullable=True, index=True
    )
    scope: Mapped[str] = mapped_column(String(30), default="page", index=True)
    metric_name: Mapped[str] = mapped_column(String(150), index=True)
    value: Mapped[float | None] = mapped_column(Float, nullable=True)
    unit: Mapped[str] = mapped_column(String(30))
    classification: Mapped[str] = mapped_column(String(30), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=100.0)
    confidence_band: Mapped[str] = mapped_column(String(30), default="high")
    capture_mode: Mapped[str] = mapped_column(String(50))
    statement: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSON)
    limitations: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped["Scan"] = relationship(back_populates="performance_metrics")
    page: Mapped[Optional["Page"]] = relationship()


class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    page_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("pages.id", ondelete="SET NULL"), nullable=True, index=True
    )
    category: Mapped[str] = mapped_column(String(100), default="security", index=True)
    subject: Mapped[str] = mapped_column(String(2048), index=True)
    statement: Mapped[str] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(String(30), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    confidence_band: Mapped[str] = mapped_column(String(30))
    severity: Mapped[str] = mapped_column(String(30), index=True)
    rule_id: Mapped[str] = mapped_column(String(100), index=True)
    rule_version: Mapped[str] = mapped_column(String(50))
    evidence: Mapped[list] = mapped_column(JSON)
    limitations: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped["Scan"] = relationship(back_populates="security_findings")
    page: Mapped[Optional["Page"]] = relationship()


class ApiEndpoint(Base):
    __tablename__ = "api_endpoints"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    url_or_path: Mapped[str] = mapped_column(String(2048), index=True)
    http_method: Mapped[str] = mapped_column(String(20), default="UNKNOWN")
    content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    classification: Mapped[str] = mapped_column(String(30), default="inferred")
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    discovered_from_source: Mapped[str] = mapped_column(String(2048))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped["Scan"] = relationship(back_populates="api_endpoints")


class AccessibilityFinding(Base):
    __tablename__ = "accessibility_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    page_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("pages.id", ondelete="SET NULL"), nullable=True, index=True
    )
    category: Mapped[str] = mapped_column(String(100), index=True)
    subject: Mapped[str] = mapped_column(String(2048), index=True)
    statement: Mapped[str] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(String(30), index=True)
    disclaimer: Mapped[str] = mapped_column(Text, default="Automated checks are partial and do not constitute WCAG compliance certification.")
    evidence: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped["Scan"] = relationship(back_populates="accessibility_findings")
    page: Mapped[Optional["Page"]] = relationship()


class ContentFinding(Base):
    __tablename__ = "content_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    page_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("pages.id", ondelete="SET NULL"), nullable=True, index=True
    )
    category: Mapped[str] = mapped_column(String(100), index=True)
    subject: Mapped[str] = mapped_column(String(2048), index=True)
    statement: Mapped[str] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(String(30), index=True)
    evidence: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped["Scan"] = relationship(back_populates="content_findings")
    page: Mapped[Optional["Page"]] = relationship()


class AIInterpretation(Base):
    __tablename__ = "ai_interpretations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    category: Mapped[str] = mapped_column(String(100), index=True)
    subject: Mapped[str] = mapped_column(String(2048), index=True)
    statement: Mapped[str] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(String(30), default="ai_interpretation", index=True)
    evidence: Mapped[list] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped["Scan"] = relationship(back_populates="ai_interpretations")


class ScanDifference(Base):
    __tablename__ = "scan_differences"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    website_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("websites.id", ondelete="CASCADE"), index=True
    )
    scan_a_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    scan_b_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    diff_data: Mapped[dict] = mapped_column(JSON)
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_evidence: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    website: Mapped["Website"] = relationship()
    scan_a: Mapped["Scan"] = relationship(foreign_keys=[scan_a_id])
    scan_b: Mapped["Scan"] = relationship(foreign_keys=[scan_b_id])


class CauseOfDeathDiagnosis(Base):
    __tablename__ = "cause_of_death_diagnoses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), unique=True, index=True
    )
    primary_issue: Mapped[dict] = mapped_column(JSON)
    secondary_issues: Mapped[list] = mapped_column(JSON)
    contributing_factors: Mapped[list] = mapped_column(JSON)
    confidence: Mapped[float] = mapped_column(Float)
    evidence_count: Mapped[int] = mapped_column(Integer)
    evidence: Mapped[list] = mapped_column(JSON)
    ai_narrative: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_evidence: Mapped[list] = mapped_column(JSON, default=list)
    disclaimer: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )

    scan: Mapped["Scan"] = relationship(back_populates="cause_of_death")


class AgentTask(Base):
    __tablename__ = "agent_tasks"
    __table_args__ = (UniqueConstraint("scan_id", "task_key", name="uq_agent_tasks_scan_task_key"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    task_key: Mapped[str] = mapped_column(String(120), index=True)
    task_type: Mapped[str] = mapped_column(String(80), index=True)
    queue_name: Mapped[str] = mapped_column(String(50), index=True)
    status: Mapped[str] = mapped_column(String(30), default="QUEUED", index=True)
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, default=2)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    dependency_keys: Mapped[list] = mapped_column(JSON, default=list)
    error_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    available_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    scan: Mapped["Scan"] = relationship(back_populates="agent_tasks")
    events: Mapped[list["AgentEvent"]] = relationship(back_populates="task", cascade="all, delete-orphan")


class AgentEvent(Base):
    __tablename__ = "agent_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    task_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("agent_tasks.id", ondelete="SET NULL"), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(60), index=True)
    payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)

    scan: Mapped["Scan"] = relationship(back_populates="agent_events")
    task: Mapped[Optional["AgentTask"]] = relationship(back_populates="events")
