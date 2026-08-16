import uuid
from datetime import UTC, datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
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
    capture_source: Mapped[str] = mapped_column(String(50), default="static_http", server_default="static_http", index=True)


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

