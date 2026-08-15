import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import ForeignKey, String, Integer, DateTime, JSON, Text, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.models.base import Base

def utc_now():
    return datetime.now(timezone.utc)


class Website(Base):
    __tablename__ = "websites"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(255), index=True, default="default")
    canonical_origin: Mapped[str] = mapped_column(String(2048), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    scans: Mapped[List["Scan"]] = relationship(back_populates="website", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    website_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("websites.id", ondelete="CASCADE"), index=True)
    state: Mapped[str] = mapped_column(String(50), index=True, default="CREATED")  # CREATED, VALIDATING, COLLECTING, COMPLETED, FAILED
    requested_url: Mapped[str] = mapped_column(String(2048))
    error_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    website: Mapped["Website"] = relationship(back_populates="scans")
    pages: Mapped[List["Page"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    observations: Mapped[List["Observation"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Page(Base):
    __tablename__ = "pages"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    canonical_url: Mapped[str] = mapped_column(String(2048))
    depth: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped["Scan"] = relationship(back_populates="pages")
    http_responses: Mapped[List["HTTPResponse"]] = relationship(back_populates="page", cascade="all, delete-orphan")
    resources: Mapped[List["Resource"]] = relationship(back_populates="page", cascade="all, delete-orphan")


class HTTPResponse(Base):
    __tablename__ = "http_responses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    page_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("pages.id", ondelete="CASCADE"), index=True)
    status_code: Mapped[int] = mapped_column(Integer, index=True)
    final_url: Mapped[str] = mapped_column(String(2048))
    content_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    timings_ms: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    page: Mapped["Page"] = relationship(back_populates="http_responses")
    headers: Mapped[List["Header"]] = relationship(back_populates="http_response", cascade="all, delete-orphan")


class Header(Base):
    __tablename__ = "headers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    http_response_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("http_responses.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    value: Mapped[str] = mapped_column(Text)

    http_response: Mapped["HTTPResponse"] = relationship(back_populates="headers")


class Resource(Base):
    __tablename__ = "resources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    page_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("pages.id", ondelete="CASCADE"), index=True)
    url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)
    type: Mapped[str] = mapped_column(String(50))  # e.g., script, link, img, form
    attributes: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    page: Mapped["Page"] = relationship(back_populates="resources")


class Observation(Base):
    __tablename__ = "observations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    category: Mapped[str] = mapped_column(String(100), index=True)
    subject: Mapped[str] = mapped_column(String(2048), index=True)
    observation: Mapped[str] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(String(50), default="OBSERVED")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    scan: Mapped["Scan"] = relationship(back_populates="observations")
