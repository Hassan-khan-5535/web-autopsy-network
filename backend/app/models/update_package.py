"""Durable provenance for verified Extension 16 update packages."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, JSON, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


def utc_now() -> datetime:
    return datetime.now(UTC)


class UpdatePackage(Base):
    __tablename__ = "update_packages"
    __table_args__ = (UniqueConstraint("package_name", "version", name="uq_update_packages_name_version"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    package_name: Mapped[str] = mapped_column(String(120), index=True)
    version: Mapped[str] = mapped_column(String(80), index=True)
    status: Mapped[str] = mapped_column(String(30), default="staged", index=True)
    manifest: Mapped[dict] = mapped_column(JSON)
    components: Mapped[dict] = mapped_column(JSON)
    compatibility: Mapped[dict] = mapped_column(JSON)
    provenance: Mapped[dict] = mapped_column(JSON, default=dict)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    signature_algorithm: Mapped[str | None] = mapped_column(String(80), nullable=True)
    signature_verified: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    validation_report: Mapped[dict] = mapped_column(JSON, default=dict)
    installed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    rollback_of_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
