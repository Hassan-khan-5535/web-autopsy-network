"""Extension 16 verified update package lifecycle.

Revision ID: 20260819_extension16
Revises: 20260819_extension13
Create Date: 2026-08-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260819_extension16"
down_revision: str | Sequence[str] | None = "20260819_extension13"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "update_packages",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("package_name", sa.String(length=120), nullable=False),
        sa.Column("version", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="staged"),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("components", sa.JSON(), nullable=False),
        sa.Column("compatibility", sa.JSON(), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("signature_algorithm", sa.String(length=80), nullable=True),
        sa.Column("signature_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("validation_report", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("installed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rollback_of_id", sa.Uuid(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.UniqueConstraint("package_name", "version", name="uq_update_packages_name_version"),
    )
    for name, columns in (("ix_update_packages_package_name", ["package_name"]), ("ix_update_packages_version", ["version"]), ("ix_update_packages_status", ["status"]), ("ix_update_packages_sha256", ["sha256"]), ("ix_update_packages_signature_verified", ["signature_verified"]), ("ix_update_packages_installed_at", ["installed_at"]), ("ix_update_packages_activated_at", ["activated_at"]), ("ix_update_packages_rolled_back_at", ["rolled_back_at"]), ("ix_update_packages_rollback_of_id", ["rollback_of_id"])):
        op.create_index(name, "update_packages", columns)


def downgrade() -> None:
    op.drop_table("update_packages")
