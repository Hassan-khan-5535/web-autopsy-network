"""Extension 3 central HTTP Agent observations.

Revision ID: 20260819_extension3
Revises: 20260819_extension2
Create Date: 2026-08-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260819_extension3"
down_revision: str | Sequence[str] | None = "20260819_extension2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("http_responses", sa.Column("body_truncated", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("http_responses", sa.Column("redirect_chain", sa.JSON(), nullable=True))
    op.create_table(
        "http_observations",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("page_id", sa.UUID(as_uuid=True), nullable=True),
        sa.Column("http_response_id", sa.UUID(as_uuid=True), nullable=True),
        sa.Column("observation_type", sa.String(length=50), nullable=False),
        sa.Column("subject", sa.String(length=2048), nullable=False),
        sa.Column("source", sa.String(length=2048), nullable=False),
        sa.Column("classification", sa.String(length=30), nullable=False, server_default="OBSERVED"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("value", sa.JSON(), nullable=True),
        sa.Column("redacted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("dedupe_key", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["page_id"], ["pages.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["http_response_id"], ["http_responses.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "dedupe_key", name="uq_http_observations_scan_dedupe"),
    )
    for index_name, column in (
        ("ix_http_observations_scan_id", "scan_id"),
        ("ix_http_observations_page_id", "page_id"),
        ("ix_http_observations_http_response_id", "http_response_id"),
        ("ix_http_observations_observation_type", "observation_type"),
        ("ix_http_observations_subject", "subject"),
        ("ix_http_observations_classification", "classification"),
        ("ix_http_observations_dedupe_key", "dedupe_key"),
    ):
        op.create_index(index_name, "http_observations", [column])


def downgrade() -> None:
    for index_name in (
        "ix_http_observations_dedupe_key",
        "ix_http_observations_classification",
        "ix_http_observations_subject",
        "ix_http_observations_observation_type",
        "ix_http_observations_http_response_id",
        "ix_http_observations_page_id",
        "ix_http_observations_scan_id",
    ):
        op.drop_index(index_name, table_name="http_observations")
    op.drop_table("http_observations")
    op.drop_column("http_responses", "redirect_chain")
    op.drop_column("http_responses", "body_truncated")
