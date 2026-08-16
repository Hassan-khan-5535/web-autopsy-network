"""phase 8 performance analysis

Revision ID: 0008_phase8_performance
Revises: 0007_phase7_security
Create Date: 2026-08-16 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0008_phase8_performance"
down_revision: str | None = "0007_phase7_security"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "performance_metrics",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("page_id", sa.UUID(as_uuid=True), nullable=True),
        sa.Column("scope", sa.String(length=30), nullable=False, server_default="page"),
        sa.Column("metric_name", sa.String(length=150), nullable=False),
        sa.Column("value", sa.Float(), nullable=True),
        sa.Column("unit", sa.String(length=30), nullable=False),
        sa.Column("classification", sa.String(length=30), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="100"),
        sa.Column("confidence_band", sa.String(length=30), nullable=False, server_default="high"),
        sa.Column("capture_mode", sa.String(length=50), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("limitations", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["page_id"], ["pages.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_performance_metrics_scan_id"), "performance_metrics", ["scan_id"], unique=False
    )
    op.create_index(
        op.f("ix_performance_metrics_page_id"), "performance_metrics", ["page_id"], unique=False
    )
    op.create_index(
        op.f("ix_performance_metrics_scope"), "performance_metrics", ["scope"], unique=False
    )
    op.create_index(
        op.f("ix_performance_metrics_metric_name"),
        "performance_metrics",
        ["metric_name"],
        unique=False,
    )
    op.create_index(
        op.f("ix_performance_metrics_classification"),
        "performance_metrics",
        ["classification"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_performance_metrics_classification"), table_name="performance_metrics"
    )
    op.drop_index(op.f("ix_performance_metrics_metric_name"), table_name="performance_metrics")
    op.drop_index(op.f("ix_performance_metrics_scope"), table_name="performance_metrics")
    op.drop_index(op.f("ix_performance_metrics_page_id"), table_name="performance_metrics")
    op.drop_index(op.f("ix_performance_metrics_scan_id"), table_name="performance_metrics")
    op.drop_table("performance_metrics")
