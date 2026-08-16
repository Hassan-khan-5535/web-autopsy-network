"""phase 7 passive security analysis

Revision ID: 0007_phase7_security
Revises: 0006_phase6_browser_analysis
Create Date: 2026-08-16 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0007_phase7_security"
down_revision: str | Sequence[str] | None = "0006_phase6_browser_analysis"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "security_findings",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("page_id", sa.UUID(as_uuid=True), nullable=True),
        sa.Column("category", sa.String(length=100), nullable=False, server_default="security"),
        sa.Column("subject", sa.String(length=2048), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("classification", sa.String(length=30), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("confidence_band", sa.String(length=30), nullable=False),
        sa.Column("severity", sa.String(length=30), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("rule_version", sa.String(length=50), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("limitations", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["page_id"], ["pages.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_security_findings_scan_id"), "security_findings", ["scan_id"], unique=False
    )
    op.create_index(
        op.f("ix_security_findings_page_id"), "security_findings", ["page_id"], unique=False
    )
    op.create_index(
        op.f("ix_security_findings_category"), "security_findings", ["category"], unique=False
    )
    op.create_index(
        op.f("ix_security_findings_subject"), "security_findings", ["subject"], unique=False
    )
    op.create_index(
        op.f("ix_security_findings_classification"),
        "security_findings",
        ["classification"],
        unique=False,
    )
    op.create_index(
        op.f("ix_security_findings_severity"), "security_findings", ["severity"], unique=False
    )
    op.create_index(
        op.f("ix_security_findings_rule_id"), "security_findings", ["rule_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_security_findings_rule_id"), table_name="security_findings")
    op.drop_index(op.f("ix_security_findings_severity"), table_name="security_findings")
    op.drop_index(op.f("ix_security_findings_classification"), table_name="security_findings")
    op.drop_index(op.f("ix_security_findings_subject"), table_name="security_findings")
    op.drop_index(op.f("ix_security_findings_category"), table_name="security_findings")
    op.drop_index(op.f("ix_security_findings_page_id"), table_name="security_findings")
    op.drop_index(op.f("ix_security_findings_scan_id"), table_name="security_findings")
    op.drop_table("security_findings")
