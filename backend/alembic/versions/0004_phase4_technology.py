"""phase 4 technology dna

Revision ID: 0004_phase4_technology
Revises: 0003_phase3_crawler
Create Date: 2026-08-16 00:00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_phase4_technology"
down_revision: Union[str, Sequence[str], None] = "0003_phase3_crawler"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("http_responses", sa.Column("raw_body", sa.Text(), nullable=True))

    op.create_table(
        "technologies",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("canonical_name", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("classification", sa.String(length=30), nullable=False, server_default="inferred"),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("confidence_band", sa.String(length=30), nullable=False),
        sa.Column("rule_version", sa.String(length=50), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_technologies_scan_id"), "technologies", ["scan_id"], unique=False)
    op.create_index(op.f("ix_technologies_canonical_name"), "technologies", ["canonical_name"], unique=False)
    op.create_index(op.f("ix_technologies_category"), "technologies", ["category"], unique=False)

    op.create_table(
        "technology_evidence",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("technology_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("page_id", sa.UUID(as_uuid=True), nullable=True),
        sa.Column("signal_type", sa.String(length=50), nullable=False),
        sa.Column("match_rule", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=2048), nullable=False),
        sa.Column("observation", sa.Text(), nullable=False),
        sa.Column("match_weight", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["technology_id"], ["technologies.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["page_id"], ["pages.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_technology_evidence_technology_id"),
        "technology_evidence",
        ["technology_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_technology_evidence_scan_id"), "technology_evidence", ["scan_id"], unique=False
    )
    op.create_index(
        op.f("ix_technology_evidence_page_id"), "technology_evidence", ["page_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_technology_evidence_page_id"), table_name="technology_evidence")
    op.drop_index(op.f("ix_technology_evidence_scan_id"), table_name="technology_evidence")
    op.drop_index(op.f("ix_technology_evidence_technology_id"), table_name="technology_evidence")
    op.drop_table("technology_evidence")
    op.drop_index(op.f("ix_technologies_category"), table_name="technologies")
    op.drop_index(op.f("ix_technologies_canonical_name"), table_name="technologies")
    op.drop_index(op.f("ix_technologies_scan_id"), table_name="technologies")
    op.drop_table("technologies")
    op.drop_column("http_responses", "raw_body")
