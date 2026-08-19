"""Extension 9 independent evidence reviews.

Revision ID: 20260819_extension9
Revises: 20260819_extension8
Create Date: 2026-08-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260819_extension9"
down_revision: str | Sequence[str] | None = "20260819_extension8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_reviews",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("security_finding_id", sa.UUID(as_uuid=True), nullable=True),
        sa.Column("candidate_key", sa.String(length=255), nullable=False),
        sa.Column("target", sa.String(length=2048), nullable=False),
        sa.Column("endpoint_or_asset", sa.String(length=2048), nullable=False),
        sa.Column("source_agent", sa.String(length=100), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("finding_state", sa.String(length=30), nullable=False),
        sa.Column("evidence_quality", sa.String(length=30), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("prerequisites_valid", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("reproducibility_state", sa.String(length=30), nullable=False, server_default="not_run"),
        sa.Column("observations", sa.JSON(), nullable=False),
        sa.Column("safe_request_metadata", sa.JSON(), nullable=True),
        sa.Column("provenance", sa.JSON(), nullable=False),
        sa.Column("redacted", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["security_finding_id"], ["security_findings.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "candidate_key", name="uq_evidence_reviews_scan_candidate"),
    )
    for index_name, column in (
        ("ix_evidence_reviews_scan_id", "scan_id"),
        ("ix_evidence_reviews_security_finding_id", "security_finding_id"),
        ("ix_evidence_reviews_candidate_key", "candidate_key"),
        ("ix_evidence_reviews_source_agent", "source_agent"),
        ("ix_evidence_reviews_rule_id", "rule_id"),
        ("ix_evidence_reviews_finding_state", "finding_state"),
        ("ix_evidence_reviews_evidence_quality", "evidence_quality"),
        ("ix_evidence_reviews_created_at", "created_at"),
    ):
        op.create_index(index_name, "evidence_reviews", [column])


def downgrade() -> None:
    for index_name in (
        "ix_evidence_reviews_created_at",
        "ix_evidence_reviews_evidence_quality",
        "ix_evidence_reviews_finding_state",
        "ix_evidence_reviews_rule_id",
        "ix_evidence_reviews_source_agent",
        "ix_evidence_reviews_candidate_key",
        "ix_evidence_reviews_security_finding_id",
        "ix_evidence_reviews_scan_id",
    ):
        op.drop_index(index_name, table_name="evidence_reviews")
    op.drop_table("evidence_reviews")
