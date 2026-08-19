"""Extension 11 transparent risk prioritization.

Revision ID: 20260819_extension11
Revises: 20260819_extension10
Create Date: 2026-08-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260819_extension11"
down_revision: str | Sequence[str] | None = "20260819_extension10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("security_finding_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("deterministic_version", sa.String(length=50), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("risk_band", sa.String(length=30), nullable=False, server_default="info"),
        sa.Column("eligible_for_prioritization", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("evidence_state", sa.String(length=30), nullable=False, server_default="not_reviewed"),
        sa.Column("score_components", sa.JSON(), nullable=False),
        sa.Column("decision_notes", sa.JSON(), nullable=False),
        sa.Column("evidence_snapshot", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["security_finding_id"], ["security_findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "security_finding_id", name="uq_risk_assessments_scan_finding"),
    )
    op.create_table(
        "scan_risk_summaries",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("website_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("deterministic_version", sa.String(length=50), nullable=False),
        sa.Column("overall_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("risk_band", sa.String(length=30), nullable=False, server_default="info"),
        sa.Column("eligible_assessment_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("assessment_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )
    for name, table, column in (
        ("ix_risk_assessments_scan_id", "risk_assessments", "scan_id"),
        ("ix_risk_assessments_security_finding_id", "risk_assessments", "security_finding_id"),
        ("ix_risk_assessments_deterministic_version", "risk_assessments", "deterministic_version"),
        ("ix_risk_assessments_risk_score", "risk_assessments", "risk_score"),
        ("ix_risk_assessments_risk_band", "risk_assessments", "risk_band"),
        ("ix_risk_assessments_eligible_for_prioritization", "risk_assessments", "eligible_for_prioritization"),
        ("ix_risk_assessments_evidence_state", "risk_assessments", "evidence_state"),
        ("ix_scan_risk_summaries_scan_id", "scan_risk_summaries", "scan_id"),
        ("ix_scan_risk_summaries_website_id", "scan_risk_summaries", "website_id"),
        ("ix_scan_risk_summaries_deterministic_version", "scan_risk_summaries", "deterministic_version"),
        ("ix_scan_risk_summaries_overall_score", "scan_risk_summaries", "overall_score"),
        ("ix_scan_risk_summaries_risk_band", "scan_risk_summaries", "risk_band"),
    ):
        op.create_index(name, table, [column])


def downgrade() -> None:
    for name, table in (
        ("ix_scan_risk_summaries_risk_band", "scan_risk_summaries"),
        ("ix_scan_risk_summaries_overall_score", "scan_risk_summaries"),
        ("ix_scan_risk_summaries_deterministic_version", "scan_risk_summaries"),
        ("ix_scan_risk_summaries_website_id", "scan_risk_summaries"),
        ("ix_scan_risk_summaries_scan_id", "scan_risk_summaries"),
        ("ix_risk_assessments_evidence_state", "risk_assessments"),
        ("ix_risk_assessments_eligible_for_prioritization", "risk_assessments"),
        ("ix_risk_assessments_risk_band", "risk_assessments"),
        ("ix_risk_assessments_risk_score", "risk_assessments"),
        ("ix_risk_assessments_deterministic_version", "risk_assessments"),
        ("ix_risk_assessments_security_finding_id", "risk_assessments"),
        ("ix_risk_assessments_scan_id", "risk_assessments"),
    ):
        op.drop_index(name, table_name=table)
    op.drop_table("scan_risk_summaries")
    op.drop_table("risk_assessments")
