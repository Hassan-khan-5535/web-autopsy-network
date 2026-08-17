"""phase 12 cause of death diagnosis

Revision ID: 20260817_phase12
Revises: 20260817_phase11
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20260817_phase12"
down_revision: Union[str, Sequence[str], None] = "20260817_phase11"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cause_of_death_diagnoses",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("primary_issue", sa.JSON(), nullable=False),
        sa.Column("secondary_issues", sa.JSON(), nullable=False),
        sa.Column("contributing_factors", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("ai_narrative", sa.Text(), nullable=True),
        sa.Column("ai_evidence", sa.JSON(), nullable=False),
        sa.Column("disclaimer", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_index("ix_cause_of_death_diagnoses_scan_id", "cause_of_death_diagnoses", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_cause_of_death_diagnoses_scan_id", table_name="cause_of_death_diagnoses")
    op.drop_table("cause_of_death_diagnoses")


__all__ = ["revision", "down_revision", "upgrade", "downgrade"]
