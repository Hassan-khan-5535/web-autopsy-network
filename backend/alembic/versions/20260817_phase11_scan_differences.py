"""phase 11 scan differences

Revision ID: 20260817_phase11
Revises: c4ad62bb8e7b
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20260817_phase11"
down_revision: Union[str, Sequence[str], None] = "c4ad62bb8e7b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_differences",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("website_id", sa.UUID(), nullable=False),
        sa.Column("scan_a_id", sa.UUID(), nullable=False),
        sa.Column("scan_b_id", sa.UUID(), nullable=False),
        sa.Column("diff_data", sa.JSON(), nullable=False),
        sa.Column("ai_summary", sa.Text(), nullable=True),
        sa.Column("ai_evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_a_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_b_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_differences_website_id", "scan_differences", ["website_id"])
    op.create_index("ix_scan_differences_scan_a_id", "scan_differences", ["scan_a_id"])
    op.create_index("ix_scan_differences_scan_b_id", "scan_differences", ["scan_b_id"])


def downgrade() -> None:
    op.drop_index("ix_scan_differences_scan_b_id", table_name="scan_differences")
    op.drop_index("ix_scan_differences_scan_a_id", table_name="scan_differences")
    op.drop_index("ix_scan_differences_website_id", table_name="scan_differences")
    op.drop_table("scan_differences")


__all__ = ["revision", "down_revision", "upgrade", "downgrade"]
