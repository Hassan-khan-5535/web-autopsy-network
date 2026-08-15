"""phase 1 baseline

Revision ID: 0001_phase1_baseline
Revises:
Create Date: 2026-08-15 00:00:00
"""

from typing import Sequence, Union

revision: str = "0001_phase1_baseline"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Establish Alembic versioning without introducing business tables."""


def downgrade() -> None:
    """The Phase 1 baseline has no domain tables to remove."""
