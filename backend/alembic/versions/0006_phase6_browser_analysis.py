"""phase 6 browser analysis

Revision ID: 0006_phase6_browser_analysis
Revises: 0005_phase5_structure_deps
Create Date: 2026-08-16 18:00:00
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0006_phase6_browser_analysis"
down_revision: Union[str, Sequence[str], None] = "0005_phase5_structure_deps"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("http_responses", sa.Column("rendered_body", sa.Text(), nullable=True))
    op.add_column("http_responses", sa.Column("timing_data", sa.JSON(), nullable=True))
    op.add_column("resources", sa.Column("capture_source", sa.String(length=50), nullable=False, server_default="static_http"))
    op.create_index(op.f("ix_resources_capture_source"), "resources", ["capture_source"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_resources_capture_source"), table_name="resources")
    op.drop_column("resources", "capture_source")
    op.drop_column("http_responses", "timing_data")
    op.drop_column("http_responses", "rendered_body")
