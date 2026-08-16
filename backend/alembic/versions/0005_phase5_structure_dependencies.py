"""phase 5 structure and dependencies

Revision ID: 0005_phase5_structure_dependencies
Revises: 0004_phase4_technology
Create Date: 2026-08-16 12:00:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0005_phase5_structure_deps"

down_revision: Union[str, Sequence[str], None] = "0004_phase4_technology"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "dependencies",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False, server_default="Unclassified"),
        sa.Column("classification", sa.String(length=30), nullable=False, server_default="inferred"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("reference_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("sample_resource_urls", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_dependencies_scan_id"), "dependencies", ["scan_id"], unique=False)
    op.create_index(op.f("ix_dependencies_domain"), "dependencies", ["domain"], unique=False)
    op.create_index(op.f("ix_dependencies_category"), "dependencies", ["category"], unique=False)

    op.create_table(
        "api_endpoints",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("url_or_path", sa.String(length=2048), nullable=False),
        sa.Column("http_method", sa.String(length=20), nullable=False, server_default="UNKNOWN"),
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("classification", sa.String(length=30), nullable=False, server_default="inferred"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("discovered_from_source", sa.String(length=2048), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_api_endpoints_scan_id"), "api_endpoints", ["scan_id"], unique=False)
    op.create_index(op.f("ix_api_endpoints_url_or_path"), "api_endpoints", ["url_or_path"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_api_endpoints_url_or_path"), table_name="api_endpoints")
    op.drop_index(op.f("ix_api_endpoints_scan_id"), table_name="api_endpoints")
    op.drop_table("api_endpoints")

    op.drop_index(op.f("ix_dependencies_category"), table_name="dependencies")
    op.drop_index(op.f("ix_dependencies_domain"), table_name="dependencies")
    op.drop_index(op.f("ix_dependencies_scan_id"), table_name="dependencies")
    op.drop_table("dependencies")
