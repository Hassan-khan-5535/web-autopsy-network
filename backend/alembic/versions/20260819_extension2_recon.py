"""Extension 2 normalized Recon Agent storage.

Revision ID: 20260819_extension2
Revises: 20260819_extension1
Create Date: 2026-08-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260819_extension2"
down_revision: str | Sequence[str] | None = "20260819_extension1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("recon_mode", sa.String(length=30), nullable=False, server_default="disabled"))
    op.add_column("scans", sa.Column("requests_used", sa.Integer(), nullable=False, server_default="0"))

    op.create_table(
        "recon_assets",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_type", sa.String(length=50), nullable=False),
        sa.Column("value", sa.String(length=2048), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("source", sa.String(length=2048), nullable=False),
        sa.Column("discovery_mode", sa.String(length=30), nullable=False, server_default="passive_only"),
        sa.Column("classification", sa.String(length=50), nullable=False, server_default="OBSERVED"),
        sa.Column("scope_status", sa.String(length=30), nullable=False, server_default="in_scope"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("attributes", sa.JSON(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("dedupe_key", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "dedupe_key", name="uq_recon_assets_scan_dedupe"),
    )
    op.create_index("ix_recon_assets_scan_id", "recon_assets", ["scan_id"])
    op.create_index("ix_recon_assets_asset_type", "recon_assets", ["asset_type"])
    op.create_index("ix_recon_assets_value", "recon_assets", ["value"])
    op.create_index("ix_recon_assets_hostname", "recon_assets", ["hostname"])
    op.create_index("ix_recon_assets_discovery_mode", "recon_assets", ["discovery_mode"])
    op.create_index("ix_recon_assets_classification", "recon_assets", ["classification"])
    op.create_index("ix_recon_assets_scope_status", "recon_assets", ["scope_status"])
    op.create_index("ix_recon_assets_dedupe_key", "recon_assets", ["dedupe_key"])

    op.create_table(
        "recon_endpoints",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("endpoint_kind", sa.String(length=50), nullable=False),
        sa.Column("url_or_path", sa.String(length=2048), nullable=False),
        sa.Column("http_method", sa.String(length=20), nullable=False, server_default="UNKNOWN"),
        sa.Column("source", sa.String(length=2048), nullable=False),
        sa.Column("discovery_mode", sa.String(length=30), nullable=False, server_default="passive_only"),
        sa.Column("classification", sa.String(length=50), nullable=False, server_default="INFERRED"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("scope_status", sa.String(length=30), nullable=False, server_default="in_scope"),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(length=255), nullable=True),
        sa.Column("page_id", sa.UUID(as_uuid=True), nullable=True),
        sa.Column("attributes", sa.JSON(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("dedupe_key", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["page_id"], ["pages.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "dedupe_key", name="uq_recon_endpoints_scan_dedupe"),
    )
    op.create_index("ix_recon_endpoints_scan_id", "recon_endpoints", ["scan_id"])
    op.create_index("ix_recon_endpoints_endpoint_kind", "recon_endpoints", ["endpoint_kind"])
    op.create_index("ix_recon_endpoints_url_or_path", "recon_endpoints", ["url_or_path"])
    op.create_index("ix_recon_endpoints_discovery_mode", "recon_endpoints", ["discovery_mode"])
    op.create_index("ix_recon_endpoints_classification", "recon_endpoints", ["classification"])
    op.create_index("ix_recon_endpoints_scope_status", "recon_endpoints", ["scope_status"])
    op.create_index("ix_recon_endpoints_page_id", "recon_endpoints", ["page_id"])
    op.create_index("ix_recon_endpoints_dedupe_key", "recon_endpoints", ["dedupe_key"])

    op.create_table(
        "recon_parameters",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("endpoint_id", sa.UUID(as_uuid=True), nullable=True),
        sa.Column("page_id", sa.UUID(as_uuid=True), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("location", sa.String(length=30), nullable=False),
        sa.Column("source", sa.String(length=2048), nullable=False),
        sa.Column("discovery_mode", sa.String(length=30), nullable=False, server_default="passive_only"),
        sa.Column("classification", sa.String(length=50), nullable=False, server_default="INFERRED"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("scope_status", sa.String(length=30), nullable=False, server_default="in_scope"),
        sa.Column("example_value", sa.String(length=1024), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("dedupe_key", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["endpoint_id"], ["recon_endpoints.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["page_id"], ["pages.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "dedupe_key", name="uq_recon_parameters_scan_dedupe"),
    )
    op.create_index("ix_recon_parameters_scan_id", "recon_parameters", ["scan_id"])
    op.create_index("ix_recon_parameters_endpoint_id", "recon_parameters", ["endpoint_id"])
    op.create_index("ix_recon_parameters_page_id", "recon_parameters", ["page_id"])
    op.create_index("ix_recon_parameters_name", "recon_parameters", ["name"])
    op.create_index("ix_recon_parameters_location", "recon_parameters", ["location"])
    op.create_index("ix_recon_parameters_discovery_mode", "recon_parameters", ["discovery_mode"])
    op.create_index("ix_recon_parameters_classification", "recon_parameters", ["classification"])
    op.create_index("ix_recon_parameters_scope_status", "recon_parameters", ["scope_status"])
    op.create_index("ix_recon_parameters_dedupe_key", "recon_parameters", ["dedupe_key"])


def downgrade() -> None:
    op.drop_index("ix_recon_parameters_dedupe_key", table_name="recon_parameters")
    op.drop_index("ix_recon_parameters_scope_status", table_name="recon_parameters")
    op.drop_index("ix_recon_parameters_classification", table_name="recon_parameters")
    op.drop_index("ix_recon_parameters_discovery_mode", table_name="recon_parameters")
    op.drop_index("ix_recon_parameters_location", table_name="recon_parameters")
    op.drop_index("ix_recon_parameters_name", table_name="recon_parameters")
    op.drop_index("ix_recon_parameters_page_id", table_name="recon_parameters")
    op.drop_index("ix_recon_parameters_endpoint_id", table_name="recon_parameters")
    op.drop_index("ix_recon_parameters_scan_id", table_name="recon_parameters")
    op.drop_table("recon_parameters")

    op.drop_index("ix_recon_endpoints_dedupe_key", table_name="recon_endpoints")
    op.drop_index("ix_recon_endpoints_page_id", table_name="recon_endpoints")
    op.drop_index("ix_recon_endpoints_scope_status", table_name="recon_endpoints")
    op.drop_index("ix_recon_endpoints_classification", table_name="recon_endpoints")
    op.drop_index("ix_recon_endpoints_discovery_mode", table_name="recon_endpoints")
    op.drop_index("ix_recon_endpoints_url_or_path", table_name="recon_endpoints")
    op.drop_index("ix_recon_endpoints_endpoint_kind", table_name="recon_endpoints")
    op.drop_index("ix_recon_endpoints_scan_id", table_name="recon_endpoints")
    op.drop_table("recon_endpoints")

    for index_name in (
        "ix_recon_assets_dedupe_key",
        "ix_recon_assets_scope_status",
        "ix_recon_assets_classification",
        "ix_recon_assets_discovery_mode",
        "ix_recon_assets_hostname",
        "ix_recon_assets_value",
        "ix_recon_assets_asset_type",
        "ix_recon_assets_scan_id",
    ):
        op.drop_index(index_name, table_name="recon_assets")
    op.drop_table("recon_assets")
    op.drop_column("scans", "requests_used")
    op.drop_column("scans", "recon_mode")
