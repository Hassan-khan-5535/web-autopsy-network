"""Extension 8 CVE and technology intelligence.

Revision ID: 20260819_extension8
Revises: 20260819_extension3
Create Date: 2026-08-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260819_extension8"
down_revision: str | Sequence[str] | None = "20260819_extension3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _uuid():
    return sa.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "cve_feed_runs",
        sa.Column("id", _uuid(), nullable=False),
        sa.Column("source_name", sa.String(length=100), nullable=False),
        sa.Column("source_url", sa.String(length=2048), nullable=False),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_last_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("record_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("stale_after_seconds", sa.Integer(), nullable=False, server_default="86400"),
        sa.Column("is_stale", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="succeeded"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cve_feed_runs_source_name", "cve_feed_runs", ["source_name"])
    op.create_index("ix_cve_feed_runs_retrieved_at", "cve_feed_runs", ["retrieved_at"])
    op.create_index("ix_cve_feed_runs_is_stale", "cve_feed_runs", ["is_stale"])

    op.create_table(
        "cve_intelligence",
        sa.Column("id", _uuid(), nullable=False),
        sa.Column("source_name", sa.String(length=100), nullable=False),
        sa.Column("cve_id", sa.String(length=30), nullable=False),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("cwe", sa.JSON(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=255), nullable=True),
        sa.Column("affected_ranges", sa.JSON(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_url", sa.String(length=2048), nullable=False),
        sa.Column("feed_retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("feed_stale_after_seconds", sa.Integer(), nullable=False, server_default="86400"),
        sa.Column("feed_is_stale", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("kev_listed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("kev_date_added", sa.DateTime(timezone=True), nullable=True),
        sa.Column("kev_due_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provenance", sa.JSON(), nullable=True),
        sa.Column("dedupe_key", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_name", "cve_id", name="uq_cve_intelligence_source_cve"),
    )
    for index_name, column in (
        ("ix_cve_intelligence_source_name", "source_name"),
        ("ix_cve_intelligence_cve_id", "cve_id"),
        ("ix_cve_intelligence_vendor", "vendor"),
        ("ix_cve_intelligence_product", "product"),
        ("ix_cve_intelligence_feed_retrieved_at", "feed_retrieved_at"),
        ("ix_cve_intelligence_feed_is_stale", "feed_is_stale"),
        ("ix_cve_intelligence_kev_listed", "kev_listed"),
        ("ix_cve_intelligence_dedupe_key", "dedupe_key"),
    ):
        op.create_index(index_name, "cve_intelligence", [column])

    op.create_table(
        "technology_cve_matches",
        sa.Column("id", _uuid(), nullable=False),
        sa.Column("scan_id", _uuid(), nullable=False),
        sa.Column("technology_id", _uuid(), nullable=False),
        sa.Column("cve_intelligence_id", _uuid(), nullable=True),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=False),
        sa.Column("detected_version", sa.String(length=100), nullable=True),
        sa.Column("version_source", sa.String(length=2048), nullable=True),
        sa.Column("detection_confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("version_evidence_confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("applicability_confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("applicability_state", sa.String(length=40), nullable=False),
        sa.Column("match_reason", sa.Text(), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["technology_id"], ["technologies.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["cve_intelligence_id"], ["cve_intelligence.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "technology_id", "cve_intelligence_id", name="uq_technology_cve_scan_match"),
    )
    for index_name, column in (
        ("ix_technology_cve_matches_scan_id", "scan_id"),
        ("ix_technology_cve_matches_technology_id", "technology_id"),
        ("ix_technology_cve_matches_cve_intelligence_id", "cve_intelligence_id"),
        ("ix_technology_cve_matches_applicability_state", "applicability_state"),
        ("ix_technology_cve_matches_created_at", "created_at"),
    ):
        op.create_index(index_name, "technology_cve_matches", [column])


def downgrade() -> None:
    for index_name in (
        "ix_technology_cve_matches_created_at",
        "ix_technology_cve_matches_applicability_state",
        "ix_technology_cve_matches_cve_intelligence_id",
        "ix_technology_cve_matches_technology_id",
        "ix_technology_cve_matches_scan_id",
    ):
        op.drop_index(index_name, table_name="technology_cve_matches")
    op.drop_table("technology_cve_matches")
    for index_name in (
        "ix_cve_intelligence_dedupe_key",
        "ix_cve_intelligence_kev_listed",
        "ix_cve_intelligence_feed_is_stale",
        "ix_cve_intelligence_feed_retrieved_at",
        "ix_cve_intelligence_product",
        "ix_cve_intelligence_vendor",
        "ix_cve_intelligence_cve_id",
        "ix_cve_intelligence_source_name",
    ):
        op.drop_index(index_name, table_name="cve_intelligence")
    op.drop_table("cve_intelligence")
    for index_name in ("ix_cve_feed_runs_is_stale", "ix_cve_feed_runs_retrieved_at", "ix_cve_feed_runs_source_name"):
        op.drop_index(index_name, table_name="cve_feed_runs")
    op.drop_table("cve_feed_runs")
