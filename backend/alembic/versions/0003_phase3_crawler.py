"""phase 3 controlled crawler

Revision ID: 0003_phase3_crawler
Revises: 0002_phase2_schema
Create Date: 2026-08-16 00:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003_phase3_crawler"
down_revision: str | Sequence[str] | None = "0002_phase2_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("max_depth", sa.Integer(), nullable=False, server_default="2"))
    op.add_column(
        "scans", sa.Column("max_pages", sa.Integer(), nullable=False, server_default="30")
    )
    op.add_column(
        "scans", sa.Column("max_concurrency", sa.Integer(), nullable=False, server_default="2")
    )
    op.add_column(
        "scans", sa.Column("request_delay_ms", sa.Integer(), nullable=False, server_default="1000")
    )
    op.add_column(
        "scans",
        sa.Column(
            "same_domain_mode", sa.String(length=30), nullable=False, server_default="hostname"
        ),
    )

    op.add_column(
        "pages", sa.Column("discovered_from_page_id", sa.UUID(as_uuid=True), nullable=True)
    )
    op.add_column("pages", sa.Column("status_code", sa.Integer(), nullable=True))
    op.add_column("pages", sa.Column("title", sa.String(length=2048), nullable=True))
    op.create_index(
        op.f("ix_pages_discovered_from_page_id"), "pages", ["discovered_from_page_id"], unique=False
    )
    op.create_index(op.f("ix_pages_status_code"), "pages", ["status_code"], unique=False)
    op.create_foreign_key(
        "fk_pages_discovered_from_page_id_pages",
        "pages",
        "pages",
        ["discovered_from_page_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.create_table(
        "page_links",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("source_page_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column("is_external", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["source_page_id"], ["pages.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_page_links_source_page_id"), "page_links", ["source_page_id"], unique=False
    )
    op.create_index(op.f("ix_page_links_is_external"), "page_links", ["is_external"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_page_links_is_external"), table_name="page_links")
    op.drop_index(op.f("ix_page_links_source_page_id"), table_name="page_links")
    op.drop_table("page_links")

    op.drop_constraint("fk_pages_discovered_from_page_id_pages", "pages", type_="foreignkey")
    op.drop_index(op.f("ix_pages_status_code"), table_name="pages")
    op.drop_index(op.f("ix_pages_discovered_from_page_id"), table_name="pages")
    op.drop_column("pages", "title")
    op.drop_column("pages", "status_code")
    op.drop_column("pages", "discovered_from_page_id")

    op.drop_column("scans", "same_domain_mode")
    op.drop_column("scans", "request_delay_ms")
    op.drop_column("scans", "max_concurrency")
    op.drop_column("scans", "max_pages")
    op.drop_column("scans", "max_depth")
