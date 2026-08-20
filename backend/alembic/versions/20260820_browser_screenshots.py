"""Persist bounded safe browser screenshots.

Revision ID: 20260820_browser_screenshots
Revises: 20260819_extension16
Create Date: 2026-08-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260820_browser_screenshots"
down_revision: str | Sequence[str] | None = "20260819_extension16"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "browser_screenshots",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("page_id", sa.Uuid(), sa.ForeignKey("pages.id", ondelete="CASCADE"), nullable=False),
        sa.Column("image_base64", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("content_type", sa.String(length=50), nullable=False, server_default="image/png"),
        sa.Column("width", sa.Integer(), nullable=True),
        sa.Column("height", sa.Integer(), nullable=True),
        sa.Column("redaction_status", sa.String(length=50), nullable=False, server_default="safe_public_page"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_browser_screenshots_scan_id", "browser_screenshots", ["scan_id"])
    op.create_index("ix_browser_screenshots_page_id", "browser_screenshots", ["page_id"])
    op.create_index("ix_browser_screenshots_sha256", "browser_screenshots", ["sha256"])
    op.create_index("ix_browser_screenshots_created_at", "browser_screenshots", ["created_at"])


def downgrade() -> None:
    op.drop_table("browser_screenshots")
