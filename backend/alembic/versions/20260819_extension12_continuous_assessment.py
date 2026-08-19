"""Extension 12 differential and continuous assessment.

Revision ID: 20260819_extension12
Revises: 20260819_extension11
Create Date: 2026-08-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260819_extension12"
down_revision: str | Sequence[str] | None = "20260819_extension11"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "security_posture_snapshots",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("website_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("posture_version", sa.String(length=50), nullable=False),
        sa.Column("overall_risk_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("risk_band", sa.String(length=30), nullable=False, server_default="info"),
        sa.Column("posture_summary", sa.JSON(), nullable=False),
        sa.Column("comparison_summary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_table(
        "recurring_scan_schedules",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("website_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("source_scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("source_authorization_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column("cadence", sa.String(length=30), nullable=False, server_default="weekly"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_scan_id", sa.UUID(as_uuid=True), nullable=True),
        sa.Column("blocked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_block_reason", sa.Text(), nullable=True),
        sa.Column("authorization_snapshot", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False, server_default="system"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_authorization_id"], ["assessment_authorizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["last_scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("scans") as batch_op:
        batch_op.add_column(sa.Column("recurring_schedule_id", sa.UUID(as_uuid=True), nullable=True))
        batch_op.create_foreign_key("fk_scans_recurring_schedule", "recurring_scan_schedules", ["recurring_schedule_id"], ["id"], ondelete="SET NULL")
    for name, table, column in (
        ("ix_security_posture_snapshots_website_id", "security_posture_snapshots", "website_id"),
        ("ix_security_posture_snapshots_scan_id", "security_posture_snapshots", "scan_id"),
        ("ix_security_posture_snapshots_posture_version", "security_posture_snapshots", "posture_version"),
        ("ix_security_posture_snapshots_overall_risk_score", "security_posture_snapshots", "overall_risk_score"),
        ("ix_security_posture_snapshots_risk_band", "security_posture_snapshots", "risk_band"),
        ("ix_security_posture_snapshots_created_at", "security_posture_snapshots", "created_at"),
        ("ix_recurring_scan_schedules_website_id", "recurring_scan_schedules", "website_id"),
        ("ix_recurring_scan_schedules_source_scan_id", "recurring_scan_schedules", "source_scan_id"),
        ("ix_recurring_scan_schedules_source_authorization_id", "recurring_scan_schedules", "source_authorization_id"),
        ("ix_recurring_scan_schedules_cadence", "recurring_scan_schedules", "cadence"),
        ("ix_recurring_scan_schedules_enabled", "recurring_scan_schedules", "enabled"),
        ("ix_recurring_scan_schedules_next_run_at", "recurring_scan_schedules", "next_run_at"),
        ("ix_recurring_scan_schedules_last_scan_id", "recurring_scan_schedules", "last_scan_id"),
        ("ix_recurring_scan_schedules_created_at", "recurring_scan_schedules", "created_at"),
        ("ix_scans_recurring_schedule_id", "scans", "recurring_schedule_id"),
    ):
        op.create_index(name, table, [column])


def downgrade() -> None:
    for name, table in (
        ("ix_scans_recurring_schedule_id", "scans"),
        ("ix_recurring_scan_schedules_created_at", "recurring_scan_schedules"),
        ("ix_recurring_scan_schedules_last_scan_id", "recurring_scan_schedules"),
        ("ix_recurring_scan_schedules_next_run_at", "recurring_scan_schedules"),
        ("ix_recurring_scan_schedules_enabled", "recurring_scan_schedules"),
        ("ix_recurring_scan_schedules_cadence", "recurring_scan_schedules"),
        ("ix_recurring_scan_schedules_source_authorization_id", "recurring_scan_schedules"),
        ("ix_recurring_scan_schedules_source_scan_id", "recurring_scan_schedules"),
        ("ix_recurring_scan_schedules_website_id", "recurring_scan_schedules"),
        ("ix_security_posture_snapshots_created_at", "security_posture_snapshots"),
        ("ix_security_posture_snapshots_risk_band", "security_posture_snapshots"),
        ("ix_security_posture_snapshots_overall_risk_score", "security_posture_snapshots"),
        ("ix_security_posture_snapshots_posture_version", "security_posture_snapshots"),
        ("ix_security_posture_snapshots_scan_id", "security_posture_snapshots"),
        ("ix_security_posture_snapshots_website_id", "security_posture_snapshots"),
    ):
        op.drop_index(name, table_name=table)
    with op.batch_alter_table("scans") as batch_op:
        batch_op.drop_constraint("fk_scans_recurring_schedule", type_="foreignkey")
        batch_op.drop_column("recurring_schedule_id")
    op.drop_table("recurring_scan_schedules")
    op.drop_table("security_posture_snapshots")
