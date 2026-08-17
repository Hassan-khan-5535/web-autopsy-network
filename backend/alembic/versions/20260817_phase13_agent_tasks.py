"""phase 13 agent tasks and events

Revision ID: 20260817_phase13
Revises: 20260817_phase12
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "20260817_phase13"
down_revision: Union[str, Sequence[str], None] = "20260817_phase12"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("scans", sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_scans_cancel_requested", "scans", ["cancel_requested"])

    op.create_table(
        "agent_tasks",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("task_key", sa.String(length=120), nullable=False),
        sa.Column("task_type", sa.String(length=80), nullable=False),
        sa.Column("queue_name", sa.String(length=50), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("max_retries", sa.Integer(), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("dependency_keys", sa.JSON(), nullable=False),
        sa.Column("error_reason", sa.Text(), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "task_key", name="uq_agent_tasks_scan_task_key"),
    )
    for column in ("scan_id", "task_key", "task_type", "queue_name", "status"):
        op.create_index(f"ix_agent_tasks_{column}", "agent_tasks", [column])

    op.create_table(
        "agent_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("task_id", sa.UUID(), nullable=True),
        sa.Column("event_type", sa.String(length=60), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["task_id"], ["agent_tasks.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("scan_id", "task_id", "event_type", "created_at"):
        op.create_index(f"ix_agent_events_{column}", "agent_events", [column])


def downgrade() -> None:
    for column in ("created_at", "event_type", "task_id", "scan_id"):
        op.drop_index(f"ix_agent_events_{column}", table_name="agent_events")
    op.drop_table("agent_events")
    for column in ("status", "queue_name", "task_type", "task_key", "scan_id"):
        op.drop_index(f"ix_agent_tasks_{column}", table_name="agent_tasks")
    op.drop_table("agent_tasks")
    op.drop_index("ix_scans_cancel_requested", table_name="scans")
    op.drop_column("scans", "finished_at")
    op.drop_column("scans", "queued_at")
    op.drop_column("scans", "cancel_requested")
