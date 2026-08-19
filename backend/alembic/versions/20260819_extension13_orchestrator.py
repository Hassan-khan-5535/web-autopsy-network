"""Extension 13 multi-agent investigation orchestrator persistence.

Revision ID: 20260819_extension13
Revises: 20260819_extension12
Create Date: 2026-08-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260819_extension13"
down_revision: str | Sequence[str] | None = "20260819_extension12"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("orchestration_state", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))
    op.add_column("scans", sa.Column("orchestration_budget", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))
    op.add_column("agent_tasks", sa.Column("event_requirements", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))
    op.add_column("agent_tasks", sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_agent_tasks_deadline_at", "agent_tasks", ["deadline_at"])
    op.add_column("agent_events", sa.Column("event_key", sa.String(length=255), nullable=True))
    op.create_index("ix_agent_events_event_key", "agent_events", ["event_key"])


def downgrade() -> None:
    op.drop_index("ix_agent_events_event_key", table_name="agent_events")
    op.drop_column("agent_events", "event_key")
    op.drop_index("ix_agent_tasks_deadline_at", table_name="agent_tasks")
    op.drop_column("agent_tasks", "deadline_at")
    op.drop_column("agent_tasks", "event_requirements")
    op.drop_column("scans", "orchestration_budget")
    op.drop_column("scans", "orchestration_state")
