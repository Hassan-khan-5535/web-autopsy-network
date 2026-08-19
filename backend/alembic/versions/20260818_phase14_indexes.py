"""Phase 14 Indexes

Revision ID: phase14_indexes
Revises: 20260817_phase13
Create Date: 2026-08-18 08:50:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "phase14_indexes"
down_revision = "20260817_phase13"
branch_labels = None
depends_on = None

_INDEXES = (
    ("idx_obs_scan_cat", "observations", ["scan_id", "category"]),
    ("idx_inf_scan_cat", "inferences", ["scan_id", "category"]),
    ("idx_sec_scan_sev", "security_findings", ["scan_id", "severity"]),
    ("idx_tasks_scan_status", "agent_tasks", ["scan_id", "status"]),
)


def _existing_tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _existing_indexes(table: str) -> set[str]:
    return {item["name"] for item in sa.inspect(op.get_bind()).get_indexes(table)}


def upgrade() -> None:
    tables = _existing_tables()
    for index_name, table, columns in _INDEXES:
        if table in tables and index_name not in _existing_indexes(table):
            op.create_index(index_name, table, columns)


def downgrade() -> None:
    tables = _existing_tables()
    for index_name, table, _columns in reversed(_INDEXES):
        if table in tables and index_name in _existing_indexes(table):
            op.drop_index(index_name, table_name=table)
