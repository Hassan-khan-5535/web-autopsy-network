"""Phase 14 Indexes

Revision ID: phase14_indexes
Revises: 20260817_phase13_agent_tasks
Create Date: 2026-08-18 08:50:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = 'phase14_indexes'
down_revision = '20260817_phase13_agent_tasks'
branch_labels = None
depends_on = None

def upgrade():
    op.create_index('idx_obs_scan_cat', 'observations', ['scan_id', 'category'])
    op.create_index('idx_inf_scan_cat', 'inferences', ['scan_id', 'category'])
    op.create_index('idx_sec_scan_sev', 'security_findings', ['scan_id', 'severity'])
    op.create_index('idx_tasks_scan_status', 'agent_tasks', ['scan_id', 'status'])

def downgrade():
    op.drop_index('idx_obs_scan_cat', table_name='observations')
    op.drop_index('idx_inf_scan_cat', table_name='inferences')
    op.drop_index('idx_sec_scan_sev', table_name='security_findings')
    op.drop_index('idx_tasks_scan_status', table_name='agent_tasks')
