"""phase 2 schema

Revision ID: 0002_phase2_schema
Revises: 0001_phase1_baseline
Create Date: 2026-08-16 00:00:00
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002_phase2_schema"
down_revision: Union[str, Sequence[str], None] = "0001_phase1_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # websites
    op.create_table(
        'websites',
        sa.Column('id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('tenant_id', sa.String(length=255), nullable=False),
        sa.Column('canonical_origin', sa.String(length=2048), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_websites_tenant_id'), 'websites', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_websites_canonical_origin'), 'websites', ['canonical_origin'], unique=False)

    # scans
    op.create_table(
        'scans',
        sa.Column('id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('website_id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('state', sa.String(length=50), nullable=False),
        sa.Column('requested_url', sa.String(length=2048), nullable=False),
        sa.Column('error_reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['website_id'], ['websites.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scans_website_id'), 'scans', ['website_id'], unique=False)
    op.create_index(op.f('ix_scans_state'), 'scans', ['state'], unique=False)
    op.create_index(op.f('ix_scans_created_at'), 'scans', ['created_at'], unique=False)

    # pages
    op.create_table(
        'pages',
        sa.Column('id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('canonical_url', sa.String(length=2048), nullable=False),
        sa.Column('depth', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_pages_scan_id'), 'pages', ['scan_id'], unique=False)

    # http_responses
    op.create_table(
        'http_responses',
        sa.Column('id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('page_id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=False),
        sa.Column('final_url', sa.String(length=2048), nullable=False),
        sa.Column('content_type', sa.String(length=255), nullable=True),
        sa.Column('timings_ms', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['page_id'], ['pages.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_http_responses_page_id'), 'http_responses', ['page_id'], unique=False)
    op.create_index(op.f('ix_http_responses_status_code'), 'http_responses', ['status_code'], unique=False)

    # headers
    op.create_table(
        'headers',
        sa.Column('id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('http_response_id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['http_response_id'], ['http_responses.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_headers_http_response_id'), 'headers', ['http_response_id'], unique=False)
    op.create_index(op.f('ix_headers_name'), 'headers', ['name'], unique=False)

    # resources
    op.create_table(
        'resources',
        sa.Column('id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('page_id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('url', sa.String(length=2048), nullable=True),
        sa.Column('type', sa.String(length=50), nullable=False),
        sa.Column('attributes', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(['page_id'], ['pages.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_resources_page_id'), 'resources', ['page_id'], unique=False)

    # observations
    op.create_table(
        'observations',
        sa.Column('id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_id', sa.UUID(as_uuid=True), nullable=False),
        sa.Column('category', sa.String(length=100), nullable=False),
        sa.Column('subject', sa.String(length=2048), nullable=False),
        sa.Column('observation', sa.Text(), nullable=False),
        sa.Column('classification', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_observations_scan_id'), 'observations', ['scan_id'], unique=False)
    op.create_index(op.f('ix_observations_category'), 'observations', ['category'], unique=False)
    op.create_index(op.f('ix_observations_subject'), 'observations', ['subject'], unique=False)


def downgrade() -> None:
    op.drop_table('observations')
    op.drop_table('resources')
    op.drop_table('headers')
    op.drop_table('http_responses')
    op.drop_table('pages')
    op.drop_table('scans')
    op.drop_table('websites')
