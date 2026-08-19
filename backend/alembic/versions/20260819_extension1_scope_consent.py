"""Extension 1 scope, consent, and scan control.

Revision ID: 20260819_extension1
Revises: phase14_indexes
"""

from alembic import op
import sqlalchemy as sa

revision = "20260819_extension1"
down_revision = "phase14_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("assessment_profile", sa.String(length=30), nullable=True, server_default="legacy_passive"),
    )
    op.add_column(
        "scans",
        sa.Column("max_requests", sa.Integer(), nullable=True, server_default="30"),
    )
    op.add_column(
        "scans",
        sa.Column("pause_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_scans_assessment_profile", "scans", ["assessment_profile"], unique=False)

    op.create_table(
        "assessment_authorizations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_type", sa.String(length=50), nullable=False),
        sa.Column("actor_id", sa.String(length=255), nullable=False),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column("allowed_paths", sa.JSON(), nullable=False),
        sa.Column("excluded_paths", sa.JSON(), nullable=False),
        sa.Column("allowed_domains", sa.JSON(), nullable=False),
        sa.Column("assessment_profile", sa.String(length=30), nullable=False),
        sa.Column("robots_override", sa.Boolean(), nullable=False),
        sa.Column("max_depth", sa.Integer(), nullable=False),
        sa.Column("max_pages", sa.Integer(), nullable=False),
        sa.Column("max_requests", sa.Integer(), nullable=False),
        sa.Column("max_concurrency", sa.Integer(), nullable=False),
        sa.Column("rate_limit_per_host_ms", sa.Integer(), nullable=False),
        sa.Column("test_account_ref", sa.String(length=255), nullable=True),
        sa.Column("auth_secret_encrypted", sa.Text(), nullable=True),
        sa.Column("auth_secret_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("consent_hash", sa.String(length=64), nullable=False),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("policy_version", sa.String(length=50), nullable=False),
        sa.Column("scope_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_index("ix_assessment_authorizations_scan_id", "assessment_authorizations", ["scan_id"], unique=False)
    op.create_index("ix_assessment_authorizations_authorized_at", "assessment_authorizations", ["authorized_at"], unique=False)

    op.create_table(
        "assessment_audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_id", sa.Uuid(), nullable=True),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("actor_id", sa.String(length=255), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["authorization_id"], ["assessment_authorizations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_hash"),
        sa.UniqueConstraint("scan_id", "sequence_number", name="uq_assessment_audit_scan_sequence"),
    )
    op.create_index("ix_assessment_audit_events_scan_id", "assessment_audit_events", ["scan_id"], unique=False)
    op.create_index("ix_assessment_audit_events_authorization_id", "assessment_audit_events", ["authorization_id"], unique=False)
    op.create_index("ix_assessment_audit_events_event_type", "assessment_audit_events", ["event_type"], unique=False)
    op.create_index("ix_assessment_audit_events_created_at", "assessment_audit_events", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_assessment_audit_events_created_at", table_name="assessment_audit_events")
    op.drop_index("ix_assessment_audit_events_event_type", table_name="assessment_audit_events")
    op.drop_index("ix_assessment_audit_events_authorization_id", table_name="assessment_audit_events")
    op.drop_index("ix_assessment_audit_events_scan_id", table_name="assessment_audit_events")
    op.drop_table("assessment_audit_events")
    op.drop_index("ix_assessment_authorizations_authorized_at", table_name="assessment_authorizations")
    op.drop_index("ix_assessment_authorizations_scan_id", table_name="assessment_authorizations")
    op.drop_table("assessment_authorizations")
    op.drop_index("ix_scans_assessment_profile", table_name="scans")
    op.drop_column("scans", "pause_requested")
    op.drop_column("scans", "max_requests")
    op.drop_column("scans", "assessment_profile")
