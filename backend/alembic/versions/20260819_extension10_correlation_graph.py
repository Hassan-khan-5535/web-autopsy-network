"""Extension 10 correlation and attack-surface graph.

Revision ID: 20260819_extension10
Revises: 20260819_extension9
Create Date: 2026-08-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260819_extension10"
down_revision: str | Sequence[str] | None = "20260819_extension9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "attack_surface_graph_nodes",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=False),
        sa.Column("natural_key", sa.String(length=255), nullable=False),
        sa.Column("label", sa.String(length=2048), nullable=False),
        sa.Column("classification", sa.String(length=30), nullable=False, server_default="OBSERVED"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("attributes", sa.JSON(), nullable=True),
        sa.Column("provenance", sa.JSON(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "entity_type", "natural_key", name="uq_attack_surface_graph_nodes_scan_entity_key"),
    )
    op.create_table(
        "attack_surface_graph_edges",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("source_node_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("target_node_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("relationship_type", sa.String(length=80), nullable=False),
        sa.Column("classification", sa.String(length=30), nullable=False, server_default="OBSERVED"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("attributes", sa.JSON(), nullable=True),
        sa.Column("provenance", sa.JSON(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["source_node_id"], ["attack_surface_graph_nodes.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_node_id"], ["attack_surface_graph_nodes.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "relationship_type", "source_node_id", "target_node_id", name="uq_attack_surface_graph_edges_scan_relationship"),
    )
    op.create_table(
        "attack_surface_graph_updates",
        sa.Column("id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.UUID(as_uuid=True), nullable=False),
        sa.Column("source_event", sa.String(length=120), nullable=False),
        sa.Column("correlation_version", sa.String(length=50), nullable=False),
        sa.Column("inserted_node_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("refreshed_node_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("inserted_edge_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("refreshed_edge_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    for name, table, column in (
        ("ix_attack_surface_graph_nodes_scan_id", "attack_surface_graph_nodes", "scan_id"),
        ("ix_attack_surface_graph_nodes_entity_type", "attack_surface_graph_nodes", "entity_type"),
        ("ix_attack_surface_graph_nodes_natural_key", "attack_surface_graph_nodes", "natural_key"),
        ("ix_attack_surface_graph_edges_scan_id", "attack_surface_graph_edges", "scan_id"),
        ("ix_attack_surface_graph_edges_source_node_id", "attack_surface_graph_edges", "source_node_id"),
        ("ix_attack_surface_graph_edges_target_node_id", "attack_surface_graph_edges", "target_node_id"),
        ("ix_attack_surface_graph_edges_relationship_type", "attack_surface_graph_edges", "relationship_type"),
        ("ix_attack_surface_graph_updates_scan_id", "attack_surface_graph_updates", "scan_id"),
        ("ix_attack_surface_graph_updates_source_event", "attack_surface_graph_updates", "source_event"),
        ("ix_attack_surface_graph_updates_correlation_version", "attack_surface_graph_updates", "correlation_version"),
        ("ix_attack_surface_graph_updates_created_at", "attack_surface_graph_updates", "created_at"),
    ):
        op.create_index(name, table, [column])


def downgrade() -> None:
    for name, table in (
        ("ix_attack_surface_graph_updates_created_at", "attack_surface_graph_updates"),
        ("ix_attack_surface_graph_updates_correlation_version", "attack_surface_graph_updates"),
        ("ix_attack_surface_graph_updates_source_event", "attack_surface_graph_updates"),
        ("ix_attack_surface_graph_updates_scan_id", "attack_surface_graph_updates"),
        ("ix_attack_surface_graph_edges_relationship_type", "attack_surface_graph_edges"),
        ("ix_attack_surface_graph_edges_target_node_id", "attack_surface_graph_edges"),
        ("ix_attack_surface_graph_edges_source_node_id", "attack_surface_graph_edges"),
        ("ix_attack_surface_graph_edges_scan_id", "attack_surface_graph_edges"),
        ("ix_attack_surface_graph_nodes_natural_key", "attack_surface_graph_nodes"),
        ("ix_attack_surface_graph_nodes_entity_type", "attack_surface_graph_nodes"),
        ("ix_attack_surface_graph_nodes_scan_id", "attack_surface_graph_nodes"),
    ):
        op.drop_index(name, table_name=table)
    op.drop_table("attack_surface_graph_updates")
    op.drop_table("attack_surface_graph_edges")
    op.drop_table("attack_surface_graph_nodes")
