"""add config_type to config_snapshots

Adds config_type column to distinguish between running-config and startup-config.
Also adds is_latest and synced_at columns for tracking sync status.

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-19 22:30:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add config_type column (running | startup)
    op.add_column(
        "config_snapshots",
        sa.Column("config_type", sa.String(50), nullable=False, server_default="running"),
    )

    # Add is_latest to track if this is the latest snapshot of its type
    op.add_column(
        "config_snapshots",
        sa.Column("is_latest", sa.Boolean(), nullable=False, server_default="true"),
    )

    # Add synced_at to track when running and startup configs last matched
    op.add_column(
        "config_snapshots",
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("config_snapshots", "synced_at")
    op.drop_column("config_snapshots", "is_latest")
    op.drop_column("config_snapshots", "config_type")
