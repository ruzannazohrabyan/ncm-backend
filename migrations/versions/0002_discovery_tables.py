"""discovery tables

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-18 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "discovery_jobs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("org_id", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("ip_range", sa.String(100), nullable=False),
        sa.Column("ports", sa.JSON(), nullable=False),
        sa.Column("timeout", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("total_hosts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("scanned_hosts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("found_hosts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_msg", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "discovered_hosts",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("job_id", sa.String(), nullable=False),
        sa.Column("org_id", sa.String(), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("is_alive", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("open_ports", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("vendor_hint", sa.String(100), nullable=True),
        sa.Column("os_type_hint", sa.String(100), nullable=True),
        sa.Column("imported", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("device_id", sa.String(), nullable=True),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["job_id"], ["discovery_jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("discovered_hosts")
    op.drop_table("discovery_jobs")
