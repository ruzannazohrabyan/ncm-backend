"""device inventory facts

Adds inventory / firmware columns to the ``devices`` table so we can store
the data harvested from ``show version`` (or the equivalent on non-Cisco
platforms) for every device.

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-19 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


_NEW_COLUMNS = (
    ("serial_number", sa.String(100)),
    ("os_name", sa.String(100)),
    ("os_version", sa.String(100)),
    ("os_image", sa.String(255)),
    ("hardware", sa.String(255)),
    ("uptime", sa.String(255)),
)


def upgrade() -> None:
    for name, col_type in _NEW_COLUMNS:
        op.add_column("devices", sa.Column(name, col_type, nullable=True))
    op.add_column(
        "devices",
        sa.Column("facts_updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("devices", "facts_updated_at")
    for name, _ in reversed(_NEW_COLUMNS):
        op.drop_column("devices", name)
