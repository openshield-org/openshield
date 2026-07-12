"""Add the rate_limit_hits table for the Postgres-backed rate limiter.

Revision ID: c7a2e9f1b3d4
Revises: b3f1a2c4d5e6
Create Date: 2026-07-10 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# Revision identifiers, used by Alembic.
revision: str = "c7a2e9f1b3d4"
down_revision: Union[str, Sequence[str], None] = "b3f1a2c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the rate_limit_hits table used by api.rate_limit."""
    op.create_table(
        "rate_limit_hits",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("limit_key", sa.Text(), nullable=False),
        sa.Column("hit_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name="rate_limit_hits_pkey"),
    )
    op.create_index("idx_rate_limit_hits_key_time", "rate_limit_hits", ["limit_key", "hit_at"], unique=False)


def downgrade() -> None:
    """Drop the rate_limit_hits table."""
    op.drop_index("idx_rate_limit_hits_key_time", table_name="rate_limit_hits")
    op.drop_table("rate_limit_hits")
