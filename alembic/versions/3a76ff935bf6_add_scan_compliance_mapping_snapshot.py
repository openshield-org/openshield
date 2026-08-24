"""Add compliance_mapping_snapshot to scans.

Revision ID: 3a76ff935bf6
Revises: d8e4f6a1b2c3
Create Date: 2026-08-22 00:00:00.000000

Chained after d8e4f6a1b2c3 (PR #308, severity contract v1) rather than
directly off c7a2e9f1b3d4: both migrations were cut from the same parent,
which would otherwise fork the Alembic revision graph if both merged
independently. #308 was opened first (2026-08-21 vs. this PR's
2026-08-22), so this one chains after it. If #308 ends up landing after
this PR instead, its migration is the one that needs to move.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers, used by Alembic.
revision: str = "3a76ff935bf6"
down_revision: Union[str, Sequence[str], None] = "d8e4f6a1b2c3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add a nullable JSONB snapshot of each framework's mapping-pack identity.

    Populated by DatabaseManager.save_scan() at scan-completion time, so a
    historical compliance report can show the framework name, edition,
    mapping-pack version and source that were actually in effect for that
    scan instead of reinterpreting it with whatever mapping pack is deployed
    now (issue #302).
    """
    op.add_column(
        "scans",
        sa.Column("compliance_mapping_snapshot", postgresql.JSONB(), nullable=True),
    )


def downgrade() -> None:
    """Drop the compliance mapping snapshot column."""
    op.drop_column("scans", "compliance_mapping_snapshot")
