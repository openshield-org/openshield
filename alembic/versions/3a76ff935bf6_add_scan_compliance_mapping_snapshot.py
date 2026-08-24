"""Add compliance_mapping_snapshot to scans.

Revision ID: 3a76ff935bf6
Revises: c7a2e9f1b3d4
Create Date: 2026-08-22 00:00:00.000000

PR #308 (severity contract v1, d8e4f6a1b2c3) was cut from this same parent,
c7a2e9f1b3d4 - both PRs would fork the Alembic revision graph if merged
independently as-is. Chaining this migration's down_revision onto
d8e4f6a1b2c3 ahead of time was tried and reverted: Alembic resolves the
full revision map from the files present in the branch it's run against,
so pointing at a revision that only exists on #308's unmerged branch
breaks `alembic upgrade head` in this PR's own CI (KeyError on the
missing revision) until #308 actually lands on dev. The chain has to be
resolved at merge time instead: whichever of #308 / this PR merges
second rebases onto dev and repoints its down_revision at whatever
became the new head.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers, used by Alembic.
revision: str = "3a76ff935bf6"
down_revision: Union[str, Sequence[str], None] = "c7a2e9f1b3d4"
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
