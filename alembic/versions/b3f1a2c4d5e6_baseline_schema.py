"""Create the baseline OpenShield schema.

Revision ID: b3f1a2c4d5e6
Revises:
Create Date: 2026-07-05 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers, used by Alembic.
revision: str = "b3f1a2c4d5e6"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the current scans and findings tables."""
    op.create_table(
        "scans",
        sa.Column("scan_id", postgresql.UUID(), nullable=False),
        sa.Column("subscription_id", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_findings", sa.Integer(), server_default=sa.text("0"), nullable=True),
        sa.Column("score", sa.Integer(), server_default=sa.text("NULL"), nullable=True),
        sa.Column(
            "cve_enrichment_status",
            sa.Text(),
            server_default=sa.text("'PENDING'"),
            nullable=True,
        ),
        sa.Column("status", sa.Text(), server_default=sa.text("'pending'"), nullable=True),
        sa.Column("attempt_count", sa.Integer(), server_default=sa.text("0"), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("scan_id", name="scans_pkey"),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", postgresql.UUID(), nullable=True),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("rule_name", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=True),
        sa.Column("resource_id", sa.Text(), nullable=True),
        sa.Column("resource_name", sa.Text(), nullable=True),
        sa.Column("resource_type", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("playbook", sa.Text(), nullable=True),
        sa.Column("frameworks", postgresql.JSONB(), nullable=True),
        sa.Column("metadata", postgresql.JSONB(), nullable=True),
        sa.Column(
            "cve_references",
            postgresql.JSONB(),
            server_default=sa.text("'[]'::jsonb"),
            nullable=True,
        ),
        sa.Column("cvss_score", sa.Float(), server_default=sa.text("NULL"), nullable=True),
        sa.Column(
            "exploit_available",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=True,
        ),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.scan_id"],
            name="findings_scan_id_fkey",
        ),
        sa.PrimaryKeyConstraint("id", name="findings_pkey"),
    )

    op.create_index("idx_findings_scan_id", "findings", ["scan_id"], unique=False)
    op.create_index("idx_findings_severity", "findings", ["severity"], unique=False)
    op.create_index("idx_findings_rule_id", "findings", ["rule_id"], unique=False)


def downgrade() -> None:
    """Drop the current findings and scans tables."""
    op.drop_index("idx_findings_rule_id", table_name="findings")
    op.drop_index("idx_findings_severity", table_name="findings")
    op.drop_index("idx_findings_scan_id", table_name="findings")
    op.drop_table("findings")
    op.drop_table("scans")
