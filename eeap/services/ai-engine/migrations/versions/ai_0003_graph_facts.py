"""Graph context per finding subject (asset id or AD distinguished name), fed by graph.analysis_completed.

Revision ID: ai_0003
Revises: ai_0002
"""
from alembic import op

revision = "ai_0003"
down_revision = "ai_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE ai.graph_facts (
            subject_kind      text NOT NULL CHECK (subject_kind IN ('asset', 'dn')),
            subject_key       text NOT NULL,
            propagation_score numeric(5,4) NOT NULL CHECK (propagation_score BETWEEN 0 AND 1),
            tier0_reachable   boolean NOT NULL,
            min_hops          smallint,
            is_tier0          boolean NOT NULL,
            is_privileged     boolean NOT NULL,
            analysis_id       uuid NOT NULL,
            updated_at        timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (subject_kind, subject_key)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE ai.graph_facts")
