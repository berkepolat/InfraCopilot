"""Local read model of findings and assets, fed by events (ADR-0015).

Revision ID: ai_0002
Revises: ai_0001
"""
from alembic import op

revision = "ai_0002"
down_revision = "ai_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE ai.finding_facts (
            finding_id        uuid PRIMARY KEY,
            asset_id          varchar(64) NOT NULL,
            control_id        varchar(32) NOT NULL,
            category          text,
            severity          text NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Informational')),
            status            text NOT NULL CHECK (status IN ('PASS', 'FAIL', 'WARNING', 'INFO')),
            lifecycle_state   text NOT NULL,
            subject_key       text NOT NULL DEFAULT '',
            exploitability    numeric(3,2) NOT NULL CHECK (exploitability BETWEEN 0 AND 1),
            privilege_impact  numeric(3,2) NOT NULL CHECK (privilege_impact BETWEEN 0 AND 1),
            source_occurred_at timestamptz NOT NULL,
            updated_at        timestamptz NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX finding_facts_control_idx ON ai.finding_facts (control_id)")
    op.execute("CREATE INDEX finding_facts_asset_idx ON ai.finding_facts (asset_id)")
    op.execute("""
        CREATE TABLE ai.asset_facts (
            asset_id           varchar(64) PRIMARY KEY,
            hostname           text,
            criticality        text NOT NULL CHECK (criticality IN ('Critical', 'High', 'Medium', 'Low')),
            tier               text NOT NULL,
            environment        text,
            owner              text,
            source_occurred_at timestamptz NOT NULL,
            updated_at         timestamptz NOT NULL DEFAULT now()
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE ai.asset_facts")
    op.execute("DROP TABLE ai.finding_facts")
