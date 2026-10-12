"""Scoring model v2: network exposure factor (X) and known-exploited floor.

Adds the per-asset service exposure read model (fed by network.exposure_observed), the KEV flag on
finding facts, and activates v2. v1 stays in ai.scoring_models so its scores remain attributable.

Revision ID: ai_0010
Revises: ai_0009
"""
import json

import sqlalchemy as sa
from alembic import op

revision = "ai_0010"
down_revision = "ai_0009"
branch_labels = None
depends_on = None

V2_WEIGHTS = {
    "factor_weights": {"severity": 0.25, "asset_criticality": 0.20, "exploitability": 0.20,
                       "exposure_breadth": 0.05, "privilege_impact": 0.10, "propagation": 0.10,
                       "network_exposure": 0.10},
    "severity_values": {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25, "Informational": 0.0},
    "criticality_values": {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25},
    "status_multipliers": {"FAIL": 1.0, "WARNING": 0.6, "INFO": 0.0, "PASS": 0.0},
    "lifecycle_multipliers": {"open": 1.0, "acknowledged": 1.0, "in_remediation": 0.9,
                              "risk_accepted": 0.0, "false_positive": 0.0, "resolved": 0.0},
    "breadth_reference_count": 100,
    "severity_floor": {"Critical": 70},
    "known_exploited_floor": 80,
    "exposure_unknown": 0.3,
    "bands": {"Critical": 90, "High": 70, "Medium": 40, "Low": 0},
}


def upgrade() -> None:
    op.execute("ALTER TABLE ai.finding_facts ADD COLUMN known_exploited boolean NOT NULL DEFAULT false")
    op.execute("""
        CREATE TABLE ai.exposure_facts (
            asset_id           varchar(64) PRIMARY KEY,
            ip                 inet,
            services           jsonb NOT NULL DEFAULT '[]',
            run_id             uuid,
            source_occurred_at timestamptz NOT NULL,
            updated_at         timestamptz NOT NULL DEFAULT now()
        )""")
    bind = op.get_bind()
    bind.execute(sa.text(
        "INSERT INTO ai.scoring_models (model_version, description, weights, is_active) VALUES "
        "('v2', 'v1 plus network exposure of the asset and a floor for actively exploited vulnerabilities', "
        "CAST(:w AS jsonb), false) ON CONFLICT (model_version) DO NOTHING"), {"w": json.dumps(V2_WEIGHTS)})
    bind.execute(sa.text("UPDATE ai.scoring_models SET is_active = false WHERE is_active AND model_version <> 'v2'"))
    bind.execute(sa.text("UPDATE ai.scoring_models SET is_active = true WHERE model_version = 'v2'"))


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text("UPDATE ai.scoring_models SET is_active = false WHERE model_version = 'v2'"))
    bind.execute(sa.text("UPDATE ai.scoring_models SET is_active = true WHERE model_version = 'v1'"))
    # v2 scores reference the model row, so it is kept; only the read-model additions are removed.
    op.execute("DROP TABLE ai.exposure_facts")
    op.execute("ALTER TABLE ai.finding_facts DROP COLUMN known_exploited")
