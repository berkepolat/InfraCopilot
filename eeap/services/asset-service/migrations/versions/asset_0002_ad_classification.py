"""Classification rules for assets discovered by the AD configuration assessment.

Revision ID: asset_0002
"""
from alembic import op

revision = "asset_0002"
down_revision = "asset_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        INSERT INTO asset.classification_rules (name, priority, condition, set_values) VALUES
          ('AD domains are Tier 0', 11, '{"asset_type": "Identity", "tags_any": ["ad:domain"]}',
           '{"tier": "Tier0", "criticality": "Critical"}'),
          ('AD privileged-group computers are Tier 0', 12, '{"tags_any": ["ad:tier0"]}',
           '{"tier": "Tier0", "criticality": "Critical"}')
        ON CONFLICT (name) DO NOTHING
    """)


def downgrade() -> None:
    op.execute("DELETE FROM asset.classification_rules WHERE name IN "
               "('AD domains are Tier 0', 'AD privileged-group computers are Tier 0')")
