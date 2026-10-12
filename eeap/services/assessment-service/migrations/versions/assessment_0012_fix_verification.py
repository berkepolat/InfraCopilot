"""Fix verification: targeted reassessment runs (trigger 'verification') and their per-finding outcome.

Revision ID: assessment_0012
"""
from alembic import op

revision = "assessment_0012"
down_revision = "assessment_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE assessment.assessment_runs DROP CONSTRAINT assessment_runs_trigger_check")
    op.execute("ALTER TABLE assessment.assessment_runs ADD CONSTRAINT assessment_runs_trigger_check "
               "CHECK (trigger IN ('manual', 'schedule', 'api', 'import', 'verification'))")
    op.execute("""
        CREATE TABLE assessment.finding_verifications (
            verification_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            finding_id      uuid NOT NULL REFERENCES assessment.findings(finding_id) ON DELETE CASCADE,
            run_id          uuid REFERENCES assessment.assessment_runs(run_id) ON DELETE SET NULL,
            status          text NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'verified', 'still_failing', 'inconclusive', 'failed')),
            requested_by    text NOT NULL,
            note            text CHECK (length(note) <= 2000),
            requested_at    timestamptz NOT NULL DEFAULT now(),
            completed_at    timestamptz,
            observed_status text,
            summary         text
        )""")
    op.execute("CREATE INDEX finding_verifications_finding_idx "
               "ON assessment.finding_verifications (finding_id, requested_at DESC)")
    op.execute("CREATE INDEX finding_verifications_pending_idx "
               "ON assessment.finding_verifications (run_id) WHERE status = 'pending'")
    op.execute("CREATE INDEX finding_verifications_recent_idx ON assessment.finding_verifications (requested_at DESC)")


def downgrade() -> None:
    op.execute("DROP TABLE assessment.finding_verifications")
    op.execute("UPDATE assessment.assessment_runs SET trigger = 'manual' WHERE trigger = 'verification'")
    op.execute("ALTER TABLE assessment.assessment_runs DROP CONSTRAINT assessment_runs_trigger_check")
    op.execute("ALTER TABLE assessment.assessment_runs ADD CONSTRAINT assessment_runs_trigger_check "
               "CHECK (trigger IN ('manual', 'schedule', 'api', 'import'))")
