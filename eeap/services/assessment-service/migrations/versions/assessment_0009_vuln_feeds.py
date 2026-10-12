"""Known vulnerable packages: uploaded OSV feeds, fixed-version ranges and LIN-009.

Revision ID: assessment_0009
"""
import json

import sqlalchemy as sa
from alembic import op

revision = "assessment_0009"
down_revision = "assessment_0008"
branch_labels = None
depends_on = None

CONTROL = (
    "LIN-009", "Known Vulnerable Packages", "Vulnerability Management", "High", 0.80, 0.60,
    ("Update the listed packages to at least the fixed version from the distribution (apt, dnf or apk), "
     "restart affected services or reboot for kernel and library updates, and keep the vulnerability data "
     "current by uploading a fresh OSV file at least monthly."),
    ["https://osv.dev/", "https://ossf.github.io/osv-schema/"],
    ["T1068", "T1190", "T1203"],
)


def upgrade() -> None:
    control_id, name, category, severity, exp, priv, rec, links, mitre = CONTROL
    op.get_bind().execute(sa.text(
        "INSERT INTO assessment.controls (control_id, name, module, category, default_severity, exploitability, "
        "privilege_impact, execution_site, collector_id, recommendation, reference_links, mitre_techniques, "
        "enabled) VALUES (:id, :name, 'LINUX', :category, :severity, :exp, :priv, 'server', "
        "'linux.ssh_posture', :rec, CAST(:links AS jsonb), :mitre, true) ON CONFLICT (control_id) DO NOTHING"),
        {"id": control_id, "name": name, "category": category, "severity": severity, "exp": exp, "priv": priv,
         "rec": rec, "links": json.dumps(links), "mitre": mitre})

    op.execute("""
        CREATE TABLE assessment.vuln_feeds (
            feed_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            filename         text NOT NULL,
            bucket           text NOT NULL,
            object_key       text NOT NULL,
            sha256           text NOT NULL,
            size_bytes       bigint NOT NULL,
            status           text NOT NULL DEFAULT 'queued'
                             CHECK (status IN ('queued', 'importing', 'completed', 'failed')),
            ecosystems       text[] NOT NULL DEFAULT '{}',
            records          integer,
            ranges           integer,
            newest_modified  timestamptz,
            error            text,
            uploaded_by      text NOT NULL,
            created_at       timestamptz NOT NULL DEFAULT now(),
            completed_at     timestamptz
        )""")
    op.execute("""
        CREATE TABLE assessment.vuln_ecosystems (
            ecosystem        text PRIMARY KEY,
            feed_id          uuid NOT NULL REFERENCES assessment.vuln_feeds (feed_id),
            ranges           integer NOT NULL,
            newest_modified  timestamptz,
            imported_at      timestamptz NOT NULL
        )""")
    op.execute("""
        CREATE TABLE assessment.vuln_ranges (
            ecosystem    text NOT NULL,
            package      text NOT NULL,
            advisory_id  text NOT NULL,
            cves         text[] NOT NULL DEFAULT '{}',
            severity     text NOT NULL,
            introduced   text NOT NULL,
            fixed        text NOT NULL
        )""")
    op.execute("CREATE INDEX vuln_ranges_lookup ON assessment.vuln_ranges (ecosystem, package)")


def downgrade() -> None:
    op.execute("DROP TABLE assessment.vuln_ranges")
    op.execute("DROP TABLE assessment.vuln_ecosystems")
    op.execute("DROP TABLE assessment.vuln_feeds")
    op.get_bind().execute(sa.text(
        "DELETE FROM assessment.controls WHERE control_id = 'LIN-009' "
        "AND NOT EXISTS (SELECT 1 FROM assessment.findings f WHERE f.control_id = controls.control_id)"))
