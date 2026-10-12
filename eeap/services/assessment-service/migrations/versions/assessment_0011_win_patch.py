"""Windows patch status over WinRM/JEA: WIN-010 missing security updates, WIN-011 patch currency,
WIN-012 operating system lifecycle.

Revision ID: assessment_0011
"""
import json

import sqlalchemy as sa
from alembic import op

revision = "assessment_0011"
down_revision = "assessment_0010"
branch_labels = None
depends_on = None

COLLECTOR = "win.winrm_posture"
LIFECYCLE = "https://learn.microsoft.com/lifecycle/products/"

# control -> (name, category, severity, exploitability, privilege_impact, recommendation, links, mitre)
CONTROLS = {
    "WIN-010": (
        "Missing Windows Security Updates", "Patch Management", "High", 0.70, 0.70,
        ("Install the missing security updates through Windows Update, WSUS, Intune or Configuration Manager, "
         "starting with updates that fix vulnerabilities listed in CISA KEV, then reboot the host."),
        ["https://msrc.microsoft.com/update-guide/",
         "https://learn.microsoft.com/windows/deployment/update/waas-quick-start"],
        ["T1068", "T1190", "T1203", "T1210"]),
    "WIN-011": (
        "Windows Patch Currency", "Patch Management", "Medium", 0.50, 0.50,
        ("Apply the monthly cumulative update within 30 days of release, make sure Windows Update or the "
         "management tool can reach the host, and reboot hosts with pending updates."),
        ["https://learn.microsoft.com/windows/deployment/update/waas-overview"],
        ["T1068", "T1210"]),
    "WIN-012": (
        "Windows Operating System Lifecycle", "Patch Management", "High", 0.60, 0.60,
        ("Upgrade Windows to a release that still receives security updates, or enrol the host in Extended "
         "Security Updates until it can be upgraded or retired."),
        [LIFECYCLE + "windows-server-2016", LIFECYCLE + "windows-11-home-and-pro",
         LIFECYCLE + "windows-11-enterprise-and-education"],
        ["T1068", "T1190", "T1210"]),
}


def upgrade() -> None:
    insert = sa.text(
        "INSERT INTO assessment.controls (control_id, name, module, category, default_severity, exploitability, "
        "privilege_impact, execution_site, collector_id, recommendation, reference_links, mitre_techniques, "
        "enabled) VALUES (:id, :name, 'WIN', :category, :severity, :exp, :priv, 'server', :collector, :rec, "
        "CAST(:links AS jsonb), :mitre, true) ON CONFLICT (control_id) DO NOTHING")
    for control_id, (name, category, severity, exp, priv, rec, links, mitre) in CONTROLS.items():
        op.get_bind().execute(insert, {"id": control_id, "name": name, "category": category, "severity": severity,
                                       "exp": exp, "priv": priv, "collector": COLLECTOR, "rec": rec,
                                       "links": json.dumps(links), "mitre": mitre})


def downgrade() -> None:
    op.get_bind().execute(sa.text(
        "DELETE FROM assessment.controls WHERE control_id = ANY(:ids) "
        "AND NOT EXISTS (SELECT 1 FROM assessment.findings f WHERE f.control_id = controls.control_id)"),
        {"ids": list(CONTROLS)})
