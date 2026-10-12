"""ATT&CK mapping and remediation templates for WIN-010, WIN-011 and WIN-012 (Windows patch status).

Revision ID: ai_0011
Revises: ai_0010
"""
from alembic import op
from sqlalchemy import text

revision = "ai_0011"
down_revision = "ai_0010"
branch_labels = None
depends_on = None

# control -> [(technique, why the weakness is relevant to it)] — defensive context only.
# All techniques were added by earlier revisions (ai_0005, ai_0009).
MAPPING = {
    "WIN-010": [("T1068", "Unpatched kernel and driver flaws allow local privilege escalation."),
                ("T1190", "Unpatched network-facing Windows services are reachable entry points."),
                ("T1203", "Unpatched document, browser and media components can be triggered by crafted files."),
                ("T1210", "Unpatched remote services (SMB, RDP, RPC) allow lateral movement.")],
    "WIN-011": [("T1068", "Hosts that fall behind on monthly updates accumulate privilege escalation flaws."),
                ("T1210", "Hosts that fall behind on monthly updates accumulate remotely exploitable flaws.")],
    "WIN-012": [("T1068", "Unsupported Windows releases no longer receive fixes for privilege escalation flaws."),
                ("T1190", "Unsupported Windows releases no longer receive fixes for exposed services."),
                ("T1210", "Unsupported Windows releases no longer receive fixes for remotely exploitable services.")],
}

TEMPLATES = {
    "WIN-010": ("Install missing Windows security updates",
                ("Approve and deploy the missing updates (Windows Update, WSUS, Intune or Configuration Manager), "
                 "prioritising those that fix CISA KEV-listed vulnerabilities, and reboot the host."), "Low"),
    "WIN-011": ("Restore the monthly Windows update cycle",
                ("Check why the host stopped installing updates (servicing stack, disk space, WSUS approval, "
                 "maintenance windows), install the latest cumulative update and reboot pending hosts."), "Medium"),
    "WIN-012": ("Upgrade unsupported Windows releases",
                ("Plan an in-place upgrade or migration to a supported Windows release; until then enrol the host "
                 "in Extended Security Updates and limit its network exposure."), "High"),
}


def upgrade() -> None:
    conn = op.get_bind()
    for control_id, entries in MAPPING.items():
        for technique_id, rationale in entries:
            conn.execute(text(
                "INSERT INTO ai.control_technique_map (control_id, technique_id, rationale) VALUES (:c, :t, :r) "
                "ON CONFLICT (control_id, technique_id) DO UPDATE SET rationale = EXCLUDED.rationale"),
                {"c": control_id, "t": technique_id, "r": rationale})
    for control_id, (title, guidance, effort) in TEMPLATES.items():
        conn.execute(text(
            "INSERT INTO ai.remediation_templates (control_id, title, guidance, effort) VALUES (:c, :t, :g, :e) "
            "ON CONFLICT (control_id) DO UPDATE SET title = EXCLUDED.title, guidance = EXCLUDED.guidance, "
            "effort = EXCLUDED.effort, updated_at = now()"),
            {"c": control_id, "t": title, "g": guidance, "e": effort})


def downgrade() -> None:
    controls = list(MAPPING)
    op.get_bind().execute(text("DELETE FROM ai.remediation_templates WHERE control_id = ANY(:c)"), {"c": controls})
    op.get_bind().execute(text("DELETE FROM ai.control_technique_map WHERE control_id = ANY(:c)"), {"c": controls})
