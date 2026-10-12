"""ATT&CK mapping and remediation template for LIN-009 (known vulnerable packages).

Revision ID: ai_0009
Revises: ai_0008
"""
from alembic import op
from sqlalchemy import text

revision = "ai_0009"
down_revision = "ai_0008"
branch_labels = None
depends_on = None

ATTACK_VERSION = "v16"

TECHNIQUES = {
    "T1068": ("Exploitation for Privilege Escalation", ["privilege-escalation"]),
    "T1190": ("Exploit Public-Facing Application", ["initial-access"]),
    "T1203": ("Exploitation for Client Execution", ["execution"]),
}

# control -> [(technique, why the weakness is relevant to it)] — defensive context only.
MAPPING = {
    "LIN-009": [("T1068", "Vulnerable local libraries and setuid programs allow privilege escalation."),
                ("T1190", "Vulnerable network daemons and their libraries are reachable entry points."),
                ("T1203", "Vulnerable parsers and libraries can be triggered by crafted files or data.")],
}

TEMPLATES = {
    "LIN-009": ("Update packages with known vulnerabilities",
                ("Install the fixed package versions from the distribution, restart affected services or reboot, "
                 "and keep the uploaded vulnerability data current."), "Medium"),
}


def upgrade() -> None:
    conn = op.get_bind()
    for technique_id, (name, tactics) in TECHNIQUES.items():
        url = "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"
        conn.execute(text(
            "INSERT INTO ai.mitre_techniques (technique_id, name, tactics, attack_version, url) "
            "VALUES (:id, :name, :tactics, :version, :url) ON CONFLICT (technique_id) DO UPDATE SET "
            "name = EXCLUDED.name, tactics = EXCLUDED.tactics, attack_version = EXCLUDED.attack_version, "
            "url = EXCLUDED.url"),
            {"id": technique_id, "name": name, "tactics": tactics, "version": ATTACK_VERSION, "url": url})
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
    op.get_bind().execute(text(
        "DELETE FROM ai.mitre_techniques t WHERE t.technique_id = ANY(:t) AND NOT EXISTS "
        "(SELECT 1 FROM ai.control_technique_map m WHERE m.technique_id = t.technique_id)"),
        {"t": list(TECHNIQUES)})
