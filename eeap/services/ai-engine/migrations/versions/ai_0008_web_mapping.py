"""ATT&CK mapping and remediation templates for the web service controls NET-010..NET-012.

Revision ID: ai_0008
Revises: ai_0007
"""
from alembic import op
from sqlalchemy import text

revision = "ai_0008"
down_revision = "ai_0007"
branch_labels = None
depends_on = None

ATTACK_VERSION = "v16"
CRED, COLLECTION, RECON, INITIAL, DISCOVERY = "credential-access", "collection", "reconnaissance", \
    "initial-access", "discovery"

TECHNIQUES = {
    "T1557": ("Adversary-in-the-Middle", [CRED, COLLECTION]),
    "T1592": ("Gather Victim Host Information", [RECON]),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", [CRED]),
    "T1190": ("Exploit Public-Facing Application", [INITIAL]),
    "T1040": ("Network Sniffing", [CRED, DISCOVERY]),
}

# control -> [(technique, why the weakness is relevant to it)] — defensive context only.
MAPPING = {
    "NET-010": [("T1557", "Without HSTS a first plain-HTTP visit can be intercepted and downgraded."),
                ("T1592", "Version numbers in the Server header tell an observer which software is running.")],
    "NET-011": [("T1552.001", "Downloadable .git metadata and configuration pages can contain secrets."),
                ("T1592", "Status, info and listing pages disclose software, paths and internal hosts."),
                ("T1190", "Public management consoles are reachable application entry points.")],
    "NET-012": [("T1040", "Credentials and content sent over cleartext HTTP can be read on the network."),
                ("T1557", "Expired or self-signed certificates teach users to accept interception warnings.")],
}

# control -> (title, guidance, effort)
TEMPLATES = {
    "NET-010": ("Add web security headers",
                ("Set HSTS, X-Content-Type-Options and frame protection headers and hide version numbers in the "
                 "Server header."), "Low"),
    "NET-011": ("Remove exposed web content",
                ("Delete .git and phpinfo files from the web root, disable directory listing and restrict status "
                 "pages and management consoles to administrators."), "Low"),
    "NET-012": ("Enforce HTTPS with valid certificates",
                ("Redirect HTTP to HTTPS, serve login forms only over HTTPS and use trusted certificates with "
                 "automated renewal."), "Medium"),
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
