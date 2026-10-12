"""ATT&CK mapping and remediation templates for the port discovery controls NET-006..NET-009.

Revision ID: ai_0006
Revises: ai_0005
"""
from alembic import op
from sqlalchemy import text

revision = "ai_0006"
down_revision = "ai_0005"
branch_labels = None
depends_on = None

ATTACK_VERSION = "v16"
CRED, PERSIST, PRIVESC, EVASION, INITIAL = "credential-access", "persistence", "privilege-escalation", \
    "defense-evasion", "initial-access"
LATERAL, COLLECTION, EXECUTION = "lateral-movement", "collection", "execution"

TECHNIQUES = {
    "T1021.004": ("Remote Services: SSH", [LATERAL]),
    "T1021.005": ("Remote Services: VNC", [LATERAL]),
    "T1133": ("External Remote Services", [PERSIST, INITIAL]),
    "T1190": ("Exploit Public-Facing Application", [INITIAL]),
    "T1213": ("Data from Information Repositories", [COLLECTION]),
    "T1609": ("Container Administration Command", [EXECUTION]),
    "T1610": ("Deploy Container", [EVASION, EXECUTION]),
}

# control -> [(technique, why the weakness is relevant to it)] — defensive context only.
MAPPING = {
    "NET-006": [("T1021.001", "Reachable RDP listeners widen the remote login surface."),
                ("T1021.004", "Reachable SSH daemons accept remote logins from any network that can reach them."),
                ("T1021.005", "VNC servers often rely on a single shared password."),
                ("T1021.006", "Reachable WinRM listeners allow remote command execution with valid accounts."),
                ("T1133", "Remote administration services exposed beyond management networks are entry points.")],
    "NET-007": [("T1040", "Telnet, FTP and r-services transmit credentials and data in clear text."),
                ("T1110", "Legacy login services rarely enforce lockout or modern authentication.")],
    "NET-008": [("T1213", "Reachable data stores expose stored records to anyone who can authenticate."),
                ("T1190", "Data stores reachable from user networks are frequently targeted application services.")],
    "NET-009": [("T1609", "An exposed container or orchestration API accepts administrative commands."),
                ("T1610", "Container APIs allow deploying new workloads on the host.")],
}

# control -> (title, guidance, effort)
TEMPLATES = {
    "NET-006": ("Restrict remote administration services",
                ("Allow SSH, RDP, WinRM and VNC only from management networks or jump hosts, require RDP NLA, "
                 "and prefer WinRM over HTTPS."), "Medium"),
    "NET-007": ("Remove cleartext legacy protocols",
                "Disable Telnet, FTP and r-services; replace them with SSH/SFTP or FTPS.", "Low"),
    "NET-008": ("Restrict data store exposure",
                ("Bind databases, caches and search engines to private interfaces, allow only application "
                 "servers and require authentication and TLS."), "Medium"),
    "NET-009": ("Protect container and orchestration control planes",
                ("Disable the unauthenticated Docker API, require mutual TLS and RBAC for Kubernetes, kubelet "
                 "and etcd, and restrict them to control-plane networks."), "Medium"),
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
