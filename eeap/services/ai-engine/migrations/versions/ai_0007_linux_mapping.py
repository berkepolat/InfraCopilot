"""ATT&CK mapping and remediation templates for the Linux host controls LIN-001..LIN-008.

Revision ID: ai_0007
Revises: ai_0006
"""
from alembic import op
from sqlalchemy import text

revision = "ai_0007"
down_revision = "ai_0006"
branch_labels = None
depends_on = None

ATTACK_VERSION = "v16"
CRED, PERSIST, PRIVESC, EVASION, INITIAL = "credential-access", "persistence", "privilege-escalation", \
    "defense-evasion", "initial-access"
DISCOVERY, COLLECTION = "discovery", "collection"

TECHNIQUES = {
    "T1068": ("Exploitation for Privilege Escalation", [PRIVESC]),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", [PRIVESC, EVASION]),
    "T1078.003": ("Valid Accounts: Local Accounts", [EVASION, PERSIST, PRIVESC, INITIAL]),
    "T1046": ("Network Service Discovery", [DISCOVERY]),
    "T1110.001": ("Brute Force: Password Guessing", [CRED]),
    "T1557": ("Adversary-in-the-Middle", [CRED, COLLECTION]),
    "T1003.008": ("OS Credential Dumping: /etc/passwd and /etc/shadow", [CRED]),
}

# control -> [(technique, why the weakness is relevant to it)] — defensive context only.
MAPPING = {
    "LIN-001": [("T1021.004", "Root or password logins over SSH widen remote access with valid accounts."),
                ("T1110", "Password authentication over SSH can be guessed when it is reachable.")],
    "LIN-002": [("T1068", "Missing security updates leave known local privilege escalation flaws unpatched."),
                ("T1190", "Unpatched network services are exposed to known vulnerabilities.")],
    "LIN-003": [("T1548.003", "Passwordless sudo rules let any session of the user act as root."),
                ("T1078.003", "Extra UID 0 or administrator accounts are additional privileged local accounts.")],
    "LIN-004": [("T1046", "Without a host firewall every listening service is reachable and discoverable.")],
    "LIN-005": [("T1078.003", "Accounts without a password are usable local accounts."),
                ("T1110.001", "Passwords that never expire stay valid after exposure.")],
    "LIN-006": [("T1068", "Disabled ASLR and exposed kernel pointers make local exploits more reliable."),
                ("T1557", "Accepted ICMP redirects and source routing allow traffic to be diverted.")],
    "LIN-007": [("T1003.008", ("Readable shadow files expose password hashes; writable account files allow "
                              "adding accounts."))],
    "LIN-008": [("T1068", "Releases past end of support no longer receive fixes for privilege escalation flaws."),
                ("T1190", "Services on unsupported releases keep known vulnerabilities.")],
}

# control -> (title, guidance, effort)
TEMPLATES = {
    "LIN-001": ("Harden the SSH daemon",
                ("Disable root and password logins, forbid empty passwords, lower MaxAuthTries and remove weak "
                 "ciphers, MACs and key exchanges in sshd_config."), "Low"),
    "LIN-002": ("Install pending security updates",
                "Apply security updates, enable automatic security updates and reboot after kernel updates.",
                "Medium"),
    "LIN-003": ("Restrict privileged access",
                ("Remove extra UID 0 accounts, require passwords for sudo and limit sudo/wheel/admin membership "
                 "to approved administrators."), "Low"),
    "LIN-004": ("Enable a host firewall",
                "Enable nftables, firewalld or ufw with a default-deny inbound policy.", "Medium"),
    "LIN-005": ("Fix local account hygiene",
                "Lock accounts with empty passwords and set a maximum password age.", "Low"),
    "LIN-006": ("Apply kernel hardening settings",
                "Enable full ASLR, disable redirects and source routing and restrict kernel information.", "Low"),
    "LIN-007": ("Restore sensitive file permissions",
                "Reset ownership and modes of account, sudo and SSH configuration files.", "Low"),
    "LIN-008": ("Upgrade unsupported operating systems",
                "Move hosts to a supported release before end of security support.", "High"),
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
