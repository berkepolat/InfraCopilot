"""MITRE ATT&CK mapping and template-based remediation roadmap (docs/architecture/15-remediation-mitre.md).

Revision ID: ai_0005
Revises: ai_0004
"""
from alembic import op
from sqlalchemy import text

revision = "ai_0005"
down_revision = "ai_0004"
branch_labels = None
depends_on = None

ATTACK_VERSION = "v16"
CRED, PERSIST, PRIVESC, EVASION, INITIAL = "credential-access", "persistence", "privilege-escalation", \
    "defense-evasion", "initial-access"
LATERAL, RECON, DISCOVERY, COLLECTION, IMPACT = "lateral-movement", "reconnaissance", "discovery", "collection", "impact"

TECHNIQUES = {
    "T1110": ("Brute Force", [CRED]),
    "T1558": ("Steal or Forge Kerberos Tickets", [CRED]),
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", [CRED]),
    "T1558.004": ("Steal or Forge Kerberos Tickets: AS-REP Roasting", [CRED]),
    "T1078.002": ("Valid Accounts: Domain Accounts", [EVASION, PERSIST, PRIVESC, INITIAL]),
    "T1078.003": ("Valid Accounts: Local Accounts", [EVASION, PERSIST, PRIVESC, INITIAL]),
    "T1098": ("Account Manipulation", [PERSIST, PRIVESC]),
    "T1550.002": ("Use Alternate Authentication Material: Pass the Hash", [EVASION, LATERAL]),
    "T1210": ("Exploitation of Remote Services", [LATERAL]),
    "T1590.002": ("Gather Victim Network Information: DNS", [RECON]),
    "T1040": ("Network Sniffing", [CRED, DISCOVERY]),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", [LATERAL]),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", [LATERAL]),
    "T1021.006": ("Remote Services: Windows Remote Management", [LATERAL]),
    "T1592": ("Gather Victim Host Information", [RECON]),
    "T1498": ("Network Denial of Service", [IMPACT]),
    "T1557": ("Adversary-in-the-Middle", [CRED, COLLECTION]),
    "T1557.001": ("Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay", [CRED, COLLECTION]),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", [EVASION]),
}

# control -> [(technique, why the weakness is relevant to it)] — defensive context only.
MAPPING = {
    "AD-001": [("T1110", "Short, non-complex passwords without lockout are easier to guess.")],
    "AD-002": [("T1558.003", "Service tickets of SPN accounts can be requested by any user and attacked offline.")],
    "AD-003": [("T1558.004", "Accounts without pre-authentication return material that can be attacked offline.")],
    "AD-004": [("T1558", "Hosts with unconstrained delegation cache forwardable tickets of connecting users.")],
    "AD-005": [("T1558", "Constrained delegation, especially with protocol transition, allows ticket impersonation.")],
    "AD-006": [("T1558", "Resource-based delegation entries allow impersonation towards the configured resource.")],
    "AD-007": [("T1078.002", "Every member of a privileged group is a domain account worth taking over."),
               ("T1098", "Broad membership makes unnoticed privileged group changes more likely.")],
    "AD-008": [("T1078.003", "Shared local administrator passwords make one local account valid on many hosts."),
               ("T1550.002", "Identical local administrator hashes can be reused across hosts.")],
    "AD-009": [("T1210", "Unsupported systems no longer receive fixes for remotely exploitable services.")],
    "NET-001": [("T1590.002", "Zone transfers disclose the internal DNS inventory.")],
    "NET-002": [("T1040", "Legacy TLS versions weaken the protection of traffic in transit.")],
    "NET-003": [("T1021.002", "Reachable SMB services widen the lateral movement surface.")],
    "NET-004": [("T1040", "SNMPv1/v2c communities travel in clear text."),
                ("T1592", "Default communities disclose host and network configuration.")],
    "NET-005": [("T1498", "Open NTP control queries can be abused for traffic amplification.")],
    "WIN-001": [("T1557.001", "Without SMB signing, relayed authentication is accepted.")],
    "WIN-002": [("T1210", "SMBv1 is a legacy protocol with known remotely exploitable flaws.")],
    "WIN-003": [("T1557.001", "Permissive NTLM settings allow relay of authentication."),
                ("T1550.002", "NTLM accepts password hashes as authentication material.")],
    "WIN-004": [("T1557", "Unsigned LDAP binds can be intercepted and relayed.")],
    "WIN-005": [("T1557", "Without channel binding, LDAPS authentication can be relayed.")],
    "WIN-006": [("T1021.001", "RDP without NLA exposes the login surface before authentication.")],
    "WIN-007": [("T1078.003", "Unexpected local administrators are valid accounts on the host.")],
    "WIN-008": [("T1021.006", "Exposed WinRM listeners widen the remote management surface.")],
    "WIN-009": [("T1562.001", "Hosts without working endpoint protection lack detection and prevention.")],
}

# control -> (title, guidance, effort)
TEMPLATES = {
    "AD-001": ("Harden the domain password and lockout policy",
               ("Raise the minimum length to 14, enable complexity and history, enable lockout, and use "
               "fine-grained policies for privileged and service accounts."), "Low"),
    "AD-002": ("Move service accounts to gMSA or long random passwords",
               ("Convert SPN accounts to group Managed Service Accounts; otherwise set 25+ character random "
               "passwords, enable AES only and remove the accounts from privileged groups."), "Medium"),
    "AD-003": ("Re-enable Kerberos pre-authentication",
               ("Clear 'Do not require Kerberos preauthentication' on all accounts; isolate any legacy "
               "dependency with a long random password."), "Low"),
    "AD-004": ("Remove unconstrained delegation",
               ("Replace unconstrained delegation on servers and accounts with constrained or resource-based "
               "delegation and protect privileged accounts (sensitive flag, Protected Users)."), "Medium"),
    "AD-005": ("Restrict constrained delegation",
               ("Limit delegation to required services, avoid protocol transition and never delegate to "
               "domain controller services."), "Medium"),
    "AD-006": ("Clean up resource-based delegation",
               ("Remove unneeded msDS-AllowedToActOnBehalfOfOtherIdentity entries and restrict who can write "
               "the attribute, starting with Tier-0 objects."), "Medium"),
    "AD-007": ("Reduce privileged group membership",
               ("Shrink Domain Admins to named administrators, empty Schema/Enterprise Admins and operator "
               "groups, and remove disabled and service accounts."), "Medium"),
    "AD-008": ("Deploy Windows LAPS",
               ("Roll out Windows LAPS to every domain-joined computer and restrict who can read the managed "
               "passwords."), "Medium"),
    "AD-009": ("Upgrade or isolate unsupported operating systems",
               ("Plan upgrades or decommissioning; until then isolate the systems and enrol them in extended "
               "security updates."), "High"),
    "AD-010": ("Manage Tier-0 assets from privileged access workstations",
               ("Administer domain controllers and privileged accounts only from Tier-0 privileged access "
               "workstations."), "High"),
    "NET-001": ("Restrict DNS zone transfers", "Allow AXFR only to listed secondary name servers, preferably with TSIG.", "Low"),
    "NET-002": ("Disable TLS 1.0 and 1.1", "Allow only TLS 1.2+ with modern cipher suites on every listener.", "Medium"),
    "NET-003": ("Restrict SMB exposure", "Limit TCP/445 with host firewalls and segmentation; require signing.", "Medium"),
    "NET-004": ("Secure SNMP", "Disable SNMPv1/v2c or default communities; use SNMPv3 with auth and privacy.", "Low"),
    "NET-005": ("Restrict NTP control queries", "Disable mode 6/7 queries and limit NTP to authorized clients.", "Low"),
    "WIN-001": ("Require SMB signing", "Enforce SMB signing for clients and servers by Group Policy.", "Medium"),
    "WIN-002": ("Disable SMBv1", "Remove the SMBv1 feature from all Windows hosts.", "Low"),
    "WIN-003": ("Restrict NTLM", "Audit NTLM use, then restrict it and require NTLMv2 only.", "High"),
    "WIN-004": ("Require LDAP signing", "Require LDAP signing on domain controllers by Group Policy.", "Medium"),
    "WIN-005": ("Enforce LDAP channel binding", "Set LDAP channel binding to 'Always' on domain controllers.", "Medium"),
    "WIN-006": ("Require RDP Network Level Authentication", "Enable NLA for all RDP listeners.", "Low"),
    "WIN-007": ("Review local administrators", "Remove unexpected local administrators; manage membership centrally.", "Medium"),
    "WIN-008": ("Restrict WinRM", "Limit WinRM listeners to management networks and HTTPS.", "Medium"),
    "WIN-009": ("Ensure endpoint protection", "Deploy and monitor endpoint protection on every host.", "Medium"),
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
                "INSERT INTO ai.control_technique_map (control_id, technique_id, rationale) "
                "VALUES (:c, :t, :r) ON CONFLICT (control_id, technique_id) DO UPDATE SET rationale = EXCLUDED.rationale"),
                {"c": control_id, "t": technique_id, "r": rationale})

    op.execute("""
        CREATE TABLE ai.remediation_templates (
            control_id  varchar(32) PRIMARY KEY,
            title       text NOT NULL,
            guidance    text NOT NULL,
            effort      text NOT NULL CHECK (effort IN ('Low', 'Medium', 'High')),
            updated_at  timestamptz NOT NULL DEFAULT now()
        )""")
    for control_id, (title, guidance, effort) in TEMPLATES.items():
        conn.execute(text("INSERT INTO ai.remediation_templates (control_id, title, guidance, effort) "
                          "VALUES (:c, :t, :g, :e)"), {"c": control_id, "t": title, "g": guidance, "e": effort})

    op.execute("ALTER TABLE ai.remediation_items ADD COLUMN control_id varchar(32), "
               "ADD COLUMN finding_ids uuid[] NOT NULL DEFAULT '{}', "
               "ADD COLUMN scenario_ids uuid[] NOT NULL DEFAULT '{}', "
               "ADD COLUMN rationale jsonb NOT NULL DEFAULT '{}'::jsonb")
    op.execute("ALTER TABLE ai.remediation_items DROP CONSTRAINT remediation_has_subject")
    op.execute("ALTER TABLE ai.remediation_items ADD CONSTRAINT remediation_has_subject "
               "CHECK (finding_id IS NOT NULL OR scenario_id IS NOT NULL OR control_id IS NOT NULL)")
    op.execute("CREATE UNIQUE INDEX remediation_control_uq ON ai.remediation_items (control_id) "
               "WHERE generated_by = 'template' AND control_id IS NOT NULL")


def downgrade() -> None:
    op.execute("DELETE FROM ai.remediation_items WHERE control_id IS NOT NULL")
    op.execute("DROP INDEX ai.remediation_control_uq")
    op.execute("ALTER TABLE ai.remediation_items DROP CONSTRAINT remediation_has_subject")
    op.execute("ALTER TABLE ai.remediation_items ADD CONSTRAINT remediation_has_subject "
               "CHECK (finding_id IS NOT NULL OR scenario_id IS NOT NULL)")
    op.execute("ALTER TABLE ai.remediation_items DROP COLUMN control_id, DROP COLUMN finding_ids, "
               "DROP COLUMN scenario_ids, DROP COLUMN rationale")
    op.execute("DROP TABLE ai.remediation_templates")
    op.execute("DELETE FROM ai.control_technique_map")
    op.execute("DELETE FROM ai.mitre_techniques")
