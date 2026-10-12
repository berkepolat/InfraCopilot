"""Linux host posture over SSH: LIN-001..LIN-008 and pinned SSH host keys.

Revision ID: assessment_0007
"""
import json

import sqlalchemy as sa
from alembic import op

revision = "assessment_0007"
down_revision = "assessment_0006"
branch_labels = None
depends_on = None

COLLECTOR = "linux.ssh_posture"
CIS = "https://www.cisecurity.org/benchmark/distribution_independent_linux"

# control -> (name, category, severity, exploitability, privilege_impact, recommendation, links, mitre)
CONTROLS = {
    "LIN-001": (
        "SSH Daemon Hardening", "Remote Access", "High", 0.60, 0.60,
        ("Set PermitRootLogin no (or prohibit-password), PermitEmptyPasswords no and PasswordAuthentication no, "
         "keep MaxAuthTries at 6 or lower and remove CBC ciphers, MD5/96-bit MACs and SHA-1 key exchanges."),
        ["https://man.openbsd.org/sshd_config", CIS],
        ["T1021.004", "T1110"]),
    "LIN-002": (
        "Security Update Status", "Vulnerability Management", "High", 0.70, 0.60,
        ("Install pending security updates, enable automatic security updates (unattended-upgrades, "
         "dnf-automatic) and reboot after kernel or library updates."),
        [CIS],
        ["T1068", "T1190"]),
    "LIN-003": (
        "Privileged Access Configuration", "Privileged Access", "High", 0.50, 0.90,
        ("Keep root the only UID 0 account, require a password for sudo, keep the sudo/wheel/admin groups to "
         "approved administrators and list exceptions in LINUX_ADMINS_ALLOWED."),
        [CIS],
        ["T1548.003", "T1078.003"]),
    "LIN-004": (
        "Host Firewall", "Network Exposure", "Medium", 0.40, 0.30,
        ("Enable a host firewall (nftables, firewalld or ufw) with a default-deny inbound policy that allows "
         "only the services the host provides."),
        [CIS],
        ["T1046"]),
    "LIN-005": (
        "Local Account Hygiene", "Identity Hygiene", "High", 0.70, 0.60,
        ("Lock or set passwords for accounts with an empty password and set PASS_MAX_DAYS to 365 or less in "
         "/etc/login.defs."),
        [CIS],
        ["T1078.003", "T1110.001"]),
    "LIN-006": (
        "Kernel Hardening", "System Hardening", "Medium", 0.30, 0.40,
        ("Set kernel.randomize_va_space = 2, disable ICMP redirects and source routing, keep fs.protected_* "
         "enabled and restrict kernel pointers and dmesg through /etc/sysctl.d."),
        ["https://docs.kernel.org/admin-guide/sysctl/kernel.html", CIS],
        ["T1068", "T1557"]),
    "LIN-007": (
        "Sensitive File Permissions", "System Hardening", "Medium", 0.50, 0.70,
        ("Restore root ownership and restrictive modes on /etc/passwd, /etc/group (644), /etc/shadow, "
         "/etc/gshadow (640 or 000), /etc/sudoers (440) and sshd_config, and remove world-writable files "
         "from /etc."),
        [CIS],
        ["T1003.008"]),
    "LIN-008": (
        "Operating System Lifecycle", "Lifecycle Management", "High", 0.70, 0.50,
        "Upgrade hosts to a release that still receives security updates before its end of support.",
        ["https://endoflife.date/"],
        ["T1068", "T1190"]),
}


def upgrade() -> None:
    insert = sa.text(
        "INSERT INTO assessment.controls (control_id, name, module, category, default_severity, exploitability, "
        "privilege_impact, execution_site, collector_id, recommendation, reference_links, mitre_techniques, "
        "enabled) VALUES (:id, :name, 'LINUX', :category, :severity, :exp, :priv, 'server', :collector, :rec, "
        "CAST(:links AS jsonb), :mitre, true) ON CONFLICT (control_id) DO NOTHING")
    for control_id, (name, category, severity, exp, priv, rec, links, mitre) in CONTROLS.items():
        op.get_bind().execute(insert, {"id": control_id, "name": name, "category": category, "severity": severity,
                                       "exp": exp, "priv": priv, "collector": COLLECTOR, "rec": rec,
                                       "links": json.dumps(links), "mitre": mitre})

    op.execute("""
        CREATE TABLE assessment.ssh_host_keys (
            ip                 inet NOT NULL,
            port               integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
            key_type           text NOT NULL,
            fingerprint        text NOT NULL,
            first_seen_at      timestamptz NOT NULL,
            last_seen_at       timestamptz NOT NULL,
            first_seen_run_id  uuid,
            last_seen_run_id   uuid,
            PRIMARY KEY (ip, port)
        )""")


def downgrade() -> None:
    op.execute("DROP TABLE assessment.ssh_host_keys")
    op.get_bind().execute(sa.text(
        "DELETE FROM assessment.controls WHERE control_id = ANY(:ids) "
        "AND NOT EXISTS (SELECT 1 FROM assessment.findings f WHERE f.control_id = controls.control_id)"),
        {"ids": list(CONTROLS)})
