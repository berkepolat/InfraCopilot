"""Enable AD-001..AD-010 (read-only LDAP collector) and add remediation guidance.

Revision ID: assessment_0002
"""
import json

import sqlalchemy as sa
from alembic import op

revision = "assessment_0002"
down_revision = "assessment_0001"
branch_labels = None
depends_on = None

MS = "https://learn.microsoft.com"
CONTROLS = {
    "AD-001": (
        "Set the default domain password policy to a minimum length of 14, enable complexity, keep 24 "
        "passwords of history and enable account lockout (5 or fewer attempts). Use fine-grained password "
        "policies for privileged and service accounts.",
        [f"{MS}/windows/security/threat-protection/security-policy-settings/password-policy",
         "https://www.cisecurity.org/benchmark/microsoft_windows_server"],
        ["T1110"]),
    "AD-002": (
        "Replace user-based service accounts with group Managed Service Accounts (gMSA). Where that is not "
        "possible, use long random passwords (25+ characters) rotated at least yearly, enable AES encryption "
        "types, and remove service accounts from privileged groups.",
        [f"{MS}/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview"],
        ["T1558.003"]),
    "AD-003": (
        "Enable Kerberos pre-authentication on every account (clear 'Do not require Kerberos "
        "preauthentication'). If a legacy application requires it, isolate the account and give it a long "
        "random password.",
        [f"{MS}/windows/security/threat-protection/auditing/event-4768"],
        ["T1558.004"]),
    "AD-004": (
        "Remove unconstrained delegation from servers and accounts other than domain controllers. Use "
        "constrained or resource-based delegation, and mark privileged accounts 'Account is sensitive and "
        "cannot be delegated' or add them to Protected Users.",
        [f"{MS}/windows-server/security/kerberos/kerberos-constrained-delegation-overview"],
        ["T1558"]),
    "AD-005": (
        "Limit constrained delegation to the services the application needs. Avoid protocol transition "
        "(TrustedToAuthForDelegation) and never delegate to domain controller services.",
        [f"{MS}/windows-server/security/kerberos/kerberos-constrained-delegation-overview"],
        ["T1558"]),
    "AD-006": (
        "Review msDS-AllowedToActOnBehalfOfOtherIdentity on each listed object, remove entries that are not "
        "required, and restrict who can write this attribute. Tier-0 objects should not allow delegation.",
        [f"{MS}/windows-server/security/kerberos/kerberos-constrained-delegation-overview"],
        ["T1558"]),
    "AD-007": (
        "Keep Domain Admins small (5 or fewer) and Schema/Enterprise Admins empty outside planned changes. "
        "Do not use operator groups; delegate specific rights instead. Remove disabled and service accounts "
        "from privileged groups.",
        [f"{MS}/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models"],
        ["T1078.002", "T1098"]),
    "AD-008": (
        "Deploy Windows LAPS (or legacy LAPS) so every domain-joined computer has a unique, automatically "
        "rotated local administrator password, and restrict who can read it.",
        [f"{MS}/windows-server/identity/laps/laps-overview"],
        ["T1078.003", "T1550.002"]),
    "AD-009": (
        "Upgrade or decommission systems running unsupported operating systems. Until then, isolate them "
        "on restricted network segments and enrol them in extended security updates where available.",
        [f"{MS}/lifecycle/products/"],
        ["T1210"]),
    "AD-010": (
        "Tier-0 assets (domain controllers, the domain itself and privileged accounts) should be managed "
        "only from privileged access workstations and kept within the Tier-0 administrative boundary.",
        [f"{MS}/security/privileged-access-workstations/privileged-access-access-model"],
        []),
}


def upgrade() -> None:
    statement = sa.text(
        "UPDATE assessment.controls SET enabled = true, recommendation = :rec, "
        "reference_links = CAST(:links AS jsonb), mitre_techniques = :mitre, version = version + 1 "
        "WHERE control_id = :id")
    for control_id, (recommendation, links, mitre) in CONTROLS.items():
        op.get_bind().execute(statement, {"id": control_id, "rec": recommendation,
                                          "links": json.dumps(links), "mitre": mitre})


def downgrade() -> None:
    op.execute("UPDATE assessment.controls SET enabled = false WHERE control_id LIKE 'AD-0%'")
