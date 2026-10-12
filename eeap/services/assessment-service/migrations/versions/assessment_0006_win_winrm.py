"""Credentialed WinRM/JEA evaluation of WIN-003, WIN-004, WIN-005, WIN-007 and WIN-009.

Revision ID: assessment_0006
"""
import json

import sqlalchemy as sa
from alembic import op

revision = "assessment_0006"
down_revision = "assessment_0005"
branch_labels = None
depends_on = None

COLLECTOR = "win.winrm_posture"

# control -> (recommendation, links)
CONTROLS = {
    "WIN-003": (
        ("Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM & "
         "NTLM' (5), keep 'Do not store LAN Manager hash value' enabled and audit NTLM before restricting it."),
        [("https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/"
         "security-policy-settings/network-security-lan-manager-authentication-level")]),
    "WIN-004": (
        ("Set 'Domain controller: LDAP server signing requirements' to 'Require signing' on every domain "
         "controller after checking event 2889 for unsigned binds."),
        ["https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server"]),
    "WIN-005": (
        ("Set 'Domain controller: LDAP server channel binding token requirements' to 'Always' "
         "(LdapEnforceChannelBinding = 2) once clients support channel binding."),
        [("https://support.microsoft.com/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-"
         "for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a")]),
    "WIN-007": (
        ("Remove unexpected members from the local Administrators group, manage membership with Group Policy "
         "Restricted Groups or LAPS, and list approved exceptions in WIN_LOCAL_ADMINS_ALLOWED."),
        [("https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/"
         "implementing-least-privilege-administrative-models")]),
    "WIN-009": (
        ("Keep Microsoft Defender real-time protection or a supported EDR running on every host and make sure "
         "signatures update at least daily."),
        ["https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows"]),
}
AGENT_COLLECTORS = {"WIN-003": "win.lsa_config", "WIN-004": "win.ldap_server_config",
                    "WIN-005": "win.ldap_server_config", "WIN-007": "win.local_admins",
                    "WIN-009": "win.security_products"}


def upgrade() -> None:
    update = sa.text(
        "UPDATE assessment.controls SET execution_site = 'server', collector_id = :collector, enabled = true, "
        "recommendation = :rec, reference_links = CAST(:links AS jsonb), updated_at = now() WHERE control_id = :id")
    for control_id, (rec, links) in CONTROLS.items():
        op.get_bind().execute(update, {"id": control_id, "collector": COLLECTOR, "rec": rec,
                                       "links": json.dumps(links)})


def downgrade() -> None:
    revert = sa.text(
        "UPDATE assessment.controls SET execution_site = 'agent:windows', collector_id = :collector, "
        "enabled = false, updated_at = now() WHERE control_id = :id")
    for control_id, collector in AGENT_COLLECTORS.items():
        op.get_bind().execute(revert, {"id": control_id, "collector": collector})
