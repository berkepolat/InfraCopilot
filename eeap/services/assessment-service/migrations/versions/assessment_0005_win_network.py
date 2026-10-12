"""Credential-free network evaluation of WIN-001, WIN-002, WIN-006 and WIN-008.

Revision ID: assessment_0005
"""
import json

import sqlalchemy as sa
from alembic import op

revision = "assessment_0005"
down_revision = "assessment_0004"
branch_labels = None
depends_on = None

# control -> (collector, recommendation, links)
CONTROLS = {
    "WIN-001": (
        "net.smb_negotiate",
        ("Require SMB signing on servers and clients ('Microsoft network server: Digitally sign communications "
        "(always)' by Group Policy; 'server signing = mandatory' on Samba)."),
        ["https://learn.microsoft.com/windows-server/storage/file-server/smb-signing"]),
    "WIN-002": (
        "net.smb_negotiate",
        ("Remove the SMB 1.0/CIFS feature from Windows hosts and set 'server min protocol = SMB2_10' or higher "
        "on Samba."),
        ["https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"]),
    "WIN-006": (
        "net.port_scan",
        ("Require Network Level Authentication for Remote Desktop connections by Group Policy and disable the "
        "legacy RDP security layer."),
        ["https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access"]),
    "WIN-008": (
        "net.port_scan",
        ("Remove WinRM HTTP listeners, keep HTTPS (5986) listeners with a valid certificate only and restrict "
        "them to management networks."),
        ["https://learn.microsoft.com/windows/win32/winrm/installation-and-configuration-for-windows-remote-management"]),
}
AGENT_COLLECTORS = {"WIN-001": "win.smb_config", "WIN-002": "win.smb_config", "WIN-006": "win.rdp_config",
                    "WIN-008": "win.winrm_config"}


def upgrade() -> None:
    update = sa.text(
        "UPDATE assessment.controls SET execution_site = 'server', collector_id = :collector, enabled = true, "
        "recommendation = :rec, reference_links = CAST(:links AS jsonb), updated_at = now() WHERE control_id = :id")
    for control_id, (collector, rec, links) in CONTROLS.items():
        op.get_bind().execute(update, {"id": control_id, "collector": collector, "rec": rec,
                                       "links": json.dumps(links)})


def downgrade() -> None:
    revert = sa.text(
        "UPDATE assessment.controls SET execution_site = 'agent:windows', collector_id = :collector, "
        "enabled = false, updated_at = now() WHERE control_id = :id")
    for control_id, collector in AGENT_COLLECTORS.items():
        op.get_bind().execute(revert, {"id": control_id, "collector": collector})
