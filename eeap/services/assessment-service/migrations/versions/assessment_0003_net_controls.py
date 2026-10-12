"""Enable NET-001..NET-005 (read-only IP network probes) and add remediation guidance.

Revision ID: assessment_0003
"""
import json

import sqlalchemy as sa
from alembic import op

revision = "assessment_0003"
down_revision = "assessment_0002"
branch_labels = None
depends_on = None

CONTROLS = {
    "NET-001": (
        "Disable DNS zone transfers (AXFR) to unauthorized hosts. Allow AXFR only to explicitly "
        "listed secondary name servers, preferably over TSIG-authenticated channels.",
        ["https://datatracker.ietf.org/doc/html/rfc5936",
         "https://www.cisecurity.org/benchmark/dns"],
        ["T1590.002"]),
    "NET-002": (
        "Disable TLS 1.0 and TLS 1.1 on every listener. Prefer TLS 1.2+ with modern cipher suites "
        "and keep certificates valid and renewed before expiry.",
        ["https://datatracker.ietf.org/doc/html/rfc8996",
         "https://ssl-config.mozilla.org/"],
        ["T1040"]),
    "NET-003": (
        "Restrict SMB (TCP/445) exposure with host firewalls and network segmentation. Prefer "
        "SMB signing and disable SMBv1 on Windows hosts (see WIN-001/WIN-002).",
        ["https://learn.microsoft.com/windows-server/storage/file-server/smb-security"],
        ["T1021.002"]),
    "NET-004": (
        "Disable SNMPv1/v2c or change default communities; prefer SNMPv3 with authentication and "
        "privacy. Do not expose SNMP to untrusted networks.",
        ["https://datatracker.ietf.org/doc/html/rfc3414"],
        ["T1040", "T1592"]),
    "NET-005": (
        "Limit NTP access to authorized clients and use authenticated NTP (NTS/Autokey) where "
        "supported. Disable monlist/mode-6 control queries on public-facing servers.",
        ["https://datatracker.ietf.org/doc/html/rfc5905",
         "https://www.cisecurity.org/benchmark/network_devices"],
        ["T1498"]),
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
    op.execute("UPDATE assessment.controls SET enabled = false WHERE control_id LIKE 'NET-0%'")
