"""Port discovery: NET-006..NET-009 controls and the network service inventory.

Revision ID: assessment_0004
"""
import json

import sqlalchemy as sa
from alembic import op

revision = "assessment_0004"
down_revision = "assessment_0003"
branch_labels = None
depends_on = None

# control -> (name, category, severity, exploitability, privilege_impact, collector, recommendation, links, mitre)
CONTROLS = {
    "NET-006": (
        "Remote Administration Exposure", "Network Exposure", "Medium", 0.50, 0.60, "net.port_scan",
        ("Expose SSH, RDP, WinRM and VNC only to management networks or jump hosts (host firewall and "
        "segmentation). Require Network Level Authentication for RDP and prefer WinRM over HTTPS."),
        ["https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access",
         "https://www.cisecurity.org/controls/v8"],
        ["T1021.001", "T1021.004", "T1021.006", "T1133"]),
    "NET-007": (
        "Cleartext Legacy Protocols", "Transport Security", "High", 0.60, 0.50, "net.port_scan",
        ("Disable Telnet, FTP and the r-services (rexec, rlogin, rsh). Replace them with SSH/SFTP or FTPS and "
        "remove the packages where possible."),
        ["https://www.cisecurity.org/benchmark/distribution_independent_linux"],
        ["T1040", "T1110"]),
    "NET-008": (
        "Data Store Exposure", "Network Exposure", "Medium", 0.50, 0.60, "net.port_scan",
        ("Bind databases, caches and search engines to private interfaces and allow connections only from "
        "their application servers. Require authentication and TLS on every data store."),
        ["https://www.cisecurity.org/cis-benchmarks"],
        ["T1213", "T1190"]),
    "NET-009": (
        "Container and Orchestration Control Plane Exposure", "Network Exposure", "High", 0.70, 0.90,
        "net.port_scan",
        ("Never expose the Docker Engine API without TLS client authentication; restrict Kubernetes API, kubelet "
        "and etcd to control-plane networks and require mutual TLS and RBAC."),
        ["https://docs.docker.com/engine/security/protect-access/",
         "https://kubernetes.io/docs/concepts/security/controlling-access/"],
        ["T1609", "T1610"]),
}


def upgrade() -> None:
    insert = sa.text(
        "INSERT INTO assessment.controls (control_id, name, module, category, default_severity, exploitability, "
        "privilege_impact, execution_site, collector_id, recommendation, reference_links, mitre_techniques, "
        "enabled) VALUES (:id, :name, 'NET', :category, :severity, :exp, :priv, 'server', :collector, :rec, "
        "CAST(:links AS jsonb), :mitre, true) ON CONFLICT (control_id) DO NOTHING")
    for control_id, (name, category, severity, exp, priv, collector, rec, links, mitre) in CONTROLS.items():
        op.get_bind().execute(insert, {"id": control_id, "name": name, "category": category, "severity": severity,
                                       "exp": exp, "priv": priv, "collector": collector, "rec": rec,
                                       "links": json.dumps(links), "mitre": mitre})

    op.execute("""
        CREATE TABLE assessment.network_services (
            service_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            asset_id           text NOT NULL,
            ip                 inet NOT NULL,
            transport          text NOT NULL DEFAULT 'tcp' CHECK (transport IN ('tcp', 'udp')),
            port               integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
            state              text NOT NULL CHECK (state IN ('open', 'closed')),
            service            text NOT NULL,
            product            text,
            version            text,
            tls_version        text,
            details            jsonb NOT NULL DEFAULT '{}'::jsonb,
            first_seen_at      timestamptz NOT NULL,
            last_seen_at       timestamptz NOT NULL,
            first_seen_run_id  uuid,
            last_seen_run_id   uuid,
            closed_at          timestamptz,
            updated_at         timestamptz NOT NULL DEFAULT now(),
            UNIQUE (ip, transport, port)
        )""")
    op.execute("CREATE INDEX network_services_asset_idx ON assessment.network_services (asset_id, state)")
    op.execute("CREATE INDEX network_services_port_idx ON assessment.network_services (port) WHERE state = 'open'")


def downgrade() -> None:
    op.execute("DROP TABLE assessment.network_services")
    op.execute("DELETE FROM assessment.controls WHERE control_id IN ('NET-006', 'NET-007', 'NET-008', 'NET-009') "
               "AND NOT EXISTS (SELECT 1 FROM assessment.findings f WHERE f.control_id = controls.control_id)")
