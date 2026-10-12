"""Web service checks on HTTP(S) ports found by the port scan: NET-010..NET-012.

Revision ID: assessment_0008
"""
import json

import sqlalchemy as sa
from alembic import op

revision = "assessment_0008"
down_revision = "assessment_0007"
branch_labels = None
depends_on = None

COLLECTOR = "net.web_probe"
OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"

# control -> (name, category, severity, exploitability, privilege_impact, recommendation, links, mitre)
CONTROLS = {
    "NET-010": (
        "Web Security Headers", "Web Exposure", "Low", 0.30, 0.20,
        ("Send Strict-Transport-Security on HTTPS sites, X-Content-Type-Options: nosniff and X-Frame-Options or "
         "a CSP frame-ancestors directive, and stop the Server header from disclosing version numbers."),
        [OWASP_HEADERS, "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"],
        ["T1557", "T1592"]),
    "NET-011": (
        "Web Content Exposure", "Web Exposure", "High", 0.70, 0.40,
        ("Remove .git directories and phpinfo pages from the web root, disable directory listing, restrict "
         "server-status/server-info, Tomcat Manager and Spring Boot actuator endpoints to administrators and "
         "replace default pages with the site or a blank page."),
        ["https://owasp.org/www-project-web-security-testing-guide/",
         "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html"],
        ["T1552.001", "T1592", "T1190"]),
    "NET-012": (
        "Web Transport Security", "Web Exposure", "High", 0.50, 0.50,
        ("Serve login pages and other content over HTTPS only, redirect HTTP to HTTPS and use certificates "
         "from a trusted CA that are renewed before they expire."),
        ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"],
        ["T1040", "T1557"]),
}


def upgrade() -> None:
    insert = sa.text(
        "INSERT INTO assessment.controls (control_id, name, module, category, default_severity, exploitability, "
        "privilege_impact, execution_site, collector_id, recommendation, reference_links, mitre_techniques, "
        "enabled) VALUES (:id, :name, 'NET', :category, :severity, :exp, :priv, 'server', :collector, :rec, "
        "CAST(:links AS jsonb), :mitre, true) ON CONFLICT (control_id) DO NOTHING")
    for control_id, (name, category, severity, exp, priv, rec, links, mitre) in CONTROLS.items():
        op.get_bind().execute(insert, {"id": control_id, "name": name, "category": category, "severity": severity,
                                       "exp": exp, "priv": priv, "collector": COLLECTOR, "rec": rec,
                                       "links": json.dumps(links), "mitre": mitre})


def downgrade() -> None:
    op.get_bind().execute(sa.text(
        "DELETE FROM assessment.controls WHERE control_id = ANY(:ids) "
        "AND NOT EXISTS (SELECT 1 FROM assessment.findings f WHERE f.control_id = controls.control_id)"),
        {"ids": list(CONTROLS)})
