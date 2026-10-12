"""Host-level correlation rules (asset scope, network exposure, exploitability) and ATT&CK tactics per stage.

Revision ID: ai_0012
Revises: ai_0011
"""
import json

from alembic import op
from sqlalchemy import text

revision = "ai_0012"
down_revision = "ai_0011"
branch_labels = None
depends_on = None

PATCH_CONTROLS = ["WIN-010", "WIN-011", "WIN-012", "LIN-002", "LIN-008", "LIN-009"]

RULES = {
    "CORR-HOST-001": ("Exposed host with an actively exploited or highly exploitable vulnerability", {
        "scope": "asset",
        "match": "all_stages",
        "stages": [
            {"order": 1, "name": "Reachable Network Services", "tactic": "initial-access", "exposure": {}},
            {"order": 2, "name": "Actively Exploited or Highly Exploitable Vulnerability", "tactic": "execution",
             "any_failed_controls": ["LIN-009", "WIN-010"], "finding": {"min_exploitability": 0.9}},
            {"order": 3, "name": "Host Compromise Exposure", "tactic": "impact", "derived": True},
        ],
        "scenario_title": "{subject} is reachable and runs software with a likely exploited vulnerability",
        "summary": "{subject} exposes network services and has a vulnerability that is listed in CISA KEV or ranks "
                   "in the top EPSS percentiles, so working exploits are likely to exist. This makes the host a "
                   "probable entry point. Install the fixed package or missing update first, then limit the "
                   "exposed services to the networks that need them.",
    }),
    "CORR-HOST-002": ("Unpatched or unsupported host on a path to Tier 0", {
        "scope": "asset",
        "match": "all_stages",
        "stages": [
            {"order": 1, "name": "Missing Security Updates or Unsupported OS", "tactic": "privilege-escalation",
             "any_failed_controls": PATCH_CONTROLS},
            {"order": 2, "name": "Tier-0 Reachability", "tactic": "lateral-movement",
             "graph": {"tier0_reachable": True, "max_hops": 2, "include_tier0": True}},
            {"order": 3, "name": "Tier-0 Compromise Exposure", "tactic": "impact", "derived": True},
        ],
        "scenario_title": "Patch gaps on {subject} sit on a path to Tier 0",
        "summary": "{subject} is missing security updates or runs an unsupported operating system and is a Tier-0 "
                   "asset or at most two relationships away from one. A local exploit on this host would put "
                   "domain-level control within reach. Patch or upgrade the host, and remove sessions and "
                   "privileged relationships that connect it to Tier 0.",
    }),
    "CORR-HOST-003": ("Exposed remote access with weak protocol or authentication settings", {
        "scope": "asset",
        "match": {"min_stages": 2},
        "stages": [
            {"order": 1, "name": "Exposed Remote Access or File Sharing", "tactic": "initial-access", "required": True,
             "exposure": {"classes": ["remote_admin", "file_sharing", "cleartext_login"]}},
            {"order": 2, "name": "Weak Protocol or Authentication Settings", "tactic": "credential-access",
             "any_failed_controls": ["WIN-001", "WIN-002", "WIN-003", "WIN-006", "WIN-008", "LIN-001", "LIN-005",
                                     "NET-003", "NET-004", "NET-007"]},
            {"order": 3, "name": "Missing Host Defenses", "tactic": "defense-evasion",
             "any_failed_controls": ["WIN-009", "LIN-004"]},
            {"order": 4, "name": "Remote Foothold Exposure", "tactic": "lateral-movement", "derived": True},
        ],
        "scenario_title": "Remote access to {subject} is exposed with weak settings",
        "summary": "{subject} offers remote administration or file sharing on the network while {stages} weaknesses "
                   "lower the effort needed to log in or intercept credentials there. Restrict the services to "
                   "management networks, then fix the protocol and authentication settings.",
    }),
}

# Existing rules: stage order -> ATT&CK tactic (presentation only, scores are unchanged).
TACTICS = {
    "CORR-AD-001": {1: "credential-access", 2: "privilege-escalation", 3: "impact"},
    "CORR-AD-002": {1: "credential-access", 2: "privilege-escalation", 3: "impact"},
    "CORR-AD-003": {1: "credential-access", 2: "credential-access", 3: "privilege-escalation",
                    4: "lateral-movement", 5: "impact"},
    "CORR-AUTH-001": {1: "credential-access", 2: "credential-access", 3: "privilege-escalation", 4: "impact"},
}


def _set_tactics(conn, mapping: dict[str, dict[int, str]] | None) -> None:
    for rule_id, stages in TACTICS.items():
        row = conn.execute(text("SELECT definition FROM ai.correlation_rules WHERE rule_id = :id"),
                           {"id": rule_id}).first()
        if row is None:
            continue
        definition = row[0] if isinstance(row[0], dict) else json.loads(row[0])
        for stage in definition["stages"]:
            if mapping is None:
                stage.pop("tactic", None)
            elif stage["order"] in stages:
                stage["tactic"] = stages[stage["order"]]
        conn.execute(text("UPDATE ai.correlation_rules SET definition = CAST(:d AS jsonb), version = version + 1 "
                          "WHERE rule_id = :id"), {"id": rule_id, "d": json.dumps(definition)})


def upgrade() -> None:
    conn = op.get_bind()
    for rule_id, (name, definition) in RULES.items():
        conn.execute(text(
            "INSERT INTO ai.correlation_rules (rule_id, name, definition) VALUES (:id, :name, CAST(:d AS jsonb)) "
            "ON CONFLICT (rule_id) DO UPDATE SET name = EXCLUDED.name, definition = EXCLUDED.definition, "
            "version = ai.correlation_rules.version + 1"),
            {"id": rule_id, "name": name, "d": json.dumps(definition)})
    _set_tactics(conn, TACTICS)


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("DELETE FROM ai.risk_scenarios WHERE rule_id = ANY(:ids)"), {"ids": list(RULES)})
    conn.execute(text("DELETE FROM ai.correlation_rules WHERE rule_id = ANY(:ids)"), {"ids": list(RULES)})
    _set_tactics(conn, None)
