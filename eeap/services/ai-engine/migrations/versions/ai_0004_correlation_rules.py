"""Correlation rules over AD findings and exposure-graph facts (docs/architecture/14-correlation.md).

Revision ID: ai_0004
Revises: ai_0003
"""
import json

from alembic import op
from sqlalchemy import text

revision = "ai_0004"
down_revision = "ai_0003"
branch_labels = None
depends_on = None

RULES = {
    "CORR-AD-001": ("Offline-crackable credentials on an account with a short path to Tier 0", {
        "scope": "subject",
        "match": "all_stages",
        "stages": [
            {"order": 1, "name": "Offline-Crackable Credential Exposure", "any_failed_controls": ["AD-002", "AD-003"]},
            {"order": 2, "name": "Tier-0 Reachability", "graph": {"tier0_reachable": True, "max_hops": 1}},
            {"order": 3, "name": "Domain Compromise Exposure", "derived": True},
        ],
        "scenario_title": "Crackable credentials of {subject} lead directly to Tier 0",
        "summary": "{subject} has credential material that can be attacked offline (SPN or missing Kerberos "
                   "pre-authentication) and is one relationship away from Tier 0. A recovered password would "
                   "grant domain-level privileges. Rotate to a long random or managed (gMSA) password and remove "
                   "the privileged path.",
    }),
    "CORR-AD-002": ("Kerberos delegation on a path to Tier 0", {
        "scope": "subject",
        "match": "all_stages",
        "stages": [
            {"order": 1, "name": "Kerberos Delegation Configured", "any_failed_controls": ["AD-004", "AD-005", "AD-006"]},
            {"order": 2, "name": "Tier-0 Reachability", "graph": {"tier0_reachable": True, "max_hops": 2}},
            {"order": 3, "name": "Privilege Escalation Exposure", "derived": True},
        ],
        "scenario_title": "Delegation configured on {subject} reaches Tier 0",
        "summary": "{subject} is trusted for Kerberos delegation and the exposure graph shows a path of at most "
                   "two relationships to Tier 0. Control of {subject} would allow impersonating users towards "
                   "Tier-0 services. Remove the delegation or restrict it to non-Tier-0 services, and mark "
                   "privileged accounts as sensitive.",
    }),
    "CORR-AD-003": ("Weak domain authentication posture combined with privileged sprawl", {
        "scope": "organization",
        "match": {"min_stages": 3},
        "stages": [
            {"order": 1, "name": "Weak Domain Password Policy", "any_failed_controls": ["AD-001"]},
            {"order": 2, "name": "Crackable Service Credentials", "any_failed_controls": ["AD-002", "AD-003"]},
            {"order": 3, "name": "Privileged Group Sprawl", "any_failed_controls": ["AD-007"], "required": True},
            {"order": 4, "name": "Unmanaged Local Administrator Passwords", "any_failed_controls": ["AD-008"]},
            {"order": 5, "name": "Increased Organizational Risk", "derived": True},
        ],
        "scenario_title": "Domain authentication weaknesses amplify privileged access exposure",
        "summary": "{stages} independent weaknesses combine: password and credential hygiene gaps make account "
                   "takeover more likely while broad privileged group membership raises the impact of any "
                   "single compromised account. Reduce privileged membership first, then harden the password "
                   "policy and service account credentials.",
    }),
}

AUTH_001_V2 = {
    "scope": "organization",
    "match": "all_stages",
    "stages": [
        {"order": 1, "name": "Authentication Hardening Gap", "any_failed_controls": ["WIN-001", "WIN-003", "WIN-004", "WIN-005"]},
        {"order": 2, "name": "Service Account Risk", "any_failed_controls": ["AD-002", "AD-003"]},
        {"order": 3, "name": "Privileged Resource Exposure", "any_failed_controls": ["AD-007"],
         "graph": {"privileged": True}},
        {"order": 4, "name": "Increased Organizational Risk", "derived": True},
    ],
    "scenario_title": "Authentication hardening gaps amplify service account and privileged access exposure",
    "summary": "Host authentication hardening gaps, exposed service account credentials and privileged access "
               "weaknesses are present together.",
}


def upgrade() -> None:
    conn = op.get_bind()
    for rule_id, (name, definition) in RULES.items():
        conn.execute(text(
            "INSERT INTO ai.correlation_rules (rule_id, name, definition) VALUES (:id, :name, CAST(:d AS jsonb)) "
            "ON CONFLICT (rule_id) DO UPDATE SET name = EXCLUDED.name, definition = EXCLUDED.definition, "
            "version = ai.correlation_rules.version + 1"),
            {"id": rule_id, "name": name, "d": json.dumps(definition)})
    conn.execute(text(
        "UPDATE ai.correlation_rules SET definition = CAST(:d AS jsonb), version = 2 WHERE rule_id = 'CORR-AUTH-001'"),
        {"d": json.dumps(AUTH_001_V2)})


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(text("DELETE FROM ai.risk_scenarios WHERE rule_id = ANY(:ids)"), {"ids": list(RULES)})
    conn.execute(text("DELETE FROM ai.correlation_rules WHERE rule_id = ANY(:ids)"), {"ids": list(RULES)})
