"""Exposure-graph relationship facts derived from an AD configuration snapshot (relationship.observed).

Only relationships the snapshot already proves are emitted: (transitive) membership of privileged
groups, privileged groups' control of the domain, and Kerberos delegation configuration. Computers
use the inventory node key (`asset:<asset_id>`) so they merge with nodes created from asset events.
"""
from __future__ import annotations

from .controls.ad import UAC_TRUSTED_FOR_DELEGATION, UAC_TRUSTED_TO_AUTH_FOR_DELEGATION, asset_id_for

MAX_RELATIONSHIPS = 50_000


def _spn_host(spn: str) -> str:
    host = spn.split("/", 2)[1] if "/" in spn else spn
    return host.split(":", 1)[0].lower()


class _Builder:
    def __init__(self, snapshot: dict, run_id: str | None):
        self.snapshot = snapshot
        self.domain = snapshot["domain"]["dns_name"]
        self.scope = f"ad:{self.domain}"
        self.run_id = run_id
        self.observed_at = snapshot["collected_at"]
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple[str, str, str], dict] = {}
        self.privileged_dns = {m["dn"] for g in snapshot["privileged_groups"] for m in g["members"] if m["dn"]}
        self.accounts_by_dn = {a["dn"]: a for a in snapshot["users"] + snapshot["computers"] if a["dn"]}
        self.computers_by_host: dict[str, dict] = {}
        for computer in snapshot["computers"]:
            for host in (computer["name"], computer["dns_host_name"]):
                if host:
                    self.computers_by_host[host.lower()] = computer

    def node(self, node: dict) -> str:
        key = node["node_key"]
        existing = self.nodes.get(key)
        if existing is None:
            self.nodes[key] = node
        else:
            existing["is_tier0"] = existing["is_tier0"] or node["is_tier0"]
            existing["is_privileged"] = existing["is_privileged"] or node["is_privileged"]
        return key

    def domain_node(self) -> str:
        domain = self.snapshot["domain"]
        asset_id = asset_id_for(domain["dns_name"])
        return self.node({"node_key": f"asset:{asset_id}", "node_type": "Tier0Asset", "display_name": domain["dns_name"],
                          "asset_id": asset_id, "domain": self.domain, "is_tier0": True, "is_privileged": True,
                          "enabled": True, "properties": {"dn": domain["dn"], "sid": domain["sid"]}})

    def computer_node(self, computer: dict) -> str:
        asset_id = asset_id_for(computer["name"])
        return self.node({"node_key": f"asset:{asset_id}", "node_type": "Computer", "display_name": computer["name"],
                          "asset_id": asset_id, "domain": self.domain, "is_tier0": bool(computer["is_dc"]),
                          "is_privileged": computer["dn"] in self.privileged_dns, "enabled": computer["enabled"],
                          "properties": {"dn": computer["dn"], "sid": computer["sid"]}})

    def principal_node(self, *, dn: str | None, sid: str | None, sam: str | None, kind: str,
                       enabled: bool | None) -> str:
        account = self.accounts_by_dn.get(dn) if dn else None
        if account is not None and "is_dc" in account:
            return self.computer_node(account)
        if kind == "computer":
            name = (sam or dn or sid or "unknown").rstrip("$")
            return self.computer_node({"name": name, "dn": dn, "sid": sid, "is_dc": False, "enabled": enabled})
        if kind == "group":
            node_type = "Group"
        else:
            node_type = "ServiceAccount" if account is not None and account["spns"] else "User"
        key = f"ad:{sid}" if sid else f"ad:dn:{(dn or sam or '').lower()}"
        return self.node({"node_key": key, "node_type": node_type, "display_name": sam or dn or sid or key,
                          "asset_id": None, "domain": self.domain, "is_tier0": False,
                          "is_privileged": bool(dn) and dn in self.privileged_dns,
                          "enabled": account["enabled"] if account is not None else enabled,
                          "properties": {k: v for k, v in (("dn", dn), ("sid", sid)) if v}})

    def account_node(self, account: dict) -> str:
        if "is_dc" in account:
            return self.computer_node(account)
        return self.principal_node(dn=account["dn"], sid=account["sid"], sam=account["sam"], kind="user",
                                   enabled=account["enabled"])

    def edge(self, source: str, relationship: str, target: str, **properties) -> None:
        if source == target:
            return
        key = (source, target, relationship)
        existing = self.edges.get(key)
        if existing is not None:
            for name, value in properties.items():
                if isinstance(value, list):
                    existing["properties"][name] = sorted(set(existing["properties"].get(name, [])) | set(value))
            return
        self.edges[key] = {"properties": {"scope": self.scope, **properties}}

    def build(self) -> list[dict]:
        domain = self.domain_node()
        for group in self.snapshot["privileged_groups"]:
            group_key = self.node({"node_key": f"ad:{group['sid']}", "node_type": "Group", "display_name": group["name"],
                                   "asset_id": None, "domain": self.domain, "is_tier0": True, "is_privileged": True,
                                   "enabled": None, "properties": {"dn": group["dn"], "sid": group["sid"]}})
            self.edge(group_key, "PrivilegedAccess", domain, privilege=group["name"])
            for member in group["members"]:
                member_key = self.principal_node(dn=member["dn"], sid=member["sid"], sam=member["sam"],
                                                 kind=member["kind"], enabled=member["enabled"])
                self.edge(member_key, "MemberOf", group_key, transitive=True)

        for account in self.snapshot["users"] + self.snapshot["computers"]:
            if not account["enabled"] or account.get("is_dc"):
                continue
            if account["uac"] & UAC_TRUSTED_FOR_DELEGATION:
                self.edge(self.account_node(account), "Delegation", domain, delegation_type="unconstrained")
            transition = bool(account["uac"] & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION)
            for spn in account["delegate_to"]:
                target = self.computers_by_host.get(_spn_host(spn))
                if target is None:
                    continue
                self.edge(self.account_node(account), "Delegation", self.computer_node(target),
                          delegation_type="constrained", protocol_transition=transition, spns=[spn])

        relationships = []
        for (source, target, relationship), edge in sorted(self.edges.items()):
            relationships.append({
                "source": source, "relationship": relationship, "target": target,
                "source_node": self.nodes[source], "target_node": self.nodes[target],
                "properties": edge["properties"], "origin": "collector",
                "observed_run_id": self.run_id, "observed_at": self.observed_at,
            })
        return relationships[:MAX_RELATIONSHIPS]


def build_relationships(snapshot: dict, run_id: str | None = None) -> list[dict]:
    """Relationship observations (shared/schemas/relationship.schema.json) for one domain snapshot."""
    return _Builder(snapshot, run_id).build()
