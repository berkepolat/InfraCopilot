import pytest

from conftest import load_service_module

analysis = load_service_module("relationship-engine", "analysis", "relationship_analysis")


def node(node_id, node_type="User", *, tier0=False, privileged=False, enabled=True):
    return {"node_id": node_id, "display_name": node_id, "node_type": node_type, "is_tier0": tier0,
            "is_privileged": privileged, "enabled": enabled}


def edge(source, target, relationship="MemberOf"):
    return {"source_id": source, "target_id": target, "relationship": relationship}


def lab():
    nodes = [node("domain", "Tier0Asset", tier0=True, privileged=True),
             node("DA", "Group", tier0=True, privileged=True),
             node("ops", "Group", privileged=True),
             node("alice"), node("helper"), node("bob"),
             node("frank", enabled=False),
             node("svc_web", "ServiceAccount"), node("APP01", "Computer")]
    edges = [edge("DA", "domain", "PrivilegedAccess"),
             edge("alice", "DA"), edge("ops", "DA"), edge("helper", "ops"), edge("frank", "DA"),
             edge("APP01", "domain", "Delegation"), edge("svc_web", "APP01", "Delegation")]
    return nodes, edges


def metrics(result):
    return {m.node_id: m for m in result.metrics}


def test_propagation_score_follows_the_risk_model():
    assert analysis.propagation_score(None, 0) == 0.0
    assert analysis.propagation_score(0, 1) == 1.0
    assert analysis.propagation_score(1, 1) == 0.9
    assert analysis.propagation_score(2, 1) == 0.8  # doc 08: Tier 0 in two hops
    assert analysis.propagation_score(2, 2) == 0.85
    assert analysis.propagation_score(6, 1) == 0.4


def test_reachability_hops_and_paths():
    result = analysis.analyze(*lab())
    m = metrics(result)
    assert m["domain"].min_hops_to_tier0 == 0 and m["domain"].propagation_score == 1.0
    assert m["alice"].tier0_reachable and m["alice"].min_hops_to_tier0 == 1
    assert m["helper"].min_hops_to_tier0 == 2 and m["helper"].propagation_score == 0.8
    assert m["svc_web"].min_hops_to_tier0 == 2
    assert "bob" not in m  # isolated: no metrics row
    assert "frank" not in m  # disabled accounts are no stepping stone
    assert m["DA"].inbound_privileged_degree == 3
    assert result.node_count == 9 and result.edge_count == 7


def test_multiple_shortest_paths_are_counted():
    nodes = [node("t0", tier0=True), node("a"), node("b"), node("x")]
    edges = [edge("a", "t0"), edge("b", "t0"), edge("x", "a"), edge("x", "b")]
    m = metrics(analysis.analyze(nodes, edges))
    assert m["x"].paths_to_tier0 == 2 and m["x"].propagation_score == 0.85


def test_depth_bound_and_cycles():
    nodes = [node("t0", tier0=True), node("a"), node("b"), node("c")]
    edges = [edge("a", "t0"), edge("b", "a"), edge("c", "b"), edge("a", "c")]
    m = metrics(analysis.analyze(nodes, edges, max_depth=2))
    assert m["b"].min_hops_to_tier0 == 2
    assert "c" not in m or not m["c"].tier0_reachable


def test_concentration_areas():
    nodes, edges = lab()
    for i in range(6):
        nodes.append(node(f"admin{i}"))
        edges.append(edge(f"admin{i}", "DA"))
    result = analysis.analyze(nodes, edges)
    by_type = {}
    for area in result.areas:
        by_type.setdefault(area.area_type, []).append(area)

    sprawl = by_type["privileged_group_sprawl"]
    assert [a.anchor_node_id for a in sprawl] == ["DA"] and sprawl[0].member_count == 8
    assert 0 < sprawl[0].score <= 1
    delegation = {a.anchor_node_id: a.member_count for a in by_type["delegation_cluster"]}
    assert delegation == {"domain": 1}
    exposure = {a.anchor_node_id: a.member_count for a in by_type["tier0_exposure"]}
    # domain is reached by ops, alice, helper, APP01, svc_web and six admins (frank is disabled)
    assert exposure["domain"] == 11
    assert "admin_access_hub" not in by_type


@pytest.mark.parametrize("bad_edge", [edge("a", "a"), edge("a", "missing")])
def test_invalid_edges_are_ignored(bad_edge):
    result = analysis.analyze([node("t0", tier0=True), node("a")], [bad_edge])
    assert result.edge_count == 0
