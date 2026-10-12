"""Exposure-graph analytics on an in-memory NetworkX snapshot (pure; no I/O).

Edge direction is the direction compromise travels: whoever controls the source gains what the
target grants (member -> group, delegating account -> target host, privileged group -> domain).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

import networkx as nx

PATH_COUNT_CAP = 10_000
SPRAWL_MIN_MEMBERS = 5
ADMIN_HUB_MIN_TARGETS = 5
SERVICE_HUB_MIN_EDGES = 3
DELEGATION_MIN_SOURCES = 3
MAX_AREAS_PER_TYPE = 25
PRIVILEGE_RELATIONSHIPS = {"MemberOf", "AdministrativeAccess", "Delegation", "PrivilegedAccess"}
HUB_RELATIONSHIPS = {"AdministrativeAccess", "Delegation", "RemoteAccess", "PrivilegedAccess"}


@dataclass(frozen=True)
class NodeMetrics:
    node_id: str
    tier0_reachable: bool
    min_hops_to_tier0: int | None
    paths_to_tier0: int
    inbound_privileged_degree: int
    concentration_score: float
    propagation_score: float


@dataclass(frozen=True)
class Area:
    area_type: str
    anchor_node_id: str
    score: float
    member_count: int
    summary: str


@dataclass
class AnalysisResult:
    node_count: int
    edge_count: int
    metrics: list[NodeMetrics] = field(default_factory=list)
    areas: list[Area] = field(default_factory=list)


def propagation_score(hops: int | None, paths: int) -> float:
    """1.0 on Tier 0; 0.8 for Tier 0 two hops away over a single path; more paths raise it slightly."""
    if hops is None:
        return 0.0
    if hops == 0:
        return 1.0
    score = (1.0 - 0.1 * hops) + 0.05 * math.log2(max(paths, 1))
    return round(min(1.0, max(0.05, score)), 4)


def _log_score(count: int, saturation: int) -> float:
    if count <= 0:
        return 0.0
    return round(min(1.0, math.log2(1 + count) / math.log2(1 + saturation)), 4)


def build_graph(nodes: list[dict], edges: list[dict]) -> nx.DiGraph:
    """nodes: {node_id, display_name, node_type, is_tier0, is_privileged, enabled};
    edges: {source_id, target_id, relationship} (active only)."""
    graph = nx.DiGraph()
    for node in nodes:
        graph.add_node(node["node_id"], **node)
    for edge in edges:
        source, target = edge["source_id"], edge["target_id"]
        if source == target or source not in graph or target not in graph:
            continue
        if graph.has_edge(source, target):
            graph[source][target]["relationships"].add(edge["relationship"])
        else:
            graph.add_edge(source, target, relationships={edge["relationship"]})
    return graph


def _usable(graph: nx.DiGraph, node_id: str) -> bool:
    # A disabled account cannot be used to move towards Tier 0.
    return graph.nodes[node_id].get("enabled") is not False


def tier0_distances(graph: nx.DiGraph, max_depth: int) -> tuple[dict[str, int], dict[str, int]]:
    """Bounded reverse BFS from every Tier-0 node: hop distance and number of shortest paths."""
    tier0 = [n for n, attrs in graph.nodes(data=True) if attrs.get("is_tier0")]
    hops = {n: 0 for n in tier0}
    paths = {n: 1 for n in tier0}
    frontier = list(tier0)
    depth = 0
    while frontier and depth < max_depth:
        depth += 1
        next_frontier = []
        for node in frontier:
            for pred in graph.predecessors(node):
                if not _usable(graph, pred):
                    continue
                if pred not in hops:
                    hops[pred] = depth
                    paths[pred] = 0
                    next_frontier.append(pred)
                if hops[pred] == depth:
                    paths[pred] = min(PATH_COUNT_CAP, paths[pred] + paths[node])
        frontier = next_frontier
    return hops, paths


def _name(graph: nx.DiGraph, node_id: str) -> str:
    return graph.nodes[node_id].get("display_name") or node_id


def _in_with(graph: nx.DiGraph, node_id: str, relationships: set[str]) -> list[str]:
    return [s for s, _, d in graph.in_edges(node_id, data=True) if d["relationships"] & relationships]


def _out_with(graph: nx.DiGraph, node_id: str, relationships: set[str]) -> list[str]:
    return [t for _, t, d in graph.out_edges(node_id, data=True) if d["relationships"] & relationships]


def _areas(graph: nx.DiGraph, hops: dict[str, int], max_depth: int) -> list[Area]:
    found: dict[str, list[Area]] = {}

    def add(area: Area) -> None:
        found.setdefault(area.area_type, []).append(area)

    for node_id, attrs in graph.nodes(data=True):
        if attrs.get("node_type") == "Group" and attrs.get("is_privileged"):
            members = [m for m in _in_with(graph, node_id, {"MemberOf"}) if _usable(graph, m)]
            if len(members) > SPRAWL_MIN_MEMBERS:
                add(Area("privileged_group_sprawl", node_id, _log_score(len(members), 50), len(members),
                         f"{_name(graph, node_id)} has {len(members)} enabled members (direct or nested)."))

        delegators = [s for s in _in_with(graph, node_id, {"Delegation"}) if _usable(graph, s)]
        if delegators and (attrs.get("is_tier0") or len(delegators) >= DELEGATION_MIN_SOURCES):
            add(Area("delegation_cluster", node_id, _log_score(len(delegators), 20), len(delegators),
                     f"{len(delegators)} accounts hold Kerberos delegation towards {_name(graph, node_id)}."))

        admin_targets = _out_with(graph, node_id, {"AdministrativeAccess"})
        if len(admin_targets) >= ADMIN_HUB_MIN_TARGETS:
            add(Area("admin_access_hub", node_id, _log_score(len(admin_targets), 100), len(admin_targets),
                     f"{_name(graph, node_id)} has administrative access to {len(admin_targets)} systems."))

        if attrs.get("node_type") == "ServiceAccount":
            reach = _out_with(graph, node_id, HUB_RELATIONSHIPS)
            if len(reach) >= SERVICE_HUB_MIN_EDGES:
                add(Area("service_account_hub", node_id, _log_score(len(reach), 50), len(reach),
                         f"Service account {_name(graph, node_id)} has privileged reach to {len(reach)} objects."))

    traversable = graph.subgraph(n for n in graph if _usable(graph, n) or graph.nodes[n].get("is_tier0"))
    reverse = traversable.reverse(copy=False)
    for anchor in (n for n, h in hops.items() if h == 0):
        reached = nx.single_source_shortest_path_length(reverse, anchor, cutoff=max_depth)
        exposed = [n for n in reached if not graph.nodes[n].get("is_tier0")]
        if exposed:
            add(Area("tier0_exposure", anchor, _log_score(len(exposed), 200), len(exposed),
                     f"{len(exposed)} non-Tier-0 objects have a path of at most {max_depth} hops to "
                     f"{_name(graph, anchor)}."))

    areas = []
    for items in found.values():
        items.sort(key=lambda a: (-a.score, -a.member_count, a.anchor_node_id))
        areas.extend(items[:MAX_AREAS_PER_TYPE])
    return areas


def analyze(nodes: list[dict], edges: list[dict], max_depth: int = 6) -> AnalysisResult:
    graph = build_graph(nodes, edges)
    hops, paths = tier0_distances(graph, max_depth)
    privileged_in = {n: len(_in_with(graph, n, PRIVILEGE_RELATIONSHIPS)) for n in graph.nodes}
    max_in = max(privileged_in.values(), default=0)

    metrics = []
    for node_id in graph.nodes:
        hop = hops.get(node_id)
        inbound = privileged_in[node_id]
        if hop is None and inbound == 0:
            continue  # only non-trivial rows are stored
        metrics.append(NodeMetrics(
            node_id=node_id, tier0_reachable=hop is not None, min_hops_to_tier0=hop,
            paths_to_tier0=paths.get(node_id, 0), inbound_privileged_degree=inbound,
            concentration_score=_log_score(inbound, max_in) if max_in else 0.0,
            propagation_score=propagation_score(hop, paths.get(node_id, 0)),
        ))
    return AnalysisResult(node_count=graph.number_of_nodes(), edge_count=graph.number_of_edges(),
                          metrics=metrics, areas=_areas(graph, hops, max_depth))
