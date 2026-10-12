# ADR-0004: Exposure graph stored in PostgreSQL, analyzed in-process

- Status: Accepted
- Date: 2026-10-12

## Context

The Relationship Engine models Users, Computers, Groups, Service Accounts and Tier-0
assets with six relationship types. Expected size: up to ~500k nodes and ~2M edges per
deployment. Required queries: neighborhood, bounded path-to-Tier-0, transitive group
expansion, concentration metrics. Neo4j adds a JVM service, separate backup and licensing
considerations.

## Decision

Store the graph as property-graph adjacency tables (`graph.nodes`, `graph.edges`) in
PostgreSQL. Serve interactive queries with indexed lookups and bounded recursive CTEs
(max depth 6, max 2,000 nodes per response). Run analytics (reachability, centrality,
concentration) in worker processes by loading a snapshot into NetworkX, writing results to
`graph.node_metrics` and `graph.concentration_areas`.

## Alternatives considered

- Neo4j / Memgraph: excellent traversal performance and Cypher, but an additional stateful
  system to secure, back up and license; data duplication with PostgreSQL.
- Apache AGE (Cypher on PostgreSQL): attractive, but extension availability on managed
  PostgreSQL offerings is limited.

## Consequences

- (+) No additional database; graph data participates in the same backups and outbox.
- (+) Storage layer hidden behind a `GraphRepository` interface → can swap to Neo4j/AGE.
- (−) Deep traversals are slower than a native graph DB; mitigated by depth bounds and
  precomputed metrics.
- (−) NetworkX memory for 2M edges ≈ 2–4 GB per analysis worker; worker memory limits set
  accordingly. Revisit when > 5M edges.
