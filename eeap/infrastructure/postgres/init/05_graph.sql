-- Relationship Engine schema: exposure graph (property graph on adjacency tables) and analysis results.
\set ON_ERROR_STOP on

CREATE TABLE graph.nodes (
    node_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_key        text NOT NULL UNIQUE,                        -- stable natural key, e.g. "ad:S-1-5-21-...-1105", "asset:SRV001"
    node_type       text NOT NULL CHECK (node_type IN ('User', 'Computer', 'Group', 'ServiceAccount', 'Tier0Asset')),
    display_name    text NOT NULL,
    asset_id        varchar(64),                                 -- logical ref to asset.assets for Computer / Tier0Asset
    domain          citext,
    is_tier0        boolean NOT NULL DEFAULT false,              -- any node type may be Tier0 (e.g. a DC Computer)
    is_privileged   boolean NOT NULL DEFAULT false,
    enabled         boolean,
    properties      jsonb NOT NULL DEFAULT '{}'::jsonb,
    source          text NOT NULL,                               -- collector or import that produced the node
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX nodes_type_idx    ON graph.nodes (node_type) WHERE deleted_at IS NULL;
CREATE INDEX nodes_tier0_idx   ON graph.nodes (node_id) WHERE is_tier0 AND deleted_at IS NULL;
CREATE INDEX nodes_asset_idx   ON graph.nodes (asset_id);
CREATE INDEX nodes_name_trgm   ON graph.nodes USING gin (display_name gin_trgm_ops);

CREATE TABLE graph.edges (
    edge_id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    source_node_id       uuid NOT NULL REFERENCES graph.nodes(node_id) ON DELETE CASCADE,
    target_node_id       uuid NOT NULL REFERENCES graph.nodes(node_id) ON DELETE CASCADE,
    relationship         text NOT NULL CHECK (relationship IN (
                             'MemberOf', 'AdministrativeAccess', 'Delegation',
                             'AuthenticationRisk', 'RemoteAccess', 'PrivilegedAccess')),
    properties           jsonb NOT NULL DEFAULT '{}'::jsonb,     -- e.g. {"delegation_type": "constrained", "spn": "..."}
    origin               text NOT NULL CHECK (origin IN ('collector', 'import', 'derived')),
    evidence_finding_id  uuid,                                   -- logical ref to assessment.findings
    observed_run_id      uuid,
    is_active            boolean NOT NULL DEFAULT true,
    first_seen_at        timestamptz NOT NULL DEFAULT now(),
    last_seen_at         timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT edges_no_self_loop CHECK (source_node_id <> target_node_id),
    UNIQUE (source_node_id, target_node_id, relationship)
);
CREATE INDEX edges_out_idx ON graph.edges (source_node_id, relationship) WHERE is_active;
CREATE INDEX edges_in_idx  ON graph.edges (target_node_id, relationship) WHERE is_active;

CREATE TABLE graph.analysis_runs (
    analysis_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    trigger        text NOT NULL,                                -- event type or "manual"
    status         text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
    node_count     integer,
    edge_count     integer,
    parameters     jsonb NOT NULL DEFAULT '{}'::jsonb,           -- max_depth, sampling, etc.
    started_at     timestamptz NOT NULL DEFAULT now(),
    completed_at   timestamptz,
    error          text
);

CREATE TABLE graph.node_metrics (
    analysis_id                 uuid NOT NULL REFERENCES graph.analysis_runs(analysis_id) ON DELETE CASCADE,
    node_id                     uuid NOT NULL REFERENCES graph.nodes(node_id) ON DELETE CASCADE,
    tier0_reachable             boolean NOT NULL DEFAULT false,
    min_hops_to_tier0           smallint,
    paths_to_tier0              integer NOT NULL DEFAULT 0,      -- bounded count (max depth per analysis parameters)
    inbound_privileged_degree   integer NOT NULL DEFAULT 0,
    concentration_score         numeric(5,4) NOT NULL DEFAULT 0 CHECK (concentration_score BETWEEN 0 AND 1),
    propagation_score           numeric(5,4) NOT NULL DEFAULT 0 CHECK (propagation_score BETWEEN 0 AND 1),
    PRIMARY KEY (analysis_id, node_id)
);

CREATE TABLE graph.concentration_areas (
    area_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    analysis_id    uuid NOT NULL REFERENCES graph.analysis_runs(analysis_id) ON DELETE CASCADE,
    anchor_node_id uuid NOT NULL REFERENCES graph.nodes(node_id) ON DELETE CASCADE,
    area_type      text NOT NULL CHECK (area_type IN (
                       'privileged_group_sprawl', 'admin_access_hub', 'delegation_cluster',
                       'service_account_hub', 'tier0_exposure')),
    score          numeric(5,4) NOT NULL CHECK (score BETWEEN 0 AND 1),
    member_count   integer NOT NULL,
    summary        text NOT NULL
);

SELECT public.eeap_attach_updated_at_triggers('graph');
