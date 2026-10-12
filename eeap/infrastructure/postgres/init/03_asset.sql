-- Asset Service schema: inventory, classification, ownership, criticality, environment.
\set ON_ERROR_STOP on

CREATE TABLE asset.owners (
    owner_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                text NOT NULL UNIQUE,                    -- e.g. "Database Team"
    email               citext,
    escalation_contact  text,
    description         text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE asset.assets (
    asset_id               varchar(64) PRIMARY KEY CHECK (asset_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    hostname               text NOT NULL,
    fqdn                   citext,
    asset_type             text NOT NULL CHECK (asset_type IN (
                               'Server', 'Workstation', 'DomainController', 'NetworkDevice',
                               'Database', 'Application', 'CloudResource', 'Identity', 'Other')),
    criticality            text NOT NULL DEFAULT 'Medium' CHECK (criticality IN ('Critical', 'High', 'Medium', 'Low')),
    criticality_locked     boolean NOT NULL DEFAULT false,       -- true = manual value, rules never overwrite
    tier                   text NOT NULL DEFAULT 'Unclassified' CHECK (tier IN ('Tier0', 'Tier1', 'Tier2', 'Unclassified')),
    environment            text NOT NULL DEFAULT 'Production' CHECK (environment IN (
                               'Production', 'Staging', 'Test', 'Development', 'DR')),
    owner_id               uuid REFERENCES asset.owners(owner_id) ON DELETE SET NULL,
    os_family              text CHECK (os_family IN ('Windows', 'Linux', 'macOS', 'NetworkOS', 'Other')),
    os_version             text,
    domain                 citext,
    status                 text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'discovered', 'retired')),
    classification_source  text NOT NULL DEFAULT 'manual' CHECK (classification_source IN ('manual', 'rule', 'import', 'discovery')),
    tags                   text[] NOT NULL DEFAULT '{}',
    attributes             jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at          timestamptz NOT NULL DEFAULT now(),
    last_seen_at           timestamptz NOT NULL DEFAULT now(),
    retired_at             timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX assets_hostname_trgm_idx ON asset.assets USING gin (hostname gin_trgm_ops);
CREATE INDEX assets_fqdn_idx          ON asset.assets (fqdn);
CREATE INDEX assets_filter_idx        ON asset.assets (status, environment, criticality, asset_type);
CREATE INDEX assets_owner_idx         ON asset.assets (owner_id);
CREATE INDEX assets_tags_idx          ON asset.assets USING gin (tags);

CREATE TABLE asset.asset_identifiers (
    identifier_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id       varchar(64) NOT NULL REFERENCES asset.assets(asset_id) ON DELETE CASCADE,
    id_type        text NOT NULL CHECK (id_type IN (
                       'ip', 'mac', 'fqdn', 'hostname', 'ad_object_sid', 'ad_object_guid',
                       'ad_dn', 'cloud_resource_id', 'serial', 'agent_id')),
    value          text NOT NULL,
    source         text NOT NULL,
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (asset_id, id_type, value)
);
-- Lookup path for reconciliation of discovery observations.
CREATE INDEX asset_identifiers_lookup_idx ON asset.asset_identifiers (id_type, value);
-- Stable identifiers may belong to only one asset.
CREATE UNIQUE INDEX asset_identifiers_stable_uq ON asset.asset_identifiers (id_type, value)
    WHERE id_type IN ('ad_object_sid', 'ad_object_guid', 'cloud_resource_id', 'agent_id');

CREATE TABLE asset.classification_rules (
    rule_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL UNIQUE,
    priority     integer NOT NULL DEFAULT 100,                   -- lower runs first
    condition    jsonb NOT NULL,                                 -- e.g. {"asset_type": "DomainController"}
    set_values   jsonb NOT NULL,                                 -- e.g. {"tier": "Tier0", "criticality": "Critical"}
    enabled      boolean NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

SELECT public.eeap_attach_updated_at_triggers('asset');
