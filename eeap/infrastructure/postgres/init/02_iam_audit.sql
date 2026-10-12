-- Schemas owned by the API Gateway: iam (identity, RBAC, agents) and audit (append-only).
\set ON_ERROR_STOP on

-- ---------------------------------------------------------------- iam
CREATE TABLE iam.users (
    user_id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username             citext      NOT NULL UNIQUE,
    email                citext      UNIQUE,
    display_name         text        NOT NULL,
    password_hash        text,                                   -- Argon2id; NULL for federated users
    auth_source          text        NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local', 'oidc', 'ldap')),
    external_subject     text,
    is_active            boolean     NOT NULL DEFAULT true,
    mfa_enabled          boolean     NOT NULL DEFAULT false,
    failed_login_count   integer     NOT NULL DEFAULT 0,
    locked_until         timestamptz,
    last_login_at        timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_local_has_password CHECK (auth_source <> 'local' OR password_hash IS NOT NULL),
    CONSTRAINT users_external_subject_uq UNIQUE (auth_source, external_subject)
);

CREATE TABLE iam.roles (
    role_id      text PRIMARY KEY,
    description  text NOT NULL,
    is_system    boolean NOT NULL DEFAULT true
);

CREATE TABLE iam.permissions (
    permission_id  text PRIMARY KEY CHECK (permission_id ~ '^[a-z_]+:[a-z_]+$'),
    description    text NOT NULL
);

CREATE TABLE iam.role_permissions (
    role_id        text NOT NULL REFERENCES iam.roles(role_id) ON DELETE CASCADE,
    permission_id  text NOT NULL REFERENCES iam.permissions(permission_id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE iam.user_roles (
    user_id     uuid NOT NULL REFERENCES iam.users(user_id) ON DELETE CASCADE,
    role_id     text NOT NULL REFERENCES iam.roles(role_id) ON DELETE RESTRICT,
    -- Optional scope restriction, e.g. {"owner_ids": ["..."]} for asset_owner.
    scope       jsonb NOT NULL DEFAULT '{}'::jsonb,
    granted_by  uuid REFERENCES iam.users(user_id),
    granted_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE iam.refresh_tokens (
    token_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES iam.users(user_id) ON DELETE CASCADE,
    family_id    uuid NOT NULL,                                  -- rotation family; reuse detection revokes the family
    token_hash   bytea NOT NULL UNIQUE,                          -- SHA-256 of the opaque token
    issued_at    timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    replaced_by  uuid REFERENCES iam.refresh_tokens(token_id),
    client_ip    inet,
    user_agent   text
);
CREATE INDEX refresh_tokens_user_idx ON iam.refresh_tokens (user_id) WHERE revoked_at IS NULL;
CREATE INDEX refresh_tokens_family_idx ON iam.refresh_tokens (family_id);

CREATE TABLE iam.api_keys (
    api_key_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name           text NOT NULL,
    key_prefix     varchar(12) NOT NULL UNIQUE,                  -- shown to users, e.g. "eeap_k1a2b3"
    key_hash       bytea NOT NULL,                               -- SHA-256 of full key
    owner_user_id  uuid NOT NULL REFERENCES iam.users(user_id),
    permissions    text[] NOT NULL,                              -- subset of owner's permissions
    expires_at     timestamptz NOT NULL,
    last_used_at   timestamptz,
    revoked_at     timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE iam.agent_enrollment_tokens (
    token_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash   bytea NOT NULL UNIQUE,
    platform     text NOT NULL CHECK (platform IN ('windows', 'linux', 'any')),
    labels       jsonb NOT NULL DEFAULT '{}'::jsonb,             -- applied to enrolled agents (site, environment)
    max_uses     integer NOT NULL DEFAULT 1 CHECK (max_uses BETWEEN 1 AND 10000),
    use_count    integer NOT NULL DEFAULT 0,
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    created_by   uuid NOT NULL REFERENCES iam.users(user_id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT enrollment_uses_within_limit CHECK (use_count <= max_uses)
);

CREATE TABLE iam.agents (
    agent_id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id           varchar(64),                              -- logical ref to asset.assets (no cross-schema FK)
    hostname           text NOT NULL,
    platform           text NOT NULL CHECK (platform IN ('windows', 'linux')),
    os_version         text,
    agent_version      text NOT NULL,
    capabilities       text[] NOT NULL DEFAULT '{}',             -- collector IDs the agent supports
    labels             jsonb NOT NULL DEFAULT '{}'::jsonb,
    status             text NOT NULL DEFAULT 'active'
                       CHECK (status IN ('active', 'stale', 'suspended', 'revoked')),
    cert_serial        text NOT NULL UNIQUE,
    cert_thumbprint    char(64) NOT NULL UNIQUE,                 -- SHA-256 hex of DER cert
    cert_expires_at    timestamptz NOT NULL,
    enrolled_via       uuid REFERENCES iam.agent_enrollment_tokens(token_id),
    enrolled_at        timestamptz NOT NULL DEFAULT now(),
    last_heartbeat_at  timestamptz,
    last_ip            inet,
    revoked_at         timestamptz,
    revoked_reason     text,
    updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agents_status_idx ON iam.agents (status, last_heartbeat_at);
CREATE INDEX agents_asset_idx  ON iam.agents (asset_id);

SELECT public.eeap_attach_updated_at_triggers('iam');

-- ---------------------------------------------------------------- audit
CREATE TABLE audit.audit_log (
    audit_id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_time     timestamptz NOT NULL DEFAULT now(),
    actor_type     text NOT NULL CHECK (actor_type IN ('user', 'agent', 'api_key', 'service', 'system', 'anonymous')),
    actor_id       text,
    actor_name     text,
    action         text NOT NULL,                                -- e.g. "auth.login", "asset.update", "report.download"
    resource_type  text,
    resource_id    text,
    outcome        text NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    source_ip      inet,
    user_agent     text,
    request_id     text,
    details        jsonb NOT NULL DEFAULT '{}'::jsonb,           -- never contains secrets or tokens
    prev_hash      bytea,
    entry_hash     bytea NOT NULL                                -- SHA-256(prev_hash || canonical(entry))
);
CREATE INDEX audit_log_time_idx     ON audit.audit_log (event_time DESC);
CREATE INDEX audit_log_actor_idx    ON audit.audit_log (actor_type, actor_id, event_time DESC);
CREATE INDEX audit_log_resource_idx ON audit.audit_log (resource_type, resource_id, event_time DESC);

CREATE OR REPLACE FUNCTION audit.reject_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit.audit_log is append-only';
END;
$$;

CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit.audit_log
    FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit.audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_mutation();
