-- Assessment Service schema: control catalog, runs, jobs, evidence, findings, imports.
\set ON_ERROR_STOP on

CREATE TABLE assessment.controls (
    control_id          varchar(32) PRIMARY KEY CHECK (control_id ~ '^[A-Z]{2,8}-[0-9]{3,4}$'),
    name                text NOT NULL,
    module              text NOT NULL CHECK (module IN ('AD', 'WIN', 'NET', 'LINUX', 'CLOUD', 'IMPORT')),
    category            text NOT NULL,
    description         text,
    default_severity    text NOT NULL CHECK (default_severity IN ('Critical', 'High', 'Medium', 'Low', 'Informational')),
    exploitability      numeric(3,2) NOT NULL DEFAULT 0.50 CHECK (exploitability BETWEEN 0 AND 1),
    privilege_impact    numeric(3,2) NOT NULL DEFAULT 0.50 CHECK (privilege_impact BETWEEN 0 AND 1),
    execution_site      text NOT NULL CHECK (execution_site IN ('server', 'agent:windows', 'agent:linux', 'import')),
    collector_id        text,                                    -- built-in, allow-listed collector identifier
    recommendation      text,
    reference_links     jsonb NOT NULL DEFAULT '[]'::jsonb,      -- CIS / vendor guidance links
    mitre_techniques    text[] NOT NULL DEFAULT '{}',
    version             integer NOT NULL DEFAULT 1,
    enabled             boolean NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE assessment.assessment_profiles (
    profile_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL UNIQUE,
    description     text,
    control_ids     text[] NOT NULL,
    scope           jsonb NOT NULL DEFAULT '{}'::jsonb,          -- asset filter: environments, tags, asset_ids, domains
    schedule_cron   text,                                        -- NULL = manual only
    enabled         boolean NOT NULL DEFAULT true,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE assessment.assessment_runs (
    run_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id     uuid REFERENCES assessment.assessment_profiles(profile_id) ON DELETE SET NULL,
    trigger        text NOT NULL CHECK (trigger IN ('manual', 'schedule', 'api', 'import')),
    scope          jsonb NOT NULL DEFAULT '{}'::jsonb,
    control_ids    text[] NOT NULL DEFAULT '{}',
    full_scope     boolean NOT NULL DEFAULT true,                -- only full-scope runs may auto-resolve findings
    status         text NOT NULL DEFAULT 'queued' CHECK (status IN (
                       'queued', 'running', 'completed', 'partially_completed', 'failed', 'cancelled')),
    requested_by   text,
    stats          jsonb NOT NULL DEFAULT '{}'::jsonb,           -- job counts, finding counts by severity
    created_at     timestamptz NOT NULL DEFAULT now(),
    started_at     timestamptz,
    completed_at   timestamptz,
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX assessment_runs_status_idx ON assessment.assessment_runs (status, created_at DESC);

CREATE TABLE assessment.assessment_jobs (
    job_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          uuid NOT NULL REFERENCES assessment.assessment_runs(run_id) ON DELETE CASCADE,
    asset_id        varchar(64),
    agent_id        uuid,                                        -- set for agent execution sites
    collector_id    text NOT NULL,
    execution_site  text NOT NULL CHECK (execution_site IN ('server', 'agent:windows', 'agent:linux', 'import')),
    params          jsonb NOT NULL DEFAULT '{}'::jsonb,          -- declarative parameters only; never commands
    status          text NOT NULL DEFAULT 'pending' CHECK (status IN (
                        'pending', 'dispatched', 'running', 'succeeded', 'failed', 'expired', 'cancelled')),
    attempt         integer NOT NULL DEFAULT 0,
    max_attempts    integer NOT NULL DEFAULT 3,
    error           text,
    dispatched_at   timestamptz,
    started_at      timestamptz,
    completed_at    timestamptz,
    expires_at      timestamptz NOT NULL DEFAULT now() + interval '24 hours',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX assessment_jobs_run_idx   ON assessment.assessment_jobs (run_id, status);
CREATE INDEX assessment_jobs_agent_idx ON assessment.assessment_jobs (agent_id, status) WHERE status IN ('pending', 'dispatched');

CREATE TABLE assessment.evidence_objects (
    evidence_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id           uuid REFERENCES assessment.assessment_runs(run_id) ON DELETE SET NULL,
    job_id           uuid REFERENCES assessment.assessment_jobs(job_id) ON DELETE SET NULL,
    asset_id         varchar(64),
    bucket           text NOT NULL,
    object_key       text NOT NULL,
    sha256           char(64) NOT NULL,
    size_bytes       bigint NOT NULL CHECK (size_bytes >= 0),
    content_type     text NOT NULL DEFAULT 'application/json',
    collected_at     timestamptz NOT NULL,
    retention_until  timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (bucket, object_key)
);

-- Standard Finding Format, plus lifecycle and provenance columns.
CREATE TABLE assessment.findings (
    finding_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint         char(64) NOT NULL UNIQUE,                -- sha256(asset_id|control_id|subject_key)
    asset_id            varchar(64) NOT NULL,
    control_id          varchar(32) NOT NULL REFERENCES assessment.controls(control_id),
    control_name        text NOT NULL,
    category            text NOT NULL,
    severity            text NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Informational')),
    status              text NOT NULL CHECK (status IN ('PASS', 'FAIL', 'WARNING', 'INFO')),
    lifecycle_state     text NOT NULL DEFAULT 'open' CHECK (lifecycle_state IN (
                            'open', 'acknowledged', 'in_remediation', 'resolved', 'risk_accepted', 'false_positive')),
    subject_key         text NOT NULL DEFAULT '',                -- e.g. account DN for per-object findings
    evidence            jsonb NOT NULL DEFAULT '{}'::jsonb,      -- summarized, human-readable evidence
    recommendation      text,
    raw_data            jsonb NOT NULL DEFAULT '{}'::jsonb,      -- small payloads only (<= 64 KiB)
    raw_data_ref        uuid REFERENCES assessment.evidence_objects(evidence_id) ON DELETE SET NULL,
    source              text NOT NULL CHECK (source IN ('server', 'agent', 'import')),
    source_tool         text,                                    -- e.g. "eeap-windows-agent/1.0", "nessus"
    first_seen_run_id   uuid,
    last_seen_run_id    uuid,
    first_seen_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz NOT NULL DEFAULT now(),
    resolved_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT findings_raw_data_size CHECK (pg_column_size(raw_data) <= 65536)
);
CREATE INDEX findings_asset_idx    ON assessment.findings (asset_id, status);
CREATE INDEX findings_control_idx  ON assessment.findings (control_id, status);
CREATE INDEX findings_triage_idx   ON assessment.findings (status, severity, lifecycle_state, last_seen_at DESC);
CREATE INDEX findings_lastrun_idx  ON assessment.findings (last_seen_run_id);
CREATE INDEX findings_evidence_idx ON assessment.findings USING gin (evidence jsonb_path_ops);

CREATE TABLE assessment.finding_history (
    history_id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    finding_id       uuid NOT NULL REFERENCES assessment.findings(finding_id) ON DELETE CASCADE,
    run_id           uuid,
    status           text NOT NULL,
    severity         text NOT NULL,
    lifecycle_state  text NOT NULL,
    changed_by       text,                                       -- "system" or user id
    note             text,
    changed_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX finding_history_finding_idx ON assessment.finding_history (finding_id, changed_at DESC);

CREATE TABLE assessment.risk_acceptances (
    acceptance_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id      uuid NOT NULL REFERENCES assessment.findings(finding_id) ON DELETE CASCADE,
    justification   text NOT NULL,
    approved_by     text NOT NULL,
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE assessment.integrations (
    integration_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_type text NOT NULL CHECK (integration_type IN (
                        'nessus', 'qualys', 'tenable', 'openvas', 'bloodhound', 'sharphound',
                        'pingcastle', 'purple_knight', 'defender', 'wiz', 'nmap_xml')),
    name            text NOT NULL UNIQUE,
    mode            text NOT NULL CHECK (mode IN ('file_import', 'api_pull')),
    config          jsonb NOT NULL DEFAULT '{}'::jsonb,          -- non-secret settings only
    secret_ref      text,                                        -- name of secret in the secret store
    enabled         boolean NOT NULL DEFAULT false,
    last_sync_at    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE assessment.imports (
    import_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id  uuid REFERENCES assessment.integrations(integration_id) ON DELETE SET NULL,
    source_type     text NOT NULL,
    bucket          text NOT NULL DEFAULT 'eeap-imports',
    object_key      text NOT NULL,
    sha256          char(64) NOT NULL,
    status          text NOT NULL DEFAULT 'uploaded' CHECK (status IN ('uploaded', 'parsing', 'completed', 'failed')),
    run_id          uuid REFERENCES assessment.assessment_runs(run_id) ON DELETE SET NULL,
    stats           jsonb NOT NULL DEFAULT '{}'::jsonb,
    error           text,
    created_by      text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz
);

SELECT public.eeap_attach_updated_at_triggers('assessment');
