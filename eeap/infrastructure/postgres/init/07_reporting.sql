-- Reporting Service schema: templates, report requests, artifacts, schedules.
\set ON_ERROR_STOP on

CREATE TABLE reporting.report_templates (
    template_id   text NOT NULL,
    version       integer NOT NULL DEFAULT 1,
    report_type   text NOT NULL CHECK (report_type IN (
                      'executive_summary', 'technical', 'security_posture',
                      'mitre_mapping', 'risk_dashboard', 'remediation_roadmap')),
    name          text NOT NULL,
    formats       text[] NOT NULL CHECK (formats <@ ARRAY['json', 'html', 'pdf']),
    definition    jsonb NOT NULL DEFAULT '{}'::jsonb,            -- sections, data queries, template file names
    enabled       boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (template_id, version)
);

CREATE TABLE reporting.reports (
    report_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id       text NOT NULL,
    template_version  integer NOT NULL,
    report_type       text NOT NULL,
    title             text NOT NULL,
    formats           text[] NOT NULL CHECK (formats <@ ARRAY['json', 'html', 'pdf']),
    parameters        jsonb NOT NULL DEFAULT '{}'::jsonb,        -- scope filters, audience, period
    snapshot_at       timestamptz NOT NULL DEFAULT now(),        -- data cut-off for reproducibility
    status            text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'rendering', 'completed', 'failed', 'expired')),
    requested_by      text NOT NULL,
    error             text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    completed_at      timestamptz,
    expires_at        timestamptz,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (template_id, template_version) REFERENCES reporting.report_templates(template_id, version)
);
CREATE INDEX reports_status_idx ON reporting.reports (status, created_at DESC);

CREATE TABLE reporting.report_artifacts (
    artifact_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id    uuid NOT NULL REFERENCES reporting.reports(report_id) ON DELETE CASCADE,
    format       text NOT NULL CHECK (format IN ('json', 'html', 'pdf')),
    bucket       text NOT NULL DEFAULT 'eeap-reports',
    object_key   text NOT NULL,
    sha256       char(64) NOT NULL,
    size_bytes   bigint NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (report_id, format)
);

CREATE TABLE reporting.report_schedules (
    schedule_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id       text NOT NULL,
    template_version  integer NOT NULL,
    cron              text NOT NULL,
    parameters        jsonb NOT NULL DEFAULT '{}'::jsonb,
    formats           text[] NOT NULL,
    enabled           boolean NOT NULL DEFAULT true,
    created_by        text NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (template_id, template_version) REFERENCES reporting.report_templates(template_id, version)
);

SELECT public.eeap_attach_updated_at_triggers('reporting');
