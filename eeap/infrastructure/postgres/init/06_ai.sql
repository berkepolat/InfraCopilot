-- AI Engine schema: scoring, correlation scenarios, MITRE mapping, remediation, narratives.
\set ON_ERROR_STOP on

CREATE TABLE ai.scoring_models (
    model_version  text PRIMARY KEY,                             -- e.g. "v1"
    description    text NOT NULL,
    weights        jsonb NOT NULL,
    is_active      boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX scoring_models_single_active ON ai.scoring_models (is_active) WHERE is_active;

CREATE TABLE ai.risk_scores (
    score_id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subject_type   text NOT NULL CHECK (subject_type IN ('finding', 'asset', 'scenario', 'owner', 'organization')),
    subject_id     text NOT NULL,                                -- finding_id / asset_id / scenario_id / owner_id / "org"
    score          smallint NOT NULL CHECK (score BETWEEN 0 AND 100),
    rating         text NOT NULL CHECK (rating IN ('Critical', 'High', 'Medium', 'Low')),
    factors        jsonb NOT NULL,                               -- full factor breakdown for explainability
    model_version  text NOT NULL REFERENCES ai.scoring_models(model_version),
    is_current     boolean NOT NULL DEFAULT true,
    trigger_event  text,
    computed_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT risk_scores_rating_band CHECK (
        (rating = 'Critical' AND score >= 90) OR
        (rating = 'High'     AND score BETWEEN 70 AND 89) OR
        (rating = 'Medium'   AND score BETWEEN 40 AND 69) OR
        (rating = 'Low'      AND score <= 39))
);
CREATE UNIQUE INDEX risk_scores_current_uq ON ai.risk_scores (subject_type, subject_id) WHERE is_current;
CREATE INDEX risk_scores_history_idx       ON ai.risk_scores (subject_type, subject_id, computed_at DESC);
CREATE INDEX risk_scores_rank_idx          ON ai.risk_scores (subject_type, score DESC) WHERE is_current;

CREATE TABLE ai.correlation_rules (
    rule_id      text PRIMARY KEY,                               -- e.g. "CORR-AUTH-001"
    name         text NOT NULL,
    version      integer NOT NULL DEFAULT 1,
    definition   jsonb NOT NULL,                                 -- conditions over findings / graph facts + stage templates
    enabled      boolean NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ai.risk_scenarios (
    scenario_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id             text NOT NULL REFERENCES ai.correlation_rules(rule_id),
    scope_key           text NOT NULL,                           -- dedupe key (rule + affected scope)
    title               text NOT NULL,
    summary             text NOT NULL,
    stages              jsonb NOT NULL,                          -- ordered [{"order":1,"name":"Authentication Hardening Gap","finding_ids":[...]}]
    affected_asset_ids  text[] NOT NULL DEFAULT '{}',
    status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'mitigated', 'dismissed')),
    model_version       text NOT NULL REFERENCES ai.scoring_models(model_version),
    first_detected_at   timestamptz NOT NULL DEFAULT now(),
    last_evaluated_at   timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (rule_id, scope_key)
);
CREATE INDEX risk_scenarios_status_idx ON ai.risk_scenarios (status, last_evaluated_at DESC);

CREATE TABLE ai.scenario_findings (
    scenario_id  uuid NOT NULL REFERENCES ai.risk_scenarios(scenario_id) ON DELETE CASCADE,
    finding_id   uuid NOT NULL,                                  -- logical ref to assessment.findings
    stage_order  smallint NOT NULL,
    PRIMARY KEY (scenario_id, finding_id)
);
CREATE INDEX scenario_findings_finding_idx ON ai.scenario_findings (finding_id);

CREATE TABLE ai.mitre_techniques (
    technique_id  varchar(16) PRIMARY KEY CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
    name          text NOT NULL,
    tactics       text[] NOT NULL,
    attack_version text NOT NULL,                                -- ATT&CK release the entry was taken from
    url           text
);

CREATE TABLE ai.control_technique_map (
    control_id    varchar(32) NOT NULL,                          -- logical ref to assessment.controls
    technique_id  varchar(16) NOT NULL REFERENCES ai.mitre_techniques(technique_id),
    rationale     text NOT NULL,                                 -- why this weakness is relevant to the technique (defensive)
    PRIMARY KEY (control_id, technique_id)
);

CREATE TABLE ai.remediation_items (
    item_id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id               uuid,
    scenario_id              uuid REFERENCES ai.risk_scenarios(scenario_id) ON DELETE CASCADE,
    title                    text NOT NULL,
    guidance                 text NOT NULL,
    effort                   text NOT NULL CHECK (effort IN ('Low', 'Medium', 'High')),
    expected_risk_reduction  smallint NOT NULL CHECK (expected_risk_reduction BETWEEN 0 AND 100),
    priority                 integer NOT NULL,                   -- 1 = highest; roadmap order
    roadmap_phase            text CHECK (roadmap_phase IN ('Immediate', 'Short-term', 'Medium-term', 'Long-term')),
    generated_by             text NOT NULL CHECK (generated_by IN ('template', 'llm')),
    status                   text NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed', 'accepted', 'done', 'rejected')),
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT remediation_has_subject CHECK (finding_id IS NOT NULL OR scenario_id IS NOT NULL)
);
CREATE INDEX remediation_priority_idx ON ai.remediation_items (status, priority);

CREATE TABLE ai.narratives (
    narrative_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_type   text NOT NULL CHECK (subject_type IN ('finding', 'asset', 'scenario', 'organization', 'report')),
    subject_id     text NOT NULL,
    kind           text NOT NULL CHECK (kind IN ('summary', 'executive_summary', 'remediation', 'exposure_analysis')),
    content        text NOT NULL,
    generated_by   text NOT NULL CHECK (generated_by IN ('template', 'llm')),
    provider       text,
    model          text,
    prompt_hash    char(64),                                     -- SHA-256 of redacted prompt; prompts are not stored
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX narratives_subject_idx ON ai.narratives (subject_type, subject_id, kind, created_at DESC);

SELECT public.eeap_attach_updated_at_triggers('ai');
