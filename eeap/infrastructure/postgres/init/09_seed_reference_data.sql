-- Reference data required by every deployment. No sample/tenant data here.
\set ON_ERROR_STOP on

-- ---------------------------------------------------------------- RBAC
INSERT INTO iam.permissions (permission_id, description) VALUES
  ('assets:read',            'View assets and ownership'),
  ('assets:write',           'Create and update assets, owners, classification rules'),
  ('assets:delete',          'Retire or delete assets'),
  ('findings:read',          'View findings and evidence summaries'),
  ('findings:triage',        'Change finding lifecycle state'),
  ('findings:accept_risk',   'Approve risk acceptances'),
  ('evidence:read',          'Download raw evidence objects'),
  ('assessments:read',       'View assessment runs, jobs and profiles'),
  ('assessments:run',        'Start and cancel assessment runs'),
  ('assessments:manage',     'Manage assessment profiles and schedules'),
  ('controls:read',          'View the control catalog'),
  ('controls:manage',        'Enable, disable and tune controls'),
  ('graph:read',             'View relationship graphs and concentration areas'),
  ('risk:read',              'View risk scores, scenarios, MITRE mapping and remediation'),
  ('risk:manage',            'Manage correlation rules and remediation status'),
  ('reports:read',           'View and download reports'),
  ('reports:create',         'Request and schedule reports'),
  ('agents:read',            'View agents'),
  ('agents:manage',          'Create enrollment tokens, suspend and revoke agents'),
  ('integrations:manage',    'Configure third-party integrations'),
  ('imports:create',         'Upload third-party result files'),
  ('users:read',             'View users and role assignments'),
  ('users:manage',           'Manage users, roles and API keys'),
  ('audit:read',             'View the audit log'),
  ('settings:manage',        'Manage platform settings'),
  ('agent:self',             'Agent principal: heartbeat, pull jobs, submit results');

INSERT INTO iam.roles (role_id, description) VALUES
  ('admin',              'Platform administrator'),
  ('security_analyst',   'Runs assessments, triages findings, produces reports'),
  ('auditor',            'Read-only access including audit log and evidence'),
  ('executive',          'Dashboards, risk scores and executive reports'),
  ('asset_owner',        'Scoped access to owned assets and their findings'),
  ('integration_client', 'Machine client for imports and read APIs (API key)'),
  ('agent',              'Enrolled Windows / Linux agent');

INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT 'admin', permission_id FROM iam.permissions WHERE permission_id <> 'agent:self';

INSERT INTO iam.role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM (VALUES
  ('security_analyst', ARRAY['assets:read','assets:write','findings:read','findings:triage','evidence:read',
                             'assessments:read','assessments:run','assessments:manage','controls:read',
                             'graph:read','risk:read','risk:manage','reports:read','reports:create',
                             'agents:read','imports:create']),
  ('auditor',          ARRAY['assets:read','findings:read','evidence:read','assessments:read','controls:read',
                             'graph:read','risk:read','reports:read','agents:read','users:read','audit:read']),
  ('executive',        ARRAY['assets:read','risk:read','reports:read','reports:create']),
  ('asset_owner',      ARRAY['assets:read','findings:read','findings:triage','risk:read','reports:read']),
  ('integration_client', ARRAY['assets:read','findings:read','imports:create','risk:read']),
  ('agent',            ARRAY['agent:self'])
) AS r(role_id, perms)
CROSS JOIN LATERAL unnest(r.perms) AS p(permission_id);

-- ---------------------------------------------------------------- asset classification
INSERT INTO asset.classification_rules (name, priority, condition, set_values) VALUES
  ('Domain controllers are Tier 0', 10, '{"asset_type": "DomainController"}', '{"tier": "Tier0", "criticality": "Critical"}'),
  ('Tier 0 role tags',              20, '{"tags_any": ["role:adfs", "role:pki", "role:exchange"]}', '{"tier": "Tier0", "criticality": "Critical"}'),
  ('Production databases',          50, '{"asset_type": "Database", "environment": "Production"}', '{"criticality": "High"}');

-- ---------------------------------------------------------------- control catalog (metadata only)
-- Evaluators are implemented in Phase 2; all controls ship disabled.
INSERT INTO assessment.controls
  (control_id, name, module, category, default_severity, exploitability, privilege_impact, execution_site, collector_id)
VALUES
  ('AD-001',  'Password Policy Assessment',                  'AD',  'Identity Hygiene',          'Medium',   0.50, 0.40, 'server',        'ad.domain_policy'),
  ('AD-002',  'Service Account Exposure Assessment',         'AD',  'Credential Exposure',       'High',     0.70, 0.80, 'server',        'ad.service_accounts'),
  ('AD-003',  'Authentication Pre-Validation Assessment',    'AD',  'Authentication Hardening',  'High',     0.70, 0.60, 'server',        'ad.preauth_flags'),
  ('AD-004',  'Delegation Configuration Assessment',         'AD',  'Delegation',                'High',     0.60, 0.80, 'server',        'ad.delegation'),
  ('AD-005',  'Constrained Delegation Assessment',           'AD',  'Delegation',                'Medium',   0.50, 0.70, 'server',        'ad.constrained_delegation'),
  ('AD-006',  'Resource-Based Delegation Assessment',        'AD',  'Delegation',                'Medium',   0.50, 0.70, 'server',        'ad.rbcd'),
  ('AD-007',  'Privileged Group Assessment',                 'AD',  'Privileged Access',         'High',     0.50, 1.00, 'server',        'ad.privileged_groups'),
  ('AD-008',  'LAPS Assessment',                             'AD',  'Local Credential Management','Medium',  0.60, 0.60, 'server',        'ad.laps'),
  ('AD-009',  'Legacy Operating System Discovery',           'AD',  'Lifecycle Management',      'High',     0.70, 0.50, 'server',        'ad.computer_os'),
  ('AD-010',  'Tier-0 Asset Discovery',                      'AD',  'Asset Classification',      'Informational', 0.00, 1.00, 'server', 'ad.tier0_discovery'),
  ('WIN-001', 'SMB Signing',                                 'WIN', 'Protocol Hardening',        'High',     0.60, 0.60, 'agent:windows', 'win.smb_config'),
  ('WIN-002', 'SMBv1 Assessment',                            'WIN', 'Protocol Hardening',        'High',     0.70, 0.50, 'agent:windows', 'win.smb_config'),
  ('WIN-003', 'NTLM Hardening',                              'WIN', 'Authentication Hardening',  'High',     0.60, 0.60, 'agent:windows', 'win.lsa_config'),
  ('WIN-004', 'LDAP Signing',                                'WIN', 'Protocol Hardening',        'High',     0.60, 0.70, 'agent:windows', 'win.ldap_server_config'),
  ('WIN-005', 'LDAP Channel Binding',                        'WIN', 'Protocol Hardening',        'Medium',   0.50, 0.70, 'agent:windows', 'win.ldap_server_config'),
  ('WIN-006', 'RDP Network Level Authentication',            'WIN', 'Remote Access',             'Medium',   0.50, 0.40, 'agent:windows', 'win.rdp_config'),
  ('WIN-007', 'Local Administrators Review',                 'WIN', 'Privileged Access',         'Medium',   0.50, 0.70, 'agent:windows', 'win.local_admins'),
  ('WIN-008', 'WinRM Exposure',                              'WIN', 'Remote Access',             'Medium',   0.50, 0.50, 'agent:windows', 'win.winrm_config'),
  ('WIN-009', 'Security Agent Discovery',                    'WIN', 'Endpoint Protection',       'Medium',   0.40, 0.30, 'agent:windows', 'win.security_products'),
  ('NET-001', 'DNS Zone Transfer Assessment',                'NET', 'Information Exposure',      'Medium',   0.60, 0.20, 'server',        'net.dns_axfr_policy'),
  ('NET-002', 'TLS Security Assessment',                     'NET', 'Transport Security',        'Medium',   0.40, 0.30, 'server',        'net.tls_config'),
  ('NET-003', 'SMB Access Assessment',                       'NET', 'Network Exposure',          'Medium',   0.50, 0.40, 'server',        'net.smb_exposure'),
  ('NET-004', 'SNMP Assessment',                             'NET', 'Network Exposure',          'Medium',   0.50, 0.40, 'server',        'net.snmp_config'),
  ('NET-005', 'NTP Security Assessment',                     'NET', 'Infrastructure Services',   'Low',      0.30, 0.20, 'server',        'net.ntp_config');

-- ---------------------------------------------------------------- scoring model v1 (see docs/architecture/08-risk-scoring-model.md)
INSERT INTO ai.scoring_models (model_version, description, weights, is_active) VALUES
  ('v1', 'Weighted linear exposure model with status gating',
   '{
      "factor_weights": {"severity": 0.30, "asset_criticality": 0.20, "exploitability": 0.15,
                         "exposure_breadth": 0.10, "privilege_impact": 0.15, "propagation": 0.10},
      "severity_values": {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25, "Informational": 0.0},
      "criticality_values": {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25},
      "status_multipliers": {"FAIL": 1.0, "WARNING": 0.6, "INFO": 0.0, "PASS": 0.0},
      "lifecycle_multipliers": {"open": 1.0, "acknowledged": 1.0, "in_remediation": 0.9,
                                "risk_accepted": 0.0, "false_positive": 0.0, "resolved": 0.0},
      "breadth_reference_count": 100,
      "severity_floor": {"Critical": 70},
      "bands": {"Critical": 90, "High": 70, "Medium": 40, "Low": 0}
    }'::jsonb,
   true);

-- ---------------------------------------------------------------- reference correlation rule
INSERT INTO ai.correlation_rules (rule_id, name, definition) VALUES
  ('CORR-AUTH-001', 'Authentication hardening gap leading to privileged resource exposure',
   '{
      "match": "all_stages",
      "scope": "domain",
      "stages": [
        {"order": 1, "name": "Authentication Hardening Gap",
         "any_failed_controls": ["WIN-001", "WIN-003", "WIN-004", "WIN-005"]},
        {"order": 2, "name": "Service Account Risk",
         "any_failed_controls": ["AD-002", "AD-003"]},
        {"order": 3, "name": "Privileged Resource Exposure",
         "any_failed_controls": ["AD-007"],
         "graph_condition": {"tier0_reachable_from_stage": 2, "max_hops": 4}},
        {"order": 4, "name": "Increased Organizational Risk", "derived": true}
      ],
      "scenario_title": "Authentication hardening gaps amplify service account and privileged access exposure"
    }'::jsonb);

-- ---------------------------------------------------------------- report templates
INSERT INTO reporting.report_templates (template_id, version, report_type, name, formats) VALUES
  ('executive_summary',   1, 'executive_summary',   'Executive Summary',            ARRAY['json','html','pdf']),
  ('technical',           1, 'technical',           'Technical Findings Report',    ARRAY['json','html','pdf']),
  ('security_posture',    1, 'security_posture',    'Security Posture Report',      ARRAY['json','html','pdf']),
  ('mitre_mapping',       1, 'mitre_mapping',       'MITRE ATT&CK Mapping',         ARRAY['json','html','pdf']),
  ('risk_dashboard',      1, 'risk_dashboard',      'Risk Dashboard Export',        ARRAY['json','html']),
  ('remediation_roadmap', 1, 'remediation_roadmap', 'Remediation Roadmap',          ARRAY['json','html','pdf']);
