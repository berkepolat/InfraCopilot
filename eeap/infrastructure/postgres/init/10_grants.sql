-- Ownership and least-privilege grants. Runs last so it covers every object created above.
\set ON_ERROR_STOP on

GRANT CONNECT ON DATABASE eeap TO eeap_gateway, eeap_asset, eeap_assessment,
                                  eeap_relationship, eeap_ai, eeap_reporting;
GRANT USAGE ON SCHEMA public TO eeap_gateway, eeap_asset, eeap_assessment,
                                eeap_relationship, eeap_ai, eeap_reporting;

-- Each service owns the objects in its schema so its Alembic migrations can evolve them.
DO $$
DECLARE
  m record;
  r record;
BEGIN
  FOR m IN SELECT * FROM (VALUES
      ('iam',        'eeap_gateway'),
      ('asset',      'eeap_asset'),
      ('assessment', 'eeap_assessment'),
      ('graph',      'eeap_relationship'),
      ('ai',         'eeap_ai'),
      ('reporting',  'eeap_reporting')) AS t(schema_name, role_name)
  LOOP
    -- Identity sequences follow their table's owner automatically.
    FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = m.schema_name LOOP
      EXECUTE format('ALTER TABLE %I.%I OWNER TO %I', m.schema_name, r.tablename, m.role_name);
    END LOOP;
  END LOOP;
END;
$$;

-- Audit: the gateway may append and read, never modify. Table stays owned by eeap_audit_owner.
ALTER TABLE audit.audit_log OWNER TO eeap_audit_owner;
GRANT USAGE ON SCHEMA audit TO eeap_gateway;
GRANT SELECT, INSERT ON audit.audit_log TO eeap_gateway;
