-- EEAP common objects: extensions, schemas, shared trigger functions.
\set ON_ERROR_STOP on

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE SCHEMA iam          AUTHORIZATION eeap_gateway;
CREATE SCHEMA audit        AUTHORIZATION eeap_audit_owner;
CREATE SCHEMA asset        AUTHORIZATION eeap_asset;
CREATE SCHEMA assessment   AUTHORIZATION eeap_assessment;
CREATE SCHEMA graph        AUTHORIZATION eeap_relationship;
CREATE SCHEMA ai           AUTHORIZATION eeap_ai;
CREATE SCHEMA reporting    AUTHORIZATION eeap_reporting;

ALTER ROLE eeap_gateway      SET search_path = iam, audit, public;
ALTER ROLE eeap_asset        SET search_path = asset, public;
ALTER ROLE eeap_assessment   SET search_path = assessment, public;
ALTER ROLE eeap_relationship SET search_path = graph, public;
ALTER ROLE eeap_ai           SET search_path = ai, public;
ALTER ROLE eeap_reporting    SET search_path = reporting, public;

CREATE OR REPLACE FUNCTION public.eeap_set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

-- Attaches the updated_at trigger to every table in a schema that has an updated_at column.
CREATE OR REPLACE FUNCTION public.eeap_attach_updated_at_triggers(p_schema text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT c.table_name
    FROM information_schema.columns c
    JOIN information_schema.tables t
      ON t.table_schema = c.table_schema AND t.table_name = c.table_name
    WHERE c.table_schema = p_schema
      AND c.column_name = 'updated_at'
      AND t.table_type = 'BASE TABLE'
  LOOP
    EXECUTE format(
      'CREATE TRIGGER trg_%s_updated_at BEFORE UPDATE ON %I.%I FOR EACH ROW EXECUTE FUNCTION public.eeap_set_updated_at()',
      r.table_name, p_schema, r.table_name);
  END LOOP;
END;
$$;
