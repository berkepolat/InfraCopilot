-- Transactional outbox (reliable publish) and inbox (idempotent consume) per service schema.
-- A relay in each service moves committed outbox rows to Redis Streams (see ADR-0005).
\set ON_ERROR_STOP on

DO $$
DECLARE s text;
BEGIN
  FOREACH s IN ARRAY ARRAY['iam', 'asset', 'assessment', 'graph', 'ai', 'reporting'] LOOP
    EXECUTE format($f$
      CREATE TABLE %1$I.event_outbox (
          event_id        uuid PRIMARY KEY,
          stream          text NOT NULL,
          event_type      text NOT NULL,
          schema_version  smallint NOT NULL DEFAULT 1,
          envelope        jsonb NOT NULL,
          created_at      timestamptz NOT NULL DEFAULT now(),
          published_at    timestamptz,
          attempts        integer NOT NULL DEFAULT 0,
          last_error      text
      );
      CREATE INDEX event_outbox_unpublished_idx ON %1$I.event_outbox (created_at) WHERE published_at IS NULL;

      CREATE TABLE %1$I.event_inbox (
          consumer_group  text NOT NULL,
          event_id        uuid NOT NULL,
          processed_at    timestamptz NOT NULL DEFAULT now(),
          PRIMARY KEY (consumer_group, event_id)
      );
    $f$, s);
  END LOOP;
END;
$$;
