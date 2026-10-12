#!/usr/bin/env bash
# Creates one least-privilege login role per service. Passwords come from Docker secrets.
# Runs once, on first initialization of an empty data directory.
set -euo pipefail

SECRETS_DIR="${SECRETS_DIR:-/run/secrets}"

create_role() {
  local role="$1" secret_file="$2" password
  if [[ ! -r "$secret_file" ]]; then
    echo "missing secret file: $secret_file" >&2
    exit 1
  fi
  password="$(tr -d '\r\n' < "$secret_file")"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
       -v role="$role" -v pw="$password" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION CONNECTION LIMIT 50', :'role', :'pw') \gexec
SQL
}

create_role eeap_gateway      "$SECRETS_DIR/db_password_gateway"
create_role eeap_asset        "$SECRETS_DIR/db_password_asset"
create_role eeap_assessment   "$SECRETS_DIR/db_password_assessment"
create_role eeap_relationship "$SECRETS_DIR/db_password_relationship"
create_role eeap_ai           "$SECRETS_DIR/db_password_ai"
create_role eeap_reporting    "$SECRETS_DIR/db_password_reporting"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
-- Owns the append-only audit schema; nobody logs in as it.
CREATE ROLE eeap_audit_owner NOLOGIN;
REVOKE ALL ON DATABASE eeap FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
