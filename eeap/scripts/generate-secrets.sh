#!/usr/bin/env bash
# Generates development / PoC secrets into ./secrets. Production deployments should source
# these from an enterprise secret store instead (see docs/adr/0013-secrets-management.md).
#
# Usage: ./scripts/generate-secrets.sh [--force] [hostname]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/secrets"
FORCE=false
HOSTNAME_ARG="eeap.local"

for arg in "$@"; do
  case "$arg" in
    --force) FORCE=true ;;
    *)       HOSTNAME_ARG="$arg" ;;
  esac
done

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

mkdir -p "$DIR"
# The directory protects the files on the host. Files are 0644 because Compose bind-mounts
# file secrets with host permissions and containers run as non-root users.
chmod 700 "$DIR"

write_secret() {
  local name="$1" value="$2"
  if [[ -f "$DIR/$name" && "$FORCE" != true ]]; then
    echo "keep     $name"
    return
  fi
  printf '%s' "$value" > "$DIR/$name"
  chmod 644 "$DIR/$name"
  echo "created  $name"
}

rand() { openssl rand -base64 48 | tr -d '\n/+=' | cut -c1-"${1:-40}"; }

write_secret postgres_superuser_password "$(rand)"
for svc in gateway asset assessment relationship ai reporting; do
  write_secret "db_password_$svc" "$(rand)"
done
write_secret redis_password          "$(rand)"
write_secret minio_root_user         "eeap-root-$(rand 8)"
write_secret minio_root_password     "$(rand)"
for svc in assessment ai reporting backup; do
  write_secret "minio_secret_$svc" "$(rand)"
done
write_secret grafana_admin_password  "$(rand 24)"
[[ -f "$DIR/llm_api_key" ]] || write_secret llm_api_key ""
# Password of the read-only AD assessment account; empty until an AD target is configured.
[[ -f "$DIR/ad_bind_password" ]] || write_secret ad_bind_password ""

gen_keypair() {
  local priv="$1" pub="$2"; shift 2
  if [[ -f "$DIR/$priv" && "$FORCE" != true ]]; then
    echo "keep     $priv"
    return
  fi
  openssl genpkey "$@" -out "$DIR/$priv" 2>/dev/null
  openssl pkey -in "$DIR/$priv" -pubout -out "$DIR/$pub"
  chmod 644 "$DIR/$priv" "$DIR/$pub"
  echo "created  $priv / $pub"
}

# User / agent JWTs (RS256).
gen_keypair jwt_signing_key.pem jwt_public_key.pem -algorithm RSA -pkeyopt rsa_keygen_bits:3072
# Internal service tokens (EdDSA): only the gateway can sign, services can only verify.
gen_keypair internal_token_private_key.pem internal_token_public_key.pem -algorithm ED25519

# Agent CA (development only; use an HSM/KMS-backed intermediate in production).
if [[ ! -f "$DIR/agent_ca_cert.pem" || "$FORCE" == true ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1825 \
    -subj "/O=EEAP/CN=EEAP Agent CA (development)" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$DIR/agent_ca_key.pem" -out "$DIR/agent_ca_cert.pem" 2>/dev/null
  chmod 644 "$DIR/agent_ca_key.pem" "$DIR/agent_ca_cert.pem"
  echo "created  agent_ca_key.pem / agent_ca_cert.pem"
else
  echo "keep     agent_ca_cert.pem"
fi

# Edge TLS certificate (self-signed, development only).
if [[ ! -f "$DIR/tls_cert.pem" || "$FORCE" == true ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 397 \
    -subj "/O=EEAP/CN=$HOSTNAME_ARG" \
    -addext "subjectAltName=DNS:$HOSTNAME_ARG,DNS:localhost,IP:127.0.0.1" \
    -addext "extendedKeyUsage=serverAuth" \
    -keyout "$DIR/tls_key.pem" -out "$DIR/tls_cert.pem" 2>/dev/null
  chmod 644 "$DIR/tls_key.pem" "$DIR/tls_cert.pem"
  echo "created  tls_cert.pem / tls_key.pem ($HOSTNAME_ARG)"
else
  echo "keep     tls_cert.pem"
fi

echo "Secrets ready in $DIR"
