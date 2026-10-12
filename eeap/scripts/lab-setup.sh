#!/usr/bin/env bash
# Prepares secrets for the Samba AD test lab (docker-compose.lab.yml). Development only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/secrets"
[[ -d "$DIR" ]] || "$ROOT/scripts/generate-secrets.sh"

# Mixed character classes satisfy AD complexity rules if they are enabled later.
labpw() { echo "Eeap-$(openssl rand -base64 30 | tr -d '\n/+=' | cut -c1-28)9a"; }

for name in lab_ad_admin_password ad_bind_password; do
  if [[ -s "$DIR/$name" ]]; then
    echo "keep     $name"
  else
    labpw | tr -d '\n' > "$DIR/$name"
    chmod 644 "$DIR/$name"
    echo "created  $name"
  fi
done

if [[ -s "$DIR/linux_ssh_key" && -s "$DIR/linux_ssh_key.pub" ]]; then
  echo "keep     linux_ssh_key"
else
  rm -f "$DIR/linux_ssh_key" "$DIR/linux_ssh_key.pub"
  ssh-keygen -q -t ed25519 -N "" -C "eeap-scanner" -f "$DIR/linux_ssh_key"
  chmod 644 "$DIR/linux_ssh_key" "$DIR/linux_ssh_key.pub"
  echo "created  linux_ssh_key / linux_ssh_key.pub"
fi

echo "Lab secrets ready. Start with:"
echo "  docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile app up -d --build"
