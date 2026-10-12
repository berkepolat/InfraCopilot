#!/bin/bash
# Provisions the lab domain on first start, seeds test objects, then runs Samba in the foreground.
set -euo pipefail

REALM="${LAB_REALM:-LAB.EEAP.LOCAL}"
DOMAIN="${LAB_DOMAIN:-LAB}"
FQDN="$(hostname -s).${REALM,,}"
STATE=/var/lib/samba
TLS_DIR="$STATE/private/eeap-tls"
CONF="$STATE/etc/smb.conf"

read_secret() { tr -d '\r\n' < "/run/secrets/$1"; }

make_tls() {
  mkdir -p "$TLS_DIR"
  [[ -f "$TLS_DIR/cert.pem" ]] && return
  openssl req -x509 -newkey rsa:3072 -nodes -days 825 -subj "/O=EEAP Lab/CN=EEAP Lab CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$TLS_DIR/ca-key.pem" -out "$TLS_DIR/ca.pem" 2>/dev/null
  openssl req -newkey rsa:3072 -nodes -subj "/O=EEAP Lab/CN=$FQDN" \
    -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/server.csr" 2>/dev/null
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\n' \
    "$FQDN" > "$TLS_DIR/ext.cnf"
  openssl x509 -req -in "$TLS_DIR/server.csr" -CA "$TLS_DIR/ca.pem" -CAkey "$TLS_DIR/ca-key.pem" \
    -CAcreateserial -days 397 -extfile "$TLS_DIR/ext.cnf" -out "$TLS_DIR/cert.pem" 2>/dev/null
  chmod 600 "$TLS_DIR/key.pem" "$TLS_DIR/ca-key.pem"
}

if [[ ! -f "$STATE/private/sam.ldb" ]]; then
  echo "[lab] provisioning $REALM ($DOMAIN) as $FQDN"
  make_tls
  rm -f "$CONF"
  samba-tool domain provision \
    --realm="$REALM" --domain="$DOMAIN" --server-role=dc --dns-backend=SAMBA_INTERNAL \
    --adminpass="$(read_secret lab_ad_admin_password)" --use-rfc2307 \
    --targetdir="$STATE" \
    --option="vfs objects = dfs_samba4 acl_xattr xattr_tdb" \
    --option="tls enabled = yes" \
    --option="tls keyfile = $TLS_DIR/key.pem" \
    --option="tls certfile = $TLS_DIR/cert.pem" \
    --option="tls cafile = $TLS_DIR/ca.pem" \
    --option="dns forwarder = 127.0.0.11"
fi
ln -sf "$CONF" /etc/samba/smb.conf

if [[ ! -f "$STATE/.eeap-seeded" ]]; then
  /usr/local/bin/seed.sh "$REALM"
  touch "$STATE/.eeap-seeded"
  echo "[lab] provisioning complete"
fi

# Publish the lab CA so the EEAP collector can verify the LDAPS certificate.
if [[ -d /export ]]; then
  cp "$TLS_DIR/ca.pem" /export/ca.pem
  chmod 0644 /export/ca.pem
fi

exec samba --foreground --no-process-group --debug-stdout
