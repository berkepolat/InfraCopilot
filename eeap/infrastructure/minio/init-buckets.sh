#!/bin/sh
# Idempotent MinIO bootstrap: buckets, versioning, lifecycle, per-service users and policies.
set -eu

S=/run/secrets
mc alias set eeap http://minio:9000 "$(cat $S/minio_root_user)" "$(cat $S/minio_root_password)" >/dev/null

create_bucket() {
  bucket="$1" days="$2"
  mc mb --ignore-existing "eeap/$bucket"
  mc version enable "eeap/$bucket"
  cat > "/tmp/$bucket-lifecycle.json" <<EOF
{"Rules":[{"ID":"eeap-retention","Status":"Enabled","Filter":{"Prefix":""},
  "Expiration":{"Days":$days},"NoncurrentVersionExpiration":{"NoncurrentDays":30}}]}
EOF
  mc ilm import "eeap/$bucket" < "/tmp/$bucket-lifecycle.json"
}

create_bucket eeap-evidence 365
create_bucket eeap-imports  180
create_bucket eeap-reports  180
create_bucket eeap-backups  30

# policy_name  user  secret_file  policy_file
create_service_user() {
  policy="$1" user="$2" secret_file="$3" policy_file="$4"
  mc admin policy create eeap "$policy" "$policy_file"
  mc admin user add eeap "$user" "$(cat "$secret_file")"
  mc admin policy attach eeap "$policy" --user "$user" 2>/dev/null || true
}

create_service_user eeap-assessment svc-assessment $S/minio_secret_assessment /init/policies/assessment.json
create_service_user eeap-ai         svc-ai         $S/minio_secret_ai         /init/policies/ai.json
create_service_user eeap-reporting  svc-reporting  $S/minio_secret_reporting  /init/policies/reporting.json
create_service_user eeap-backup     svc-backup     $S/minio_secret_backup     /init/policies/backup.json

echo "minio-init: buckets and service users ready"
