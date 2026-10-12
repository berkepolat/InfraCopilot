#!/bin/bash
# Seeds the lab domain with objects that exercise each AD control (AD-001..AD-010).
# The "weaknesses" are configuration states only (flags, group memberships, attributes) so the
# read-only collector has something to report. No account here is meant to be used to sign in.
set -euo pipefail

REALM="$1"
BASE="DC=${REALM,,}"; BASE="${BASE//./,DC=}"
SAM=/var/lib/samba/private/sam.ldb
ST=(samba-tool)

randpw() { echo "Lab!$(openssl rand -base64 24 | tr -d '/+=\n')"; }
ldif() { ldbmodify -H "$SAM" >/dev/null; }

echo "[seed] AD-001 weak domain password policy"
"${ST[@]}" domain passwordsettings set --complexity=off --min-pwd-length=7 --history-length=5 \
  --account-lockout-threshold=0 --max-pwd-age=0 >/dev/null

echo "[seed] read-only collector account (svc-eeap-reader)"
"${ST[@]}" user create svc-eeap-reader "$(tr -d '\r\n' < /run/secrets/ad_bind_password)" \
  --description="EEAP read-only assessment account (lab)" >/dev/null
"${ST[@]}" user setexpiry svc-eeap-reader --noexpiry >/dev/null

echo "[seed] regular users and administrators"
for u in alice bob carol dave erin frank helpdesk1; do
  "${ST[@]}" user create "$u" "$(randpw)" >/dev/null
done
"${ST[@]}" group addmembers "Domain Admins" alice,bob,carol,dave,erin,frank >/dev/null   # AD-007: > 5 members
"${ST[@]}" group addmembers "Account Operators" helpdesk1 >/dev/null                    # AD-007: operator group in use
"${ST[@]}" user disable frank >/dev/null                                                 # AD-007: disabled admin

echo "[seed] AD-002 service accounts with SPNs"
"${ST[@]}" user create svc_sql "$(randpw)" --description="SQL Server service" >/dev/null
"${ST[@]}" spn add "MSSQLSvc/sql01.${REALM,,}:1433" svc_sql >/dev/null
"${ST[@]}" group addmembers "Domain Admins" svc_sql >/dev/null                         # privileged service account
"${ST[@]}" user create svc_backup "$(randpw)" --description="Backup service" >/dev/null
"${ST[@]}" spn add "HOST/backup01.${REALM,,}" svc_backup >/dev/null
"${ST[@]}" user setexpiry svc_backup --noexpiry >/dev/null
"${ST[@]}" user create svc_web "$(randpw)" --description="Web application pool" >/dev/null
"${ST[@]}" spn add "HTTP/intranet.${REALM,,}" svc_web >/dev/null

echo "[seed] AD-003 account without Kerberos pre-authentication"
"${ST[@]}" user create legacy_app "$(randpw)" >/dev/null
ldif <<EOF
dn: CN=legacy_app,CN=Users,$BASE
changetype: modify
replace: userAccountControl
userAccountControl: $((0x200 | 0x400000))
EOF

echo "[seed] AD-005 constrained delegation with protocol transition (svc_web -> DC CIFS)"
ldif <<EOF
dn: CN=svc_web,CN=Users,$BASE
changetype: modify
replace: msDS-AllowedToDelegateTo
msDS-AllowedToDelegateTo: cifs/dc1.${REALM,,}
-
replace: userAccountControl
userAccountControl: $((0x200 | 0x1000000))
EOF

echo "[seed] computers: AD-004 unconstrained delegation, AD-009 legacy OS, AD-008 no LAPS"
for c in APP01 FS01 WS-1002 SRV-LEGACY; do
  "${ST[@]}" computer create "$c" >/dev/null
done
computer_attrs() {
  ldif <<EOF
dn: CN=$1,CN=Computers,$BASE
changetype: modify
replace: userAccountControl
userAccountControl: $((0x1000))
-
replace: dNSHostName
dNSHostName: ${1,,}.${REALM,,}
-
replace: operatingSystem
operatingSystem: $2
-
replace: operatingSystemVersion
operatingSystemVersion: $3
EOF
}
computer_attrs APP01 "Windows Server 2019 Standard" "10.0 (17763)"
computer_attrs FS01 "Windows Server 2022 Standard" "10.0 (20348)"
computer_attrs WS-1002 "Windows 11 Enterprise" "10.0 (22631)"
computer_attrs SRV-LEGACY "Windows Server 2008 R2 Standard" "6.1 (7601)"
ldif <<EOF
dn: CN=APP01,CN=Computers,$BASE
changetype: modify
replace: userAccountControl
userAccountControl: $((0x1000 | 0x80000))
EOF

echo "[seed] done"
