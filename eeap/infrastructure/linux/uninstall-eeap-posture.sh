#!/bin/sh
# Removes the EEAP posture command, its sudo rule and the eeap-scan account (run as root).
set -eu

SCAN_USER=${EEAP_SCAN_USER:-eeap-scan}
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

rm -f /etc/sudoers.d/eeap-posture
rm -rf /usr/local/libexec/eeap
if id "$SCAN_USER" >/dev/null 2>&1; then
  if command -v userdel >/dev/null 2>&1; then userdel -r "$SCAN_USER"; else deluser --remove-home "$SCAN_USER"; fi
fi
echo "Removed the EEAP posture command and $SCAN_USER."
