#!/bin/sh
# Installs the EEAP read-only posture command on a Linux host (run as root).
#
#   ./install-eeap-posture.sh "ssh-ed25519 AAAA... eeap-scanner" [scanner-address-list]
#
# Creates the account eeap-scan (no password) whose only SSH key is restricted to one forced command:
#   sudo -n /usr/local/libexec/eeap/eeap-posture
# sudo allows exactly that root-owned script without arguments. The key cannot open a shell, a PTY or
# any forwarding. The optional address list (OpenSSH from= pattern, e.g. "10.0.5.20") limits where the
# key is accepted from. Requires OpenSSH 7.2+ (restrict) and sudo.
set -eu

SCAN_USER=${EEAP_SCAN_USER:-eeap-scan}
LIBEXEC=/usr/local/libexec/eeap
COMMAND="$LIBEXEC/eeap-posture"
SUDOERS=/etc/sudoers.d/eeap-posture

die() { echo "install-eeap-posture: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
[ $# -ge 1 ] || die "usage: $0 \"<scanner public key>\" [from-pattern]"
PUBKEY=$1
FROM=${2:-}
case "$PUBKEY" in
  "ssh-ed25519 "*|"ecdsa-sha2-"*|"ssh-rsa "*) ;;
  *) die "expected one OpenSSH public key line" ;;
esac
case "$PUBKEY$FROM" in *'"'*|*"
"*) die "invalid characters in key or from pattern" ;; esac
command -v sudo >/dev/null 2>&1 || die "sudo is required"

mkdir -p "$LIBEXEC"
cp "$(dirname "$0")/eeap-posture.sh" "$COMMAND"
sed -i 's/\r$//' "$COMMAND"
chown -R root:root "$LIBEXEC"
chmod 0755 "$LIBEXEC" "$COMMAND"

if ! id "$SCAN_USER" >/dev/null 2>&1; then
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --create-home --shell /bin/sh --comment "EEAP posture scanner" "$SCAN_USER"
  else
    adduser -S -D -h "/home/$SCAN_USER" -s /bin/sh -g "EEAP posture scanner" "$SCAN_USER"
  fi
fi
# '*' disables password logins without marking the account locked (sshd refuses locked accounts).
if command -v usermod >/dev/null 2>&1; then
  usermod -p '*' "$SCAN_USER"
else
  sed -i "s/^$SCAN_USER:[^:]*:/$SCAN_USER:*:/" /etc/shadow
fi

HOME_DIR=$(awk -F: -v u="$SCAN_USER" '$1 == u {print $6}' /etc/passwd)
[ -n "$HOME_DIR" ] || die "no home directory for $SCAN_USER"
# Root-owned so the scanner account cannot change its own key options.
mkdir -p "$HOME_DIR/.ssh"
OPTIONS="restrict,command=\"sudo -n $COMMAND\""
[ -z "$FROM" ] || OPTIONS="from=\"$FROM\",$OPTIONS"
printf '%s %s\n' "$OPTIONS" "$PUBKEY" > "$HOME_DIR/.ssh/authorized_keys"
chown root:root "$HOME_DIR/.ssh" "$HOME_DIR/.ssh/authorized_keys"
chmod 0755 "$HOME_DIR/.ssh"
chmod 0644 "$HOME_DIR/.ssh/authorized_keys"

mkdir -p /etc/sudoers.d
printf '%s\n' "Defaults:$SCAN_USER !requiretty" "$SCAN_USER ALL=(root) NOPASSWD: $COMMAND \"\"" > "$SUDOERS.tmp"
chmod 0440 "$SUDOERS.tmp"
if command -v visudo >/dev/null 2>&1; then
  visudo -cf "$SUDOERS.tmp" >/dev/null || { rm -f "$SUDOERS.tmp"; die "sudoers validation failed"; }
fi
mv "$SUDOERS.tmp" "$SUDOERS"
grep -Eq '^[[:space:]]*[#@]includedir[[:space:]]+/etc/sudoers.d' /etc/sudoers \
  || echo "warning: /etc/sudoers does not include /etc/sudoers.d" >&2

echo "Installed $COMMAND for $SCAN_USER."
