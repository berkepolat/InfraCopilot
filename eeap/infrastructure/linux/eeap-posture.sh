#!/bin/sh
# EEAP Linux security posture (read-only), schema eeap.linux.posture/1.
#
# Installed root-owned as /usr/local/libexec/eeap/eeap-posture by install-eeap-posture.sh and run only
# through the scanner key's forced command (sudo -n, no arguments). It reads configuration and prints
# one record per line: "<section>\t<key>\t<value>". It never prints password hashes, keys or file
# contents beyond the listed settings, and it changes nothing (package managers run in simulation /
# cache-only mode).
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL

rec() { printf '%s\t%s\t%s\n' "$1" "$2" "$(printf '%s' "$3" | tr '\t\r\n' '   ' | cut -c1-400)"; }
have() { command -v "$1" >/dev/null 2>&1; }
osr() { sed -n "s/^$1=//p" /etc/os-release 2>/dev/null | head -n1 | tr -d '"'; }
age_days() { [ -n "$1" ] && [ -e "$1" ] && echo $(( ($(date +%s) - $(stat -c %Y "$1")) / 86400 )); }

rec schema version eeap.linux.posture/1

# ---------------------------------------------------------------- host
rec host hostname "$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname)"
fqdn=$(hostname -f 2>/dev/null) && rec host fqdn "$fqdn"
rec host os_id "$(osr ID)"
rec host os_id_like "$(osr ID_LIKE)"
rec host os_version_id "$(osr VERSION_ID)"
rec host os_pretty "$(osr PRETTY_NAME)"
rec host kernel "$(uname -r)"
rec host arch "$(uname -m)"

# ---------------------------------------------------------------- sshd effective configuration
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
if [ -x "$SSHD" ] && sshd_out=$("$SSHD" -T 2>/dev/null); then
  rec sshd available 1
  printf '%s\n' "$sshd_out" | while read -r key value; do
    case "$key" in
      permitrootlogin|passwordauthentication|permitemptypasswords|kbdinteractiveauthentication|\
      challengeresponseauthentication|pubkeyauthentication|x11forwarding|maxauthtries|ciphers|macs|\
      kexalgorithms|allowtcpforwarding|logingracetime|usepam|port)
        rec sshd "$key" "$value" ;;
    esac
  done
else
  rec sshd available 0
fi

# ---------------------------------------------------------------- pending updates (no network, no changes)
if have apt-get; then
  rec updates manager apt
  if sim=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null); then
    rec updates pending "$(printf '%s\n' "$sim" | grep -c '^Inst ')"
    rec updates security "$(printf '%s\n' "$sim" | grep '^Inst ' | grep -ci 'securi')"
  fi
  rec updates metadata_age_days "$(age_days "$(ls -t /var/lib/apt/lists/*_Packages 2>/dev/null | head -n1)")"
  [ -f /var/run/reboot-required ] && rec updates reboot_required 1 || rec updates reboot_required 0
elif have dnf || have yum; then
  pm=$(command -v dnf || command -v yum)
  rec updates manager "$(basename "$pm")"
  meta=$(ls -td /var/cache/dnf/*/repodata /var/cache/yum/*/*/repodata 2>/dev/null | head -n1)
  rec updates metadata_age_days "$(age_days "$meta")"
  if [ -n "$meta" ]; then
    rec updates pending "$("$pm" -q -C check-update 2>/dev/null | grep -c '^[[:alnum:]]')"
    rec updates security "$("$pm" -q -C updateinfo list --security 2>/dev/null | grep -c .)"
  fi
  if have needs-restarting; then
    needs-restarting -r >/dev/null 2>&1
    [ $? -eq 1 ] && rec updates reboot_required 1 || rec updates reboot_required 0
  fi
elif have apk; then
  rec updates manager apk
  index=$(ls -t /var/cache/apk/APKINDEX.* /lib/apk/db/APKINDEX.* 2>/dev/null | head -n1)
  rec updates metadata_age_days "$(age_days "$index")"
  [ -n "$index" ] && rec updates pending "$(apk version -l '<' 2>/dev/null | grep -vc '^Installed')"
fi

# ---------------------------------------------------------------- accounts
awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | while read -r u; do rec accounts uid0 "$u"; done
if [ -r /etc/shadow ]; then
  rec accounts shadow_readable 1
  awk -F: '$2 == "" {print $1}' /etc/shadow | while read -r u; do rec accounts empty_password "$u"; done
fi
pmd=$(awk '$1 == "PASS_MAX_DAYS" {print $2}' /etc/login.defs 2>/dev/null | tail -n1)
[ -n "$pmd" ] && rec accounts pass_max_days "$pmd"

# ---------------------------------------------------------------- sudo
for g in sudo wheel admin; do
  awk -F: -v g="$g" '$1 == g {print $4}' /etc/group | tr ',' '\n' | while read -r u; do
    [ -n "$u" ] && rec sudo group_member "$g:$u"
  done
done
for f in /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$f" ] && [ "$f" != /etc/sudoers.d/eeap-posture ] || continue
  grep -v '^[[:space:]]*#' "$f" 2>/dev/null | grep -E 'NOPASSWD|!authenticate' | while IFS= read -r line; do
    rec sudo nopasswd "$line"
  done
done

# ---------------------------------------------------------------- host firewall
if have nft && ruleset=$(nft list ruleset 2>/dev/null); then
  printf '%s\n' "$ruleset" | awk '
    /^[[:space:]]*chain / {inchain = 1; input = 0; next}
    inchain && /hook input/ {input = 1; chains++; if (match($0, /policy [a-z]+/)) pol = substr($0, RSTART + 7, RLENGTH - 7); next}
    inchain && /^[[:space:]]*}/ {inchain = 0; input = 0; next}
    input && NF {rules++}
    END {printf "%d %d %s\n", chains, rules, pol}' | {
      read -r chains rules policy
      rec firewall nft_input_chains "$chains"
      rec firewall nft_input_rules "$rules"
      rec firewall nft_input_policy "${policy:-}"
    }
fi
if have iptables && ipt=$(iptables -S INPUT 2>/dev/null); then
  rec firewall iptables_input_policy "$(printf '%s\n' "$ipt" | sed -n 's/^-P INPUT //p')"
  rec firewall iptables_input_rules "$(printf '%s\n' "$ipt" | grep -c '^-A INPUT')"
fi
have ufw && rec firewall ufw "$(ufw status 2>/dev/null | sed -n 's/^Status: //p')"
have firewall-cmd && rec firewall firewalld "$(firewall-cmd --state 2>/dev/null || echo 'not running')"

# ---------------------------------------------------------------- kernel settings
for k in kernel.randomize_va_space net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects \
         net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.rp_filter \
         net.ipv4.tcp_syncookies net.ipv6.conf.all.accept_redirects kernel.kptr_restrict kernel.dmesg_restrict \
         fs.suid_dumpable fs.protected_symlinks fs.protected_hardlinks kernel.yama.ptrace_scope; do
  p=/proc/sys/$(printf '%s' "$k" | tr . /)
  [ -r "$p" ] && rec sysctl "$k" "$(cat "$p")"
done

# ---------------------------------------------------------------- sensitive file permissions
for f in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/ssh/sshd_config /etc/sudoers; do
  [ -e "$f" ] && rec files mode "$f $(stat -c '%a %U %G' "$f")"
done
find /etc -xdev -type f -perm -0002 2>/dev/null | head -n 50 | while IFS= read -r f; do rec files world_writable "$f"; done

rec schema complete 1
