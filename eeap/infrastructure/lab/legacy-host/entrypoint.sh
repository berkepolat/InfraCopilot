#!/bin/sh
set -eu

if [ -s /run/secrets/linux_ssh_key_pub ]; then
  /opt/eeap-linux/install-eeap-posture.sh "$(head -n1 /run/secrets/linux_ssh_key_pub)"
fi

/usr/sbin/sshd -e
/usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf &
/usr/sbin/smbd --foreground --no-process-group &
exec busybox-extras telnetd -F -p 23 -l /bin/false
