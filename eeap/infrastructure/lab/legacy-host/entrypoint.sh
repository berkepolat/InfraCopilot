#!/bin/sh
set -eu

/usr/sbin/sshd -e
/usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf &
/usr/sbin/smbd --foreground --no-process-group &
exec busybox-extras telnetd -F -p 23 -l /bin/false
