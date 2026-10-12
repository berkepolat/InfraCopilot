#!/bin/sh
set -eu

/usr/sbin/sshd -e
/usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf &
exec busybox-extras telnetd -F -p 23 -l /bin/false
