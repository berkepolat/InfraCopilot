# Lab target with legacy remote access services for NET-006 / NET-007 and WIN-001 / WIN-002 demonstrations.
# No account can log in: sshd allows keys only (none installed), telnetd runs /bin/false,
# vsftpd has anonymous and local logins disabled, Samba has no shares and no users.
FROM alpine:3.20

RUN apk add --no-cache openssh-server vsftpd busybox-extras samba \
    && ssh-keygen -A \
    && mkdir -p /var/run/vsftpd/empty \
    && printf '%s\n' "PasswordAuthentication no" "KbdInteractiveAuthentication no" "PermitRootLogin no" \
         "AuthorizedKeysFile none" >> /etc/ssh/sshd_config \
    && printf '%s\n' "listen=YES" "anonymous_enable=NO" "local_enable=NO" "write_enable=NO" \
         "secure_chroot_dir=/var/run/vsftpd/empty" "ftpd_banner=220 (vsFTPd 3.0.5)" > /etc/vsftpd/vsftpd.conf \
    && printf '%s\n' "[global]" "server role = standalone server" "server min protocol = NT1" \
         "server signing = disabled" "map to guest = never" "restrict anonymous = 2" "disable netbios = yes" \
         "smb ports = 445" "load printers = no" "log file = /dev/stdout" > /etc/samba/smb.conf

COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod 0755 /entrypoint.sh

EXPOSE 21 22 23 445
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD nc -z 127.0.0.1 22 && nc -z 127.0.0.1 445
ENTRYPOINT ["/entrypoint.sh"]
