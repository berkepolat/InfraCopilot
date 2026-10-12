# Lab target with legacy remote access services for NET-006 / NET-007 demonstrations.
# No account can log in: sshd allows keys only (none installed), telnetd runs /bin/false,
# vsftpd has anonymous and local logins disabled.
FROM alpine:3.20

RUN apk add --no-cache openssh-server vsftpd busybox-extras \
    && ssh-keygen -A \
    && mkdir -p /var/run/vsftpd/empty \
    && printf '%s\n' "PasswordAuthentication no" "KbdInteractiveAuthentication no" "PermitRootLogin no" \
         "AuthorizedKeysFile none" >> /etc/ssh/sshd_config \
    && printf '%s\n' "listen=YES" "anonymous_enable=NO" "local_enable=NO" "write_enable=NO" \
         "secure_chroot_dir=/var/run/vsftpd/empty" "ftpd_banner=220 (vsFTPd 3.0.5)" > /etc/vsftpd/vsftpd.conf

COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod 0755 /entrypoint.sh

EXPOSE 21 22 23
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD nc -z 127.0.0.1 22 && nc -z 127.0.0.1 21
ENTRYPOINT ["/entrypoint.sh"]
