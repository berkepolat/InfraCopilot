# Lab target with legacy remote access services and Linux misconfigurations for NET-006 / NET-007,
# WIN-001 / WIN-002 and LIN-001 … LIN-008 demonstrations. Build context: ./infrastructure.
#
# Only the EEAP scanner key can log in, and only to the forced read-only posture command (installed at
# start from /run/secrets/linux_ssh_key_pub). The weak settings below cannot be used to log in: root and
# legacy-admin have no usable password, legacy-svc / toor have no shell, empty passwords are not
# permitted by sshd, telnetd runs /bin/false, vsftpd has no logins and Samba has no shares or users.
FROM alpine:3.20

RUN apk add --no-cache openssh-server vsftpd busybox-extras samba sudo \
    && ssh-keygen -A \
    && mkdir -p /var/run/vsftpd/empty \
    && printf '%s\n' "PermitRootLogin yes" "PasswordAuthentication yes" "KbdInteractiveAuthentication no" \
         "MaxAuthTries 10" "Ciphers aes128-ctr,aes256-ctr,aes128-cbc" >> /etc/ssh/sshd_config \
    && printf '%s\n' "listen=YES" "anonymous_enable=NO" "local_enable=NO" "write_enable=NO" \
         "secure_chroot_dir=/var/run/vsftpd/empty" "ftpd_banner=220 (vsFTPd 3.0.5)" > /etc/vsftpd/vsftpd.conf \
    && printf '%s\n' "[global]" "server role = standalone server" "server min protocol = NT1" \
         "server signing = disabled" "map to guest = never" "restrict anonymous = 2" "disable netbios = yes" \
         "smb ports = 445" "load printers = no" "log file = /dev/stdout" > /etc/samba/smb.conf \
    && adduser -D -s /sbin/nologin legacy-svc && passwd -d legacy-svc \
    && adduser -D -s /bin/sh legacy-admin && addgroup legacy-admin wheel \
    && echo 'toor:x:0:0:legacy root alias:/root:/sbin/nologin' >> /etc/passwd \
    && echo 'toor:*:19000:0:99999:7:::' >> /etc/shadow \
    && echo '%wheel ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/legacy && chmod 0440 /etc/sudoers.d/legacy \
    && echo 'legacy=1' > /etc/legacy-app.conf && chmod 0666 /etc/legacy-app.conf

COPY linux/ /opt/eeap-linux/
COPY lab/legacy-host/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh /opt/eeap-linux/*.sh && chmod 0755 /entrypoint.sh /opt/eeap-linux/*.sh

EXPOSE 21 22 23 445
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD nc -z 127.0.0.1 22 && nc -z 127.0.0.1 445
ENTRYPOINT ["/entrypoint.sh"]
