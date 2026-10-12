# Samba AD domain controller for the EEAP test lab only. Never deploy this image to production.
FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision samba-dsdb-modules samba-vfs-modules winbind ldb-tools openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* /etc/samba/smb.conf

COPY entrypoint.sh seed.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/seed.sh

EXPOSE 636
HEALTHCHECK --interval=10s --timeout=3s --retries=30 --start-period=60s \
  CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/636' || exit 1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
