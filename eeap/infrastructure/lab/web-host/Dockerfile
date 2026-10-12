# Lab web target for NET-010..NET-012 with deliberate weaknesses. Development and demonstration only.
#   :80   directory listing, downloadable .git/HEAD, nginx status page, version in the Server header
#   :8080 login form over cleartext HTTP
#   :443  self-signed certificate that expires within 30 days, security headers set
FROM nginx:1.27-alpine

RUN apk add --no-cache openssl \
 && mkdir -p /etc/nginx/tls /srv/files/.git /srv/login /srv/secure \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 20 -subj "/CN=web1.lab.eeap.local" \
      -keyout /etc/nginx/tls/key.pem -out /etc/nginx/tls/cert.pem \
 && printf 'ref: refs/heads/main\n' > /srv/files/.git/HEAD \
 && printf 'quarterly report\n' > /srv/files/report-2026q3.txt \
 && printf 'backup notes\n' > /srv/files/backup-notes.txt \
 && printf '<!doctype html><html><head><title>Intranet login</title></head><body><form method="post" action="/login">\n<input type="text" name="user"><input type="password" name="password"><button>Sign in</button></form></body></html>\n' > /srv/login/index.html \
 && printf '<!doctype html><html><head><title>Secure portal</title></head><body>ok</body></html>\n' > /srv/secure/index.html

COPY lab/web-host/default.conf /etc/nginx/conf.d/default.conf
