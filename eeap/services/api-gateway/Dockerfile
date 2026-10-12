# syntax=docker/dockerfile:1.7
# Build context: repository root (eeap/).
FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY shared/ ./shared/
COPY services/api-gateway/requirements.txt ./requirements.txt
RUN pip install --prefix=/install ./shared -r requirements.txt

FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="eeap-api-gateway" org.opencontainers.image.source="eeap"
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 EEAP_ROLE=api
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin eeap
COPY --from=builder /install /usr/local
WORKDIR /app
COPY services/api-gateway/app ./app
COPY services/api-gateway/migrations ./migrations
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2).status == 200 else 1)"]
CMD ["python", "-m", "app.entrypoint"]
