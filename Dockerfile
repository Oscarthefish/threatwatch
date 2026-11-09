# syntax=docker/dockerfile:1.7
# ---------- frontend build ----------
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---------- python deps ----------
FROM python:3.13-slim AS deps
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY backend/requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv && /opt/venv/bin/pip install -r /tmp/requirements.txt

# ---------- runtime ----------
FROM python:3.13-slim
LABEL org.opencontainers.image.title="threatwatch" org.opencontainers.image.description="Personal cybersecurity intelligence platform"
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    TW_DATA_DIR=/data TW_STATIC_DIR=/app/static MALLOC_ARENA_MAX=2
RUN groupadd --system --gid 10001 tw && useradd --system --uid 10001 --gid tw --home /nonexistent --shell /usr/sbin/nologin tw \
 && mkdir -p /data && chown tw:tw /data && chmod 700 /data
COPY --from=deps /opt/venv /opt/venv
WORKDIR /app
COPY backend/app ./app
COPY backend/migrations ./migrations
COPY --from=web /web/dist ./static
USER tw:tw
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=4).status==200 else 1)"
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1,172.16.0.0/12", "--no-server-header"]
