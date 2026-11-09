#!/usr/bin/env bash
# Build locally, ship the image over SSH, and (re)start the stack on the server.
# Usage: deploy/deploy.sh <ssh-host>        e.g. deploy/deploy.sh tw-vps
# Requires: SSH key auth to a user in the server's docker group, host key already verified in known_hosts.
set -euo pipefail
HOST="${1:?usage: deploy.sh <ssh-host>}"
REMOTE_DIR="${TW_REMOTE_DIR:-/opt/threatwatch}"
SSH=(ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$HOST")
cd "$(dirname "$0")/.."

if [[ -n "$(git status --porcelain)" && "${TW_ALLOW_DIRTY:-0}" != "1" ]]; then
  echo "Refusing to deploy uncommitted changes (set TW_ALLOW_DIRTY=1 to override)." >&2; exit 1
fi
TAG="$(git rev-parse --short HEAD)"
case "$("${SSH[@]}" uname -m)" in
  x86_64) PLATFORM=linux/amd64 ;; aarch64|arm64) PLATFORM=linux/arm64 ;; *) echo "unsupported arch" >&2; exit 1 ;;
esac
echo "==> Building threatwatch:$TAG for $PLATFORM"
docker buildx build --platform "$PLATFORM" -t "threatwatch:$TAG" --load .

echo "==> Shipping image to $HOST"
docker save "threatwatch:$TAG" | gzip -1 | "${SSH[@]}" 'gunzip | docker load'

echo "==> Updating compose file and starting"
"${SSH[@]}" "test -f /etc/threatwatch/threatwatch.env || { echo 'missing /etc/threatwatch/threatwatch.env' >&2; exit 1; }"
scp -o BatchMode=yes -o StrictHostKeyChecking=yes -q docker-compose.yml "$HOST:$REMOTE_DIR/docker-compose.yml"
"${SSH[@]}" "cd $REMOTE_DIR && { grep -s '^TW_IMAGE=' .env | sed 's/^TW_IMAGE=/TW_PREVIOUS_IMAGE=/' > .env.prev || true; } \
  && printf 'TW_IMAGE=threatwatch:%s\n' '$TAG' > .env && docker compose up -d --remove-orphans"

echo "==> Waiting for health"
for i in $(seq 1 30); do
  if "${SSH[@]}" "curl -fsS http://127.0.0.1:\${TW_PORT:-8080}/api/health" >/dev/null 2>&1; then
    "${SSH[@]}" "cd $REMOTE_DIR && docker compose ps"
    echo "==> Deployed threatwatch:$TAG"; exit 0
  fi
  sleep 3
done
echo "Health check failed. Roll back with: deploy/rollback.sh $HOST" >&2
exit 1
