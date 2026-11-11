#!/usr/bin/env bash
# Run Threat Watch on this machine with Docker Compose (always-on while Docker Desktop runs).
#
#   deploy/local.sh up         build image and start (http://localhost:8787)
#   deploy/local.sh password   set/replace the login password (interactive)
#   deploy/local.sh status     container health, resource use, source health
#   deploy/local.sh logs       follow logs
#   deploy/local.sh ingest     trigger a collection run now
#   deploy/local.sh backup     consistent backup to ~/Backups/threatwatch (mode 600)
#   deploy/local.sh down       stop (data is kept in the Docker volume)
#
# Secrets/config: ~/.config/threatwatch/threatwatch.env (created on first run, mode 600, outside git).
set -euo pipefail
cd "$(dirname "$0")/.."

export COMPOSE_PROJECT_NAME=threatwatch
export TW_ENV_FILE="${TW_ENV_FILE:-$HOME/.config/threatwatch/threatwatch.env}"
export TW_PORT="${TW_PORT:-8787}"
export TW_IMAGE="${TW_IMAGE:-threatwatch:local}"
BACKUP_DIR="${TW_BACKUP_DIR:-$HOME/Backups/threatwatch}"

ensure_env() {
  if [[ ! -f "$TW_ENV_FILE" ]]; then
    mkdir -p "$(dirname "$TW_ENV_FILE")" && chmod 700 "$(dirname "$TW_ENV_FILE")"
    ( umask 077
      sed -e 's/^TW_COOKIE_SECURE=true/TW_COOKIE_SECURE=false/' \
          -e 's/^TW_TRUSTED_HOSTS=\*/TW_TRUSTED_HOSTS=localhost,127.0.0.1/' \
          deploy/threatwatch.example.env > "$TW_ENV_FILE" )
    echo "Created $TW_ENV_FILE (edit it to add ANTHROPIC_API_KEY if wanted)."
  fi
}

case "${1:-}" in
  up)
    ensure_env
    docker build -t "$TW_IMAGE" .
    docker compose up -d --remove-orphans
    echo "Waiting for health…"
    for _ in $(seq 1 40); do
      if curl -fsS "http://127.0.0.1:$TW_PORT/api/health" >/dev/null 2>&1; then
        docker compose ps; echo "Threat Watch: http://localhost:$TW_PORT"; exit 0
      fi
      sleep 3
    done
    echo "Health check failed — see: deploy/local.sh logs" >&2; exit 1 ;;
  password)
    docker compose exec web python -m app.cli set-password "${2:-analyst}" ;;
  status)
    docker compose ps
    docker stats --no-stream --format "table {{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}" $(docker compose ps -q)
    docker compose exec -T web python -m app.cli sources ;;
  logs)
    docker compose logs -f --tail=100 ;;
  ingest)
    docker compose exec -T worker python -m app.cli ingest --force ;;
  backup)
    STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
    ( umask 077; mkdir -p "$BACKUP_DIR" )
    docker compose exec -T worker python -m app.cli backup "/data/backups/tw-$STAMP.db"
    docker compose cp "worker:/data/backups/tw-$STAMP.db" "$BACKUP_DIR/tw-$STAMP.db"
    docker compose exec -T worker rm -f "/data/backups/tw-$STAMP.db"
    gzip -9 "$BACKUP_DIR/tw-$STAMP.db" && chmod 600 "$BACKUP_DIR/tw-$STAMP.db.gz"
    ls -1t "$BACKUP_DIR"/tw-*.db.gz | tail -n +15 | xargs -r rm -f
    echo "Backup: $BACKUP_DIR/tw-$STAMP.db.gz" ;;
  down)
    docker compose down ;;
  *)
    sed -n '2,13p' "$0"; exit 1 ;;
esac
