#!/usr/bin/env bash
# Restore a backup ON THE SERVER. DESTRUCTIVE: replaces the live database. Usage: restore.sh /var/backups/threatwatch/tw-XXXX.db.gz
set -euo pipefail
SRC="${1:?usage: restore.sh <backup.db.gz>}"
REMOTE_DIR="${TW_REMOTE_DIR:-/opt/threatwatch}"
read -r -p "This replaces the live Threat Watch database with $SRC. Type 'restore' to continue: " ok
[[ "$ok" == "restore" ]] || { echo aborted; exit 1; }
cd "$REMOTE_DIR"
TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
gunzip -c "$SRC" > "$TMP"
sqlite3 "$TMP" "PRAGMA integrity_check;" 2>/dev/null | grep -qx ok || { command -v sqlite3 >/dev/null && { echo "integrity check failed" >&2; exit 1; }; }
docker compose stop worker web
docker compose run --rm --no-deps -v "$TMP:/restore.db:ro" --entrypoint sh web -c \
  "cp /restore.db /data/threatwatch.db && rm -f /data/threatwatch.db-wal /data/threatwatch.db-shm && chmod 600 /data/threatwatch.db"
docker compose up -d
echo "restored from $SRC"
