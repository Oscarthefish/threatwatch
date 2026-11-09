#!/usr/bin/env bash
# Consistent online SQLite backup. Run ON THE SERVER (systemd timer: threatwatch-backup.timer).
# Keeps TW_BACKUP_KEEP (default 14) compressed copies in TW_BACKUP_DIR (default /var/backups/threatwatch), mode 600.
set -euo pipefail
REMOTE_DIR="${TW_REMOTE_DIR:-/opt/threatwatch}"
DEST="${TW_BACKUP_DIR:-/var/backups/threatwatch}"
KEEP="${TW_BACKUP_KEEP:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
umask 077
mkdir -p "$DEST"
cd "$REMOTE_DIR"
docker compose exec -T worker sh -c "mkdir -p /data/backups && python -m app.cli backup /data/backups/tw-$STAMP.db"
docker compose cp "worker:/data/backups/tw-$STAMP.db" "$DEST/tw-$STAMP.db"
docker compose exec -T worker rm -f "/data/backups/tw-$STAMP.db"
gzip -9 "$DEST/tw-$STAMP.db"
chmod 600 "$DEST/tw-$STAMP.db.gz"
ls -1t "$DEST"/tw-*.db.gz | tail -n +"$((KEEP + 1))" | xargs -r rm -f
echo "backup: $DEST/tw-$STAMP.db.gz ($(du -h "$DEST/tw-$STAMP.db.gz" | cut -f1))"
