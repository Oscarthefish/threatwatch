#!/usr/bin/env bash
# Copy the server's nightly backups to this Mac. Run by launchd daily (deploy/nz.thefish.threatwatch-backup-pull.plist).
# Usage: deploy/pull-backups.sh [ssh-host]   (default tw-vps; connects as the non-root deploy user)
# Keeps the newest TW_PULL_KEEP (default 30) server backups in TW_PULL_DIR, checks each new file, and shows a
# macOS notification if the pull fails.
set -uo pipefail
HOST="${1:-tw-vps}"
DEST="${TW_PULL_DIR:-$HOME/Backups/threatwatch/server}"
KEEP="${TW_PULL_KEEP:-30}"
umask 077
mkdir -p "$DEST"

fail() {
  echo "$(date '+%F %T') FAILED: $1" >&2
  osascript -e "display notification \"$1\" with title \"Threat Watch backup copy failed\"" >/dev/null 2>&1 || true
  exit 1
}

before=$(ls "$DEST"/tw-*.db.gz 2>/dev/null | wc -l | tr -d ' ')
# --ignore-existing: backups never change once written; only new ones are fetched
rsync -a --ignore-existing --include='tw-*.db.gz' --exclude='*' \
  -e "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=20" \
  "$HOST:/var/backups/threatwatch/" "$DEST/" 2>&1 || fail "could not reach $HOST (is the Mac online and the SSH key in the keychain?)"

# Check every copy we hold is a complete gzip file; move damaged ones aside
bad=0
for f in "$DEST"/tw-*.db.gz; do
  [ -e "$f" ] || continue
  gzip -t "$f" 2>/dev/null || { mv "$f" "$f.damaged"; bad=$((bad + 1)); }
done
[ "$bad" -eq 0 ] || fail "$bad copied backup(s) were damaged and set aside in $DEST"

ls -1t "$DEST"/tw-*.db.gz 2>/dev/null | tail -n +"$((KEEP + 1))" | while read -r old; do rm -f "$old"; done
after=$(ls "$DEST"/tw-*.db.gz 2>/dev/null | wc -l | tr -d ' ')
newest=$(ls -1t "$DEST"/tw-*.db.gz 2>/dev/null | head -1)
[ -n "$newest" ] || fail "no backups found on $HOST"
echo "$(date '+%F %T') ok: $after backups in $DEST (was $before), newest $(basename "$newest")"
