#!/usr/bin/env bash
# Roll back to the previously deployed image tag.
set -euo pipefail
HOST="${1:?usage: rollback.sh <ssh-host>}"
REMOTE_DIR="${TW_REMOTE_DIR:-/opt/threatwatch}"
ssh -o BatchMode=yes "$HOST" "cd $REMOTE_DIR && test -s .env.prev && sed 's/^TW_PREVIOUS_IMAGE=/TW_IMAGE=/' .env.prev > .env && cat .env && docker compose up -d && docker compose ps"
