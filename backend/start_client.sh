#!/usr/bin/env bash
set -euo pipefail

# --------------------------------------------
# Usage:
#   ./start_client.sh [USER_ID] [SERVER_HOST] [SERVER_PORT]
# Defaults:
#   USER_ID=random  SERVER_HOST=127.0.0.1  SERVER_PORT=8080
# Behavior mirrors Windows .bat: host/port are passed via env vars.
# --------------------------------------------

USER_ID="${1:-}"
SERVER_HOST="${2:-${SERVER_HOST:-127.0.0.1}}"
SERVER_PORT="${3:-${SERVER_PORT:-8080}}"

export SERVER_HOST SERVER_PORT

echo "Connecting client to wss://$SERVER_HOST:$SERVER_PORT/ws"

if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "Python interpreter not found (python3/python)" >&2
  exit 1
fi

if [[ -z "$USER_ID" ]]; then
  exec "$PY" client.py
else
  exec "$PY" client.py "$USER_ID"
fi
