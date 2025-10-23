#!/usr/bin/env bash
set -euo pipefail

# Group 59
# ----------------------------------
# Muhammad Tayyab Rashid - a1988298
# Nguyen Duc Tung Bui - a1976012
# Guilin Luo - a1989840
# Mazharul Islam Rakib - a1990942
# Masud Ahammad - a1993200

# --------------------------------------------
# Usage:
#   ./start_client.sh <PASSWORD> [USER_ID] [SERVER_HOST] [SERVER_PORT]
# Defaults:
#   USER_ID=random  SERVER_HOST=127.0.0.1  SERVER_PORT=8080
# Behavior mirrors Windows .bat: host/port are passed via env vars.
# --------------------------------------------

PASSWORD="${1:-}"
USER_ID="${2:-}"
SERVER_HOST="${3:-${SERVER_HOST:-127.0.0.1}}"
SERVER_PORT="${4:-${SERVER_PORT:-8080}}"

if [[ -z "$PASSWORD" ]]; then
  echo "Error: PASSWORD is required." >&2
  echo "Usage: $0 <PASSWORD> [USER_ID] [SERVER_HOST] [SERVER_PORT]" >&2
  echo "Example: $0 mysecretpassword" >&2
  exit 1
fi

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
  exec "$PY" client.py "$PASSWORD"
else
  exec "$PY" client.py "$PASSWORD" "$USER_ID"
fi
