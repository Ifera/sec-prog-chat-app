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
#   ./start_server.sh [PORT] [HOST] [INTRODUCERS_JSON]
# Sources (precedence):
#   1) CLI args override
#   2) .server.env (if present) key=value (supports #/; comments and quoted values)
#   3) Defaults
# --------------------------------------------

ENV_FILE=".server.env"

trim() {
  # trim leading/trailing whitespace
  local s="$1"
  s="${s#${s%%[![:space:]]*}}"  # leading
  s="${s%${s##*[![:space:]]}}"  # trailing
  printf '%s' "$s"
}

load_env_file() {
  local file="$1"
  while IFS= read -r line || [ -n "$line" ]; do
    # ignore empty and comment lines (# or ;) at start
    case "$line" in
      ''|'#'*|';'*) continue ;;
    esac
    # split at first '='
    local key="${line%%=*}"
    local val="${line#*=}"
    key=$(trim "$key")
    val=$(trim "$val")
    # strip surrounding quotes if present
    if [[ "$val" == '"'*'"' || "$val" == "'*'" ]]; then
      val="${val:1:${#val}-2}"
    fi
    # export
    if [[ -n "$key" ]]; then
      export "$key"="$val"
    fi
  done < "$file"
}

if [[ -f "$ENV_FILE" ]]; then
  load_env_file "$ENV_FILE"
fi

# Defaults (if not set by env file)
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"
INTRODUCERS_JSON="${INTRODUCERS_JSON:-introducers.json}"
TLS_CERT="${TLS_CERT:-../certs/dev_cert.pem}"
TLS_KEY="${TLS_KEY:-../certs/dev_key.pem}"

# CLI args override
if [[ "${1:-}" != "" ]]; then PORT="$1"; fi
if [[ "${2:-}" != "" ]]; then HOST="$2"; fi
if [[ "${3:-}" != "" ]]; then INTRODUCERS_JSON="$3"; fi

cat <<EOF

Starting Server with:
  HOST              = $HOST
  PORT              = $PORT
  INTRODUCERS_JSON  = $INTRODUCERS_JSON

EOF

export HOST PORT INTRODUCERS_JSON TLS_CERT TLS_KEY

# Choose python interpreter
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "Python interpreter not found (python3/python)" >&2
  exit 1
fi

exec "$PY" server.py

