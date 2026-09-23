#!/usr/bin/env bash
# One command for development: the API on the host with hot reload, Vite
# with its proxy, against the `dioptra-dev-pg` PostgreSQL container.
#
#   scripts/dev.sh            # API on :8000, UI on http://localhost:5173
#   scripts/dev.sh seed       # also creates the three seed accounts first
#
# Production is `docker compose -f docker/docker-compose.yml up --build`
# (README → Run it); this script exists so a dev session is one command.
# Nothing here reaches the internet: the vulnerability sync is disabled and
# the queue runs inline (no Valkey needed).

set -euo pipefail
cd "$(dirname "$0")/.."

PG_CONTAINER="${DIOPTRA_DEV_PG:-dioptra-dev-pg}"
PG_PORT="${DIOPTRA_DEV_PG_PORT:-55432}"
DATA="${DIOPTRA_DEV_DATA:-$HOME/.cache/dioptra-dev}"

if [ ! -f .env ]; then
  echo "no .env: cp .env.example .env and fill DIOPTRA_JWT_SECRET (32+ chars)" >&2
  exit 1
fi
set -a
# shellcheck disable=SC1091
. ./.env
set +a

if ! docker ps --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
  echo "starting $PG_CONTAINER (postgres:18-alpine on 127.0.0.1:$PG_PORT)"
  docker run -d --name "$PG_CONTAINER" -p "127.0.0.1:$PG_PORT:5432" \
    -e POSTGRES_USER=dioptra -e "POSTGRES_PASSWORD=${POSTGRES_PASSWORD:?POSTGRES_PASSWORD in .env}" \
    -e POSTGRES_DB=dioptra postgres:18-alpine >/dev/null
  sleep 3
fi
# The container's own password wins: it may predate the current .env.
PG_PASSWORD="$(docker inspect "$PG_CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' \
  | sed -n 's/^POSTGRES_PASSWORD=//p' | head -1)"
PG_PASSWORD="${PG_PASSWORD:-${POSTGRES_PASSWORD:-dioptra}}"

mkdir -p "$DATA/workspaces" "$DATA/runs" "$DATA/vulndb" "$DATA/osv"

export DIOPTRA_ENV="${DIOPTRA_ENV:-dev}"
export DIOPTRA_REFRESH_COOKIE_SECURE=false
export DIOPTRA_DATABASE_URL="postgresql+psycopg://dioptra:${PG_PASSWORD}@127.0.0.1:${PG_PORT}/dioptra"
export DIOPTRA_QUEUE_INLINE=true
export DIOPTRA_RUNNER_MODE="${DIOPTRA_RUNNER_MODE:-docker}"
export DIOPTRA_RUNNER_USER="$(id -u):$(id -g)"
export DIOPTRA_RULES_DIR="$PWD/rules"
export DIOPTRA_OSV_DB_DIR="$DATA/osv"
export DIOPTRA_WORKSPACE_ROOT="$DATA/workspaces"
export DIOPTRA_SANDBOX_RUNS_ROOT="$DATA/runs"
export DIOPTRA_VULNDB_SPOOL_DIR="$DATA/vulndb"
export DIOPTRA_VULNDB_SYNC_ENABLED=false

(cd backend && uv run alembic upgrade head)
if [ "${1:-}" = "seed" ]; then
  (cd backend && uv run python -m app.seed)
fi

# A previous run of THIS script left behind (Ctrl+C in a lost terminal) is
# the only thing allowed to be on our two ports; anything else is reported.
free_port() {
  local port="$1" pattern="$2" pids
  pids="$(ss -ltnpH "sport = :$port" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u || true)"
  [ -z "$pids" ] && return 0
  for pid in $pids; do
    if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q "$pattern"; then
      echo "port $port held by an old $pattern (pid $pid): stopping it"
      kill "$pid" 2>/dev/null || true
    else
      echo "port $port is used by another program (pid $pid): stop it or set a free port" >&2
      exit 1
    fi
  done
  sleep 1
}
free_port 8000 "app.main:create_app"
free_port 5173 "vite"

cleanup() { kill 0 2>/dev/null || true; }
trap cleanup EXIT INT TERM

(cd backend && uv run uvicorn app.main:create_app --factory --reload --host 127.0.0.1 --port 8000) &
(cd frontend && npm run dev) &
sleep 2
echo
echo "UI: http://localhost:5173   API: http://127.0.0.1:8000/api/docs   (Ctrl+C stops both)"
echo "Accounts (passwords from .env; every seeded account must change it on first login):"
printf '  %-8s %-10s %s\n' amedina admin "${DIOPTRA_SEED_PASSWORD_AMEDINA:-<DIOPTRA_SEED_PASSWORD_AMEDINA not set>}"
printf '  %-8s %-10s %s\n' mmarin  analyst "${DIOPTRA_SEED_PASSWORD_MMARIN:-<DIOPTRA_SEED_PASSWORD_MMARIN not set>}"
printf '  %-8s %-10s %s\n' cperez  developer "${DIOPTRA_SEED_PASSWORD_CPEREZ:-<DIOPTRA_SEED_PASSWORD_CPEREZ not set>}"
echo "  (if you already changed a password in the UI, the new one applies, not this)"
wait
