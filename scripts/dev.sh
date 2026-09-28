#!/usr/bin/env bash
# One command for development: the API on the host with hot reload, Vite
# with its proxy, against the `dioptra-dev-pg` PostgreSQL container.
#
#   scripts/dev.sh            # API on :8000, UI on http://localhost:5173
#   scripts/dev.sh seed       # also creates the three seed accounts first
#   scripts/dev.sh workers    # a real queue: Valkey + the two RQ workers
#                             # (arguments combine: `scripts/dev.sh seed workers`)
#   scripts/dev.sh reset      # WIPE the development data and start from zero:
#                             # stops a previous run, recreates the database,
#                             # empties the queue and the data directories
#                             # (the local OSV data is kept), then seeds.
#                             # Asks first; `reset workers` combines as well.
#
# Production is `docker compose -f docker/docker-compose.yml up --build`
# (README → Run it); this script exists so a dev session is one command.
# Nothing here reaches the internet: the vulnerability sync is disabled and,
# by default, the queue runs inline (no Valkey needed). `workers` swaps that
# for what Compose runs: a local Valkey and two RQ workers with the SAME job
# classes — `analysis` (PipelineJob) and `reports` (ReportWorkerJob) — so the
# PDF export is seen as a job: queued, rendering, ready (phase 8). The workers
# run on the host, so this proves the queue and the allowlists, not that the
# report worker has no Docker socket; Compose is what proves that.

set -euo pipefail
cd "$(dirname "$0")/.."

SEED=0
WORKERS=0
RESET=0
for arg in "$@"; do
  case "$arg" in
    seed) SEED=1 ;;
    workers) WORKERS=1 ;;
    reset) RESET=1; SEED=1 ;;
    *) echo "unknown argument: $arg (expected: seed, workers, reset)" >&2; exit 2 ;;
  esac
done

# The accounts `app.seed` creates (backend/app/seed.py → SEED_ACCOUNTS), for
# the banner at the end. Keep the two lists in step.
SEED_USERS=("srosales admin" "mmarin analyst" "pperez developer")

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

# Three states, not two: running (nothing to do), STOPPED — which is what a
# reboot leaves, and `docker run` then fails on the taken name — or absent.
# A stopped container is started again with its data, never recreated.
if ! docker ps --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
  if docker ps -a --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
    echo "starting the existing $PG_CONTAINER"
    docker start "$PG_CONTAINER" >/dev/null
  else
    echo "creating $PG_CONTAINER (postgres:18-alpine on 127.0.0.1:$PG_PORT)"
    docker run -d --name "$PG_CONTAINER" -p "127.0.0.1:$PG_PORT:5432" \
      -e POSTGRES_USER=dioptra -e "POSTGRES_PASSWORD=${POSTGRES_PASSWORD:?POSTGRES_PASSWORD in .env}" \
      -e POSTGRES_DB=dioptra postgres:18-alpine >/dev/null
  fi
fi
# A fresh container initialises the cluster on a temporary server that listens
# on the Unix socket only; TCP readiness is the signal that init has finished.
for _ in $(seq 1 60); do
  if docker exec "$PG_CONTAINER" pg_isready -h 127.0.0.1 -U dioptra -d dioptra >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$PG_CONTAINER" pg_isready -h 127.0.0.1 -U dioptra -d dioptra >/dev/null 2>&1 \
  || { echo "$PG_CONTAINER did not become ready in 60 s: docker logs $PG_CONTAINER" >&2; exit 1; }
# The container's own password wins: it may predate the current .env.
PG_PASSWORD="$(docker inspect "$PG_CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' \
  | sed -n 's/^POSTGRES_PASSWORD=//p' | head -1)"
PG_PASSWORD="${PG_PASSWORD:-${POSTGRES_PASSWORD:-dioptra}}"

mkdir -p "$DATA/workspaces" "$DATA/runs" "$DATA/vulndb" "$DATA/osv" "$DATA/reports"

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
# Phase 8: finished PDFs wait here. With the queue inline (the default) the
# PDF job renders INSIDE its POST, so the toast jumps straight to "listo";
# `scripts/dev.sh workers` shows the queued and rendering states too.
export DIOPTRA_REPORT_SPOOL_DIR="$DATA/reports"
export DIOPTRA_VULNDB_SYNC_ENABLED=false

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
# The RQ workers of a previous run of THIS checkout: they hold database
# connections and would pick up jobs against a database that no longer exists.
stop_old_workers() {
  local pid
  for pid in $(pgrep -f "rq worker .*--job-class app\.core\.queue\." || true); do
    if [ "$(readlink "/proc/$pid/cwd" 2>/dev/null)" = "$PWD/backend" ]; then
      echo "stopping an old worker (pid $pid)"
      kill "$pid" 2>/dev/null || true
    fi
  done
}

if [ "$RESET" = 1 ]; then
  if [ "$DIOPTRA_ENV" = "prod" ]; then
    echo "reset refused: DIOPTRA_ENV=prod — this command is for development only" >&2
    exit 1
  fi
  echo "reset: this ERASES every project, analysis, report, audit row and account"
  echo "       in the database 'dioptra' of $PG_CONTAINER, the queue, and"
  echo "       $DATA/{workspaces,runs,reports,vulndb}. The local OSV data is kept."
  if [ -t 0 ]; then
    read -r -p "Type 'delete' to continue: " answer
    [ "$answer" = "delete" ] || { echo "reset cancelled; nothing was touched"; exit 1; }
  elif [ "${DIOPTRA_DEV_RESET_YES:-}" != "1" ]; then
    echo "reset needs a terminal to confirm, or DIOPTRA_DEV_RESET_YES=1" >&2
    exit 1
  fi
  free_port 8000 "app.main:create_app"
  free_port 5173 "vite"
  stop_old_workers
  # WITH (FORCE) closes any connection still open (a psql, a stray process).
  docker exec "$PG_CONTAINER" psql -q -U dioptra -d postgres \
    -c "DROP DATABASE IF EXISTS dioptra WITH (FORCE);" -c "CREATE DATABASE dioptra OWNER dioptra;"
  VALKEY_CONTAINER="${DIOPTRA_DEV_VALKEY:-dioptra-dev-valkey}"
  if docker ps --format '{{.Names}}' | grep -qx "$VALKEY_CONTAINER"; then
    docker exec "$VALKEY_CONTAINER" valkey-cli FLUSHALL >/dev/null
  fi
  for dir in workspaces runs reports vulndb; do
    find "$DATA/$dir" -mindepth 1 -delete
  done
  echo "reset: done — migrating and seeding a fresh database"
fi

(cd backend && uv run alembic upgrade head)
if [ "$SEED" = 1 ]; then
  (cd backend && uv run python -m app.seed)
fi

free_port 8000 "app.main:create_app"
free_port 5173 "vite"

cleanup() { kill 0 2>/dev/null || true; }
trap cleanup EXIT INT TERM

if [ "$WORKERS" = 1 ]; then
  VALKEY_CONTAINER="${DIOPTRA_DEV_VALKEY:-dioptra-dev-valkey}"
  VALKEY_PORT="${DIOPTRA_DEV_VALKEY_PORT:-56379}"
  if ! docker ps --format '{{.Names}}' | grep -qx "$VALKEY_CONTAINER"; then
    if docker ps -a --format '{{.Names}}' | grep -qx "$VALKEY_CONTAINER"; then
      docker start "$VALKEY_CONTAINER" >/dev/null
    else
      echo "starting $VALKEY_CONTAINER (valkey/valkey:9-alpine on 127.0.0.1:$VALKEY_PORT)"
      # Loopback only and no persistence: a development broker, nothing more.
      docker run -d --name "$VALKEY_CONTAINER" -p "127.0.0.1:$VALKEY_PORT:6379" \
        valkey/valkey:9-alpine valkey-server --save "" --appendonly no >/dev/null
    fi
  fi
  for _ in $(seq 1 30); do
    if docker exec "$VALKEY_CONTAINER" valkey-cli ping 2>/dev/null | grep -q PONG; then break; fi
    sleep 1
  done
  export DIOPTRA_QUEUE_INLINE=false
  export DIOPTRA_REDIS_URL="redis://127.0.0.1:$VALKEY_PORT/0"
  # The same argv as the Compose services, minus the container around them.
  (cd backend && uv run rq worker --url "$DIOPTRA_REDIS_URL" --serializer json \
    --job-class app.core.queue.PipelineJob --with-scheduler analysis) &
  (cd backend && uv run rq worker --url "$DIOPTRA_REDIS_URL" --serializer json \
    --job-class app.core.queue.ReportWorkerJob --with-scheduler reports) &
fi

(cd backend && uv run uvicorn app.main:create_app --factory --reload --host 127.0.0.1 --port 8000) &
(cd frontend && npm run dev) &
sleep 2
echo
echo "UI: http://localhost:5173   API: http://127.0.0.1:8000/api/docs   (Ctrl+C stops everything)"
if [ "$WORKERS" = 1 ]; then
  echo "Queue: Valkey on 127.0.0.1:$VALKEY_PORT, workers on 'analysis' and 'reports'; PDFs wait in $DATA/reports"
fi
echo "Accounts (passwords from .env; every seeded account must change it on first login):"
for entry in "${SEED_USERS[@]}"; do
  read -r user role <<<"$entry"
  var="DIOPTRA_SEED_PASSWORD_${user^^}"
  printf '  %-9s %-10s %s\n' "$user" "$role" "${!var:-<$var not set>}"
done
echo "  (if you already changed a password in the UI, the new one applies, not this)"
wait
