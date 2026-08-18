#!/usr/bin/env bash
# Every quality gate, in one command.
#
# This script IS the CI: the workflow file only calls it, so the same gates run
# on a laptop, on GitHub Actions, or on whatever runner the factory ends up with.
#
#   scripts/ci.sh            # everything
#   scripts/ci.sh backend    # one stage: backend | frontend | supply-chain

set -euo pipefail

cd "$(dirname "$0")/.."
STAGE="${1:-all}"

log() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

run_backend() {
  log "backend: lint (ruff)"
  (cd backend && uv run ruff check .)
  (cd backend && uv run ruff format --check .)

  log "backend: types (mypy --strict)"
  (cd backend && uv run mypy app tests)

  log "backend: tests (pytest)"
  (cd backend && uv run pytest)

  log "gates: our own checkers"
  (cd backend && uv run pytest ../scripts -q)
}

run_frontend() {
  log "frontend: lint (oxlint)"
  (cd frontend && npx oxlint --deny-warnings src)

  log "frontend: types (tsc)"
  (cd frontend && npx tsc -b)

  log "frontend: tests (vitest, includes locale parity)"
  (cd frontend && npx vitest run)

  log "frontend: production build"
  (cd frontend && npm run build)
}

run_supply_chain() {
  log "supply chain: free licences only"
  uv run --project backend python scripts/license_gate.py

  log "supply chain: no CDN in the built bundle"
  uv run --project backend python scripts/no_cdn_check.py --dist frontend/dist

  log "supply chain: no secrets in the repository"
  if command -v gitleaks >/dev/null 2>&1; then
    # Two passes: the working tree (a secret not yet committed is still a
    # secret) and the history (a secret removed later is still in the log).
    gitleaks dir . --config .gitleaks.toml --redact --no-banner
    gitleaks git . --config .gitleaks.toml --redact --no-banner
  else
    echo "gitleaks not installed locally — the CI job runs it; install it to check here"
  fi
}

case "$STAGE" in
  backend) run_backend ;;
  frontend) run_frontend ;;
  supply-chain) run_supply_chain ;;
  all)
    run_backend
    run_frontend
    run_supply_chain
    ;;
  *)
    echo "unknown stage: $STAGE (expected backend | frontend | supply-chain | all)" >&2
    exit 2
    ;;
esac

log "all gates passed"
