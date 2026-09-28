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

  # The E7 sandbox image installs its own runners (pytest, coverage, mutmut,
  # vitest, Stryker) at BUILD time, so they are invisible to the checks above:
  # they live inside the image, not in backend/.venv or frontend/node_modules.
  # Run the same gate in there, against the image's own trees.
  log "supply chain: free licences inside the E7 sandbox images"
  if command -v docker >/dev/null 2>&1 \
     && docker image inspect "${DIOPTRA_SANDBOX_IMAGE:-dioptra-sandbox:latest}" >/dev/null 2>&1
  then
    docker run --rm --network none \
      -v "$(pwd)/scripts/license_gate.py:/tmp/license_gate.py:ro" \
      "${DIOPTRA_SANDBOX_IMAGE:-dioptra-sandbox:latest}" \
      python3 /tmp/license_gate.py --backend-venv /usr/local --node-modules /opt/dioptra-js/node_modules --skip-actions
  else
    echo "sandbox image not built here — build it (docker compose build sandbox-image) to check its licences"
  fi

  # The PHP image (phase 7a) installs PHPUnit and Infection as PHARS and Xdebug
  # through pecl: none of them appears in any lockfile of this repository, which
  # is the same reason the wave-1 image is gated from the inside. It carries no
  # Python venv and no node_modules, so the gate reads the manifest the image
  # generates about itself at build time — 64 packages, walked out of the
  # phars' own per-component LICENSE files.
  if command -v docker >/dev/null 2>&1 \
     && docker image inspect "${DIOPTRA_SANDBOX_IMAGE_PHP:-dioptra-sandbox-php:latest}" >/dev/null 2>&1
  then
    # The gate runs on the HOST and reads the manifest out of the image: that
    # image has no python3 (checked — it is php:8.3-cli), so the wave-1 shape
    # of "run the gate inside" cannot work here. What matters is unchanged:
    # the declaration ships INSIDE the artefact and the gate fails the build
    # on it, rather than trusting a comment in the Dockerfile.
    php_manifest="$(mktemp)"
    docker run --rm --network none --entrypoint cat \
      "${DIOPTRA_SANDBOX_IMAGE_PHP:-dioptra-sandbox-php:latest}" \
      /opt/dioptra-php/licenses.json > "$php_manifest"
    uv run --project backend python scripts/license_gate.py --php-manifest "$php_manifest"
    rm -f "$php_manifest"
  else
    echo "php sandbox image not built here — build it (docker compose build sandbox-php-image) to check its licences"
  fi

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
