# Dioptra

Web platform for white-box analysis of third-party systems: an automated audit
pipeline (SAST, dependency CVEs, secrets, metrics), a software inventory per
project (SBOM/CBOM/VEX in CycloneDX, checked against a local OSV + NVD
mirror), a gated workflow that walks a developer from a test plan to tests
they write themselves, and an editable institutional report with
OWASP/CWE/CVSS classification.

Two rules shape everything else:

- **The platform never writes tests.** There is no AI anywhere in the product.
  It generates deterministic scaffolding from the AST; assertions and logic are
  always the developer's — writing the test *is* the learning.
- **Nothing is loaded from an external server at runtime.** Every dependency is
  installed, pinned and served from this deployment; vulnerability data is a
  local mirror refreshed by a scheduled sync or a file import, never a live
  query. The same rule is applied to the systems under audit: an external
  `<script>` there is a finding (CWE-829).

Project lead: **Moises Marin** (`mmarin`).

---

## Status

Phases 0–5 are built (2026-09-22): authentication, roles, audit trail,
themes, i18n and the CI gates (P0); the audit pipeline and the institutional
report (P1); findings triage and the versioned report editor (P2); the
workflow E1–E5 with deterministic briefs (P3); scaffolds, the sandbox and the
mutation re-audit (P4); the software inventory with the local OSV + NVD
mirror, the audit-log screen, the report's closing sections and annexes, the
self-audit and the hardening of the last day (P5). Phase 1 in detail: project registration (E1), ZIP / git ingest into a per-analysis
jail (E2), the analysis pipeline in ephemeral containers (Semgrep with our own
rules, Gitleaks, OSV-Scanner offline, Syft SBOM, Lizard, cloc), SARIF
normalization with CWE → OWASP and CVSS 3.1, and the institutional report as
PDF / DOCX / Markdown / HTML. The work plan (`docs/work-plan-reference.html`,
distilled in `docs/development-phases.md`) runs 2026-08-24 → 2026-09-18 and
ends with release v1.0.0: P1 audit pipeline + institutional PDF, P2 findings
UI, P3 workflow E1–E5, P4 sandbox + mutation re-audit, P5 software inventory
and self-audit. PHP/Laravel and Java/Spring were cut to a second cycle under
the plan's own contingency: v1.0.0 ships JS/TS + Python.

## Run it

```bash
cp .env.example .env
# fill DIOPTRA_JWT_SECRET (32+ chars), POSTGRES_PASSWORD and DIOPTRA_APP_DB_PASSWORD:  openssl rand -base64 48
# (Compose interpolates them at load time, so even `docker compose build` wants the .env)
docker compose -f docker/docker-compose.yml up --build
```

The UI is on <http://localhost:8080>. The API runs behind the same origin at
`/api/v1`; the one-shot `migrate` service applies the migrations as the schema
owner before the API starts, and the API and the worker connect as the
restricted `dioptra_app` role.

### Seed accounts (development only)

Seeding is refused when `DIOPTRA_ENV=prod`, and it never invents a password — each
one comes from the environment, and every seeded account must change it on
first login.

```bash
docker compose -f docker/docker-compose.yml exec api python -m app.seed
```

| Username | Role | Does |
|---|---|---|
| `amedina` | admin | accounts, roles, projects |
| `mmarin` | analyst | runs analyses, triages findings, signs the report |
| `cperez` | developer | test plan, case design, writes the tests |

Usernames are initial + lastname, lowercase, no dots.

### Development in one command

```bash
scripts/dev.sh          # API with hot reload on :8000, Vite on http://localhost:5173
scripts/dev.sh seed     # also creates the three seed accounts
```

It uses (or starts) the `dioptra-dev-pg` PostgreSQL container on 127.0.0.1:55432,
runs the queue inline, keeps the vulnerability sync off and prints the seed
accounts at the end. `scripts/self_audit.py` runs the committed tree through
the platform's own pipeline (the plan's last-day self-audit).

### Analysis tools (phase 1)

The `worker` service runs every tool inside the `dioptra-analysis` image with
`--network none` and hard CPU / RAM / pids limits; the API never touches the
Docker daemon. The image is built once by Compose. Two things are operator
choices:

- **One data directory, same path on host and containers.** `DIOPTRA_DATA_DIR`
  (default `/var/lib/dioptra`, owned by uid 10001) holds the per-analysis jails
  and the OSV database. `docker run` bind mounts are resolved by the host
  daemon, which is why the path must be identical on both sides.
- **Vulnerability data is local.** Run
  `scripts/osv_db_download.sh /var/lib/dioptra/osv` on a connected host (or copy
  that directory from one). Without it, OSV-Scanner is reported as a coverage
  gap in every report — the platform never queries a vulnerability service live.

## Develop

```bash
# backend
cd backend && uv sync && uv run pytest
DIOPTRA_ENV=dev DIOPTRA_JWT_SECRET=a-development-secret-of-32-plus-chars \
  uv run uvicorn app.main:create_app --factory --reload

# frontend (proxies /api to localhost:8000)
cd frontend && npm ci && npm run dev
```

## Quality gates

`scripts/ci.sh` runs every gate; the CI workflow only calls that script.

| Gate | Command | Fails when |
|---|---|---|
| Lint | `ruff check` / `oxlint` | style or bug patterns |
| Types | `mypy --strict` / `tsc` | any type hole |
| Tests | `pytest` / `vitest` | a behaviour changed |
| Locale parity | `vitest` (`src/locales/locales.test.ts`) | `es.json` and `en.json` disagree on keys |
| Free licences | `scripts/license_gate.py` | a dependency is not free |
| No CDN | `scripts/no_cdn_check.py` | the built bundle points at another host |
| No secrets | `gitleaks` | a credential reaches the repository |
| Migrations | CI `migrations` job | upgrade or downgrade breaks on real PostgreSQL |

## Layout

```
backend/    FastAPI app (auth, audit today; ingest, analysis, reports, workflow, sandbox, inventory later)
frontend/   React 19 + Vite bundle, served locally, es/en, light/dark
docker/     Compose stack and images
docs/       Architecture, workflow gates, threat model, UI model, software inventory, mockups, work plan
tasks/      One file per phase: objective, deliverables, definition of done
scripts/    Our own gates (licences, no-CDN) and the CI entry point
rules/      Our own Semgrep rules (phase 1)
```

Governance, conventions and hard rules live in `CLAUDE.md`.
