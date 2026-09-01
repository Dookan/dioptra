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

Phase 0 (foundations) is done (2026-08-18): authentication, roles, audit
trail, themes, i18n and the CI gates. The work plan (`docs/work-plan-reference.html`,
distilled in `docs/development-phases.md`) runs 2026-08-24 → 2026-09-18 and
ends with release v1.0.0: P1 audit pipeline + institutional PDF, P2 findings
UI, P3 workflow E1–E5, P4 sandbox + mutation re-audit, P5 software inventory,
PHP/Java, self-audit.

## Run it

```bash
cp .env.example .env
# fill DIOPTRA_JWT_SECRET (32+ chars) and POSTGRES_PASSWORD:  openssl rand -base64 48
docker compose -f docker/docker-compose.yml up --build
```

The UI is on <http://localhost:8080>. The API runs behind the same origin at
`/api/v1`; migrations run automatically before the server accepts requests.

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
