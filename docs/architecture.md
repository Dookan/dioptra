# Architecture

> **Status: DESIGN SURFACE — not yet implemented.** Anchored to the approved development plan (2026-08) and the work plan v1.0 (2026-08-21, `docs/work-plan-reference.html`). P0 (auth, audit log, i18n, CI) is built; the rest is the target.

## Components

```
                 ┌─────────────────────────────────────────────┐
                 │                 Browser (ES/EN)              │
                 │   React 19 + Vite bundle, served locally     │
                 └───────────────┬─────────────────────────────┘
                                 │ HTTPS /api/v1  (JWT)
                 ┌───────────────▼─────────────────────────────┐
                 │            FastAPI backend                   │
                 │  auth · workflow gates · reports · audit log │
                 │  inventory (SBOM/CBOM/VEX · BOM↔CVE · stats) │
                 └───┬───────────────┬─────────────────┬───────┘
                     │               │                 │
          ┌──────────▼───┐   ┌──────▼───────┐  ┌──────▼────────┐
          │ PostgreSQL   │   │ Valkey + RQ  │  │ Report engine │
          │ users,       │   │ job queue +  │  │ Jinja2 → HTML │
          │ projects,    │   │ worker       │  │ → WeasyPrint  │
          │ findings,    │   └──────┬───────┘  │ + DOCX + MD   │
          │ report vers.,│          │          └───────────────┘
          │ BOMs, local  │   ┌──────▼──────────────────────────┐
          │ vuln DB      │   │   Ephemeral Docker containers    │
          │ (OSV + NVD   │   │ ┌─────────┐ ┌───────┐ ┌───────┐ │
          │  mirror)     │   │ │ Semgrep │ │Gitleaks│ │ OSV / │ │
          └──────▲───────┘   │ └─────────┘ └───────┘ │ Trivy │ │
                 │           │ ┌─────────┐ ┌───────┐ └───────┘ │
   scheduled sync│           │ │ Syft /  │ │Lizard │           │
   or dump-file  │           │ │ cdxgen  │ │+ cloc │           │
   import — never│           │ │ (SBOM)  │ └───────┘           │
   a live query  │           │ └─────────┘                     │
                 │           │ ┌──────────────────────────────┐ │
                 │           │ │ Test sandbox: NO network,    │ │
                 │           │ │ CPU/RAM caps, RO fs + workdir│ │
                 │           │ └──────────────────────────────┘ │
                 │           └─────────────────────────────────┘
```

Error contract: every failure is `{code, message_key}` (a stable i18n key, never server-authored copy) and MAY add `context` — short strings the UI interpolates into the translated message as text (`backend/app/core/errors.py`).

## Repository layout (target)

- `backend/app/` — `auth/`, `ingest/`, `analysis/`, `workflow/` (stages, gates, brief, `scaffold/`, verify), `reports/`, `sandbox/` (E7 run directory, executor, result parsing), `audit/`, `inventory/` (P5: BOM store, vulnerability DB sync, correlation, statistics)
- `backend/templates/` — institutional report Jinja2 templates (anchor: the manual MINCYT-form reports)
- `frontend/src/` — `screens/`, `components/`, `theme/tokens.css`, `locales/{es,en}.json`
- `rules/semgrep/` — our own SAST rules (OWASP-mapped, includes the no-CDN rule)
- `docker/` — compose files, the analysis image and the E7 sandbox image (`sandbox.Dockerfile` + `sandbox/`: the pinned runner manifest and the two wrappers that normalise each tool's output INSIDE the image, so the host never learns a tool's format)
- `docs/`, `tasks/`, `.claude/` — this governance layer

## Data flow (one analysis)

ingest (E2) → job queued → per-tool containers (Semgrep, Gitleaks, OSV,
Lizard/cloc **+ SBOM generation**) → SARIF outputs → normalizer (CWE→OWASP
map, CVSS, dedupe) → findings + SBOM persisted → triage (E3, VEX verdicts on
SCA findings) → risk matrix (E4) → AST briefs + Mermaid diagrams (E5) →
scaffolds (E6) → sandbox run + coverage + mutation (E7; a failure loops back
to E5 through an explicit reopen, never a backwards stage move) → report composition
(E8, including the inventory section) → HTML/PDF/DOCX/Markdown export.

Off the workflow, per deployment: scheduled sync (or file import) of the
OSV + NVD mirror → BOM ↔ CVE correlation over every stored SBOM → inventory
panel + CycloneDX/CSV export. See `docs/software-inventory.md`.
