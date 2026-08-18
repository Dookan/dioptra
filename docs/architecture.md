# Architecture

> **Status: DESIGN SURFACE — not yet implemented.** Anchored to the approved development plan (2026-08).

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
                 └───┬───────────────┬─────────────────┬───────┘
                     │               │                 │
          ┌──────────▼───┐   ┌──────▼───────┐  ┌──────▼────────┐
          │ PostgreSQL   │   │ Valkey + RQ  │  │ Report engine │
          │ users,       │   │ job queue    │  │ Jinja2 → HTML │
          │ projects,    │   └──────┬───────┘  │ → WeasyPrint  │
          │ findings,    │          │          └───────────────┘
          │ report vers. │   ┌──────▼──────────────────────────┐
          └──────────────┘   │   Ephemeral Docker containers    │
                             │ ┌─────────┐ ┌───────┐ ┌───────┐ │
                             │ │ Semgrep │ │Gitleaks│ │ Trivy │ │
                             │ └─────────┘ └───────┘ └───────┘ │
                             │ ┌──────────────────────────────┐ │
                             │ │ Test sandbox: NO network,    │ │
                             │ │ CPU/RAM caps, RO fs + workdir│ │
                             │ └──────────────────────────────┘ │
                             └─────────────────────────────────┘
```

## Repository layout (target)

- `backend/app/` — `auth/`, `ingest/`, `analysis/`, `workflow/`, `reports/`, `sandbox/`, `audit/`
- `backend/templates/` — MINCYT report Jinja2 templates
- `frontend/src/` — `screens/`, `components/`, `theme/tokens.css`, `locales/{es,en}.json`
- `rules/semgrep/` — our own SAST rules (OWASP-mapped, includes the no-CDN rule)
- `docker/` — compose files, analysis & sandbox images
- `docs/`, `tasks/`, `.claude/` — this governance layer

## Data flow (one analysis)

ingest (E2) → job queued → per-tool containers → SARIF outputs → normalizer
(CWE→OWASP map, CVSS) → findings persisted → triage (E3) → risk matrix (E4)
→ AST briefs + diagrams (E5) → scaffolds (E6) → sandbox run + coverage +
mutation (E7) → report composition (E8) → HTML/PDF/DOCX/Markdown export.
