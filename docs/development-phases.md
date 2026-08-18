# Development phases

> **Status: P0 DONE (2026-08-18) — everything else DESIGN.** Phase status summary
> also lives in CLAUDE.md → Current phase status; keep both in sync.

Phases replace sprints. A phase closes ONLY when its Definition of Done in the
corresponding `tasks/phaseN-*.md` is fully checked, its tests pass, and its
docs are updated.

| Phase | Delivers | Closes when |
|---|---|---|
| P0 Foundations | Repo scaffold, Docker Compose, FastAPI + React skeletons, auth (Argon2id + JWT + roles), i18n es/en, themes, CI (ruff, mypy, oxlint, tsc, license gate, Gitleaks, locale parity) | login works end-to-end for the three roles; CI green |
| P1 Audit MVP | ZIP/git ingest → Semgrep + Gitleaks + OSV → normalized findings → MINCYT PDF | the MINCYT backend report is reproduced automatically, indistinguishable in structure |
| P2 Findings UI | triage with justification, report editor + versions | E3 gate usable start-to-finish in the UI |
| P3 Workflow E1–E5 | risk matrix, AST diagrams, test briefs, pseudocode approval | a developer reaches E5 approval on a real project |
| P4 E6–E7 | deterministic scaffolds, sandbox, coverage vs. brief, mutation re-audit | a surviving mutant demonstrably rejects the gate |
| P5 Hardening + wave 2 | PHP/Laravel + Java/Spring, full audit log, ASVS L2 self-audit | the platform passes its own pipeline at ASVS L2 |

Plan-first gate: any phase slice touching auth/sandbox/ingest/report-integrity
or >200 LOC starts with `tasks/phaseN-survey.md` (read-only survey + design
pseudocode + `## Verdict`), signed off before edits.
