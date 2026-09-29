# Task: Patch 1.6.1 — the worker's memory cap, and tidying

> **Status: DONE 2026-09-29 — the commit hash is recorded here and in
> CLAUDE.md by a follow-up commit.** A PATCH (1.6.0 → 1.6.1): no endpoint, no
> request or response shape, no migration. Asked by `mmarin` ("dale, cierra
> la 1.6.0 y haz la 1.6.1") from the recorded small items. No plan-first
> survey: nothing here touches auth, the sandbox, ingestion or the report's
> integrity, and it is well under 200 lines.

## Objective
Close the small items left after phase 12: the socket-holding worker had no
memory cap although a hostile tree can drive it to ~1.5 GiB; three screen
strings said "informe"; the deployment guide never said mail is off; and the
list of loggers in `docs/name-and-identity.md` named two of thirteen.

## Deliverables
1. `docker/docker-compose.yml` — `worker`: `mem_limit` and `memswap_limit`
   `${DIOPTRA_WORKER_MEMORY:-3g}`. Only the worker: the report worker and the
   API keep their sizing.
2. `backend/tests/test_compose_limits.py` — the cap exists, allows no swap
   beyond it, and its default covers six times `DIOPTRA_MAX_TOOL_PARSE_BYTES`
   plus 512 MiB; the other services are not capped here.
3. `frontend/src/locales/es.json` — three strings: "informe" → "reporte";
   `frontend/src/locales/locales.test.ts` refuses "informe" in `es.json`.
   The report's own prose keeps "informe" (the word of all ten anchor PDFs).
4. `docs/name-and-identity.md` — the logger row lists every logger;
   `backend/tests/test_loggers.py` keeps it equal to the code.
5. `docs/deployment/README.md` (both halves) — the worker's cap under the
   backend server's requirements; "no mail" under the known limitations.
6. Docs: CLAUDE.md, development-phases, threat-model (Analysis containers),
   ui-model, README (both halves). Version 1.6.1 in the five pinned places.

## Constraints
- No contract change; no new dependency (the Compose test reads the file
  with a regular expression, as `test_upload_caps.py` does).
- The report content is the institution's: its "informe" is not touched.

## Definition of Done
- [x] Deliverables 1–6; ruff + mypy (`app tests`) + oxlint + `tsc -b` clean
- [x] Tests: the new backend tests and the locale test pass, and the whole
      suites stay green
- [x] `docker compose config` renders the cap: 3 221 225 472 bytes by
      default, 4 294 967 296 with `DIOPTRA_WORKER_MEMORY=4g`
- [x] `/precommit` returned `READY TO COMMIT` (2026-09-29). **Security**
      (MINOR): the docs said the kernel kills "the worker", but RQ runs each
      job in a forked work horse, which is the biggest process in the cgroup —
      so the job dies and the worker keeps running; and the analysis is marked
      "stopped without finishing" only once it is past the stale window and a
      sweep runs, not at once — both worded in the Compose comment, the threat
      model and the guide (both halves); `.env.example` gained the two
      settings. **Invariants** (HOLDS): GB → GiB in the operator guides.
      **QA** (GENUINE): every test fails on a reverted copy (the cap removed,
      a 1g default, no `memswap_limit`, a literal `3g`, a cap on another
      service, the old logger row, a new logger), and the cap survives the
      two-host overlays; the "only the worker" test now covers every service.
      The runtime OOM path is argued, not exercised. **Mockup fidelity**
      (FAITHFUL). The coverage adversary was not fired separately: the QA pass
      reverted every change against its test, which is that agent's method,
      and the diff adds no application code
- [x] CLAUDE.md + development-phases: 1.6.1 DONE; the hash lands in the
      follow-up commit

## Non-goals (explicit)
- Caps on the other services (the report worker renders one PDF at a time;
  the API holds no report in memory) — measure before capping
- The mail recovery flow, Betterleaks, the UI rework, phase 7b — their own
  phases
- Changing "informe" in the report's prose or its templates

## References
- `tasks/hardening-1.5.1.md` (the 158 MiB measurement); `docs/threat-model.md`
  → Analysis containers; CLAUDE.md → Release rules
