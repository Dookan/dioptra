# Survey: Phase 1 — Audit MVP (plan-first gate)

> Read-only survey + design pseudocode required by CLAUDE.md → Agent
> Behavioral Rules (ingestion surface, >200 LOC). No edits were made before
> this file. Author: Claude Code. Sign-off: `mmarin` ("go", 2026-09-21).
>
> Context: today is 2026-09-21, past every plan deadline including the release.
> P0 is the only phase built. This slice delivers P1 end to end in one push,
> with the cuts listed in §6 recorded, not hidden.

## 1. Repository state (read-only findings)

| Path | State | Consequence for P1 |
|---|---|---|
| `backend/app/{auth,audit,core,db}` | P0, 1.6 kLOC, 99 tests green | conventions to copy: `AppError` hierarchy, `UtcDateTime`, `record()` audit, `require_roles()` |
| `backend/app/db/registry.py` | imports every model | new models MUST be added here or `alembic check` fails in CI |
| `backend/alembic/versions/0001_foundations.py` | head | P1 adds `0002_audit_mvp.py` |
| `docker/docker-compose.yml` | postgres, valkey (idle), api, frontend | P1 adds `worker` (RQ) and the `analysis` image |
| `scripts/license_gate.py` | own allowlist | every new dependency below is on it |
| `rules/semgrep/` | empty directory | own rules are greenfield |
| `backend/templates/` | absent | report templates are greenfield |
| Anchor PDF (backend API REST) | 10 pages, text extracted | section order in §4 is copied from it verbatim |

## 2. Toolchain verified on this host

Docker daemon reachable, PyPI and Docker Hub reachable, `uv`, node, gitleaks,
osv-scanner on PATH. Semgrep, syft, lizard, cloc, weasyprint NOT on the host:
they live in the analysis image (§3) and the runner tests use a fake executor.

## 3. Design decisions taken in this survey

| Decision | Choice | Rationale / license |
|---|---|---|
| Runner isolation | ONE analysis image (`docker/analysis.Dockerfile`) with semgrep, gitleaks, osv-scanner, syft, lizard, cloc; each tool invoked as `docker run --rm --network none --read-only --memory --cpus --pids-limit --cap-drop ALL --security-opt no-new-privileges -u 10001` | one image to ship to an air-gapped factory; every hard limit is a flag on one command; LGPL-2.1 / MIT / Apache-2.0 / MIT / GPL-2.0 |
| Executor abstraction | `Executor` protocol → `DockerExecutor` (production) and `LocalExecutor` (dev hosts + tests, same argv, `timeout`) | runners are testable without a daemon; the docker path is exercised by an opt-in integration test |
| Who talks to Docker | the `worker` service only, via the mounted socket; the API never does | the API stays `read_only` with no socket — a compromised request handler cannot start containers |
| Queue | RQ (BSD-2) over redis-py (MIT) against Valkey; `DIOPTRA_QUEUE_INLINE=true` runs jobs synchronously | tests and single-process dev need no broker |
| Tool output format | SARIF 2.1.0 from all three security tools (`semgrep --sarif`, `gitleaks --report-format sarif`, `osv-scanner --format sarif`) | one parser; the normalizer never sees a tool-specific JSON |
| SBOM | syft → CycloneDX 1.6 JSON, `--network none`, cataloger scope on lockfiles only; schema-validated with our own structural check (no `jsonschema` dep) | metadata only; the inventory (P5) reuses it |
| CWE → OWASP + Spanish copy | own `catalog.py` keyed by CWE: title, description, impact, mitigation, references | the anchor report's per-finding prose is fixed institutional text, not tool output |
| CVSS 3.1 | own base-score calculator from the vector string; when a tool gives no vector, severity from the tool level (error/warning/note → alta/media/baja) and `cvss = null` | no dependency; deterministic |
| Report | Jinja2 (BSD-3) → HTML → WeasyPrint (BSD-3); Markdown from a second Jinja2 template; DOCX via python-docx (MIT) | every snippet/path goes through autoescape; WeasyPrint gets a `url_fetcher` that refuses everything but the template's own assets |
| Upload parsing | python-multipart (Apache-2.0), 200 MiB request cap | FastAPI's `UploadFile` needs it |
| Git ingest | `git clone --depth 1` in the worker, https only, host resolved and rejected if private/loopback/link-local, `http.followRedirects=false`, timeout | SSRF row of the threat model |

## 4. Report structure (from the anchor PDF, authoritative order)

1. Cover: "Análisis de Caja Blanca Sistema <name>", month + year.
2. INTRODUCCIÓN (fixed text, system name interpolated).
3. RESUMEN EJECUTIVO: "El análisis identificó N hallazgo(s) (a alta, b media, c baja)".
4. DETALLES DEL SISTEMA: Nombre del sitio Web, Framework, Fecha de instalación, Base de datos, Desarrollador.
5. Control de versiones: Versión | Áreas Modificadas | Descripción del cambio | Fecha de entrega.
6. HALLAZGOS DE VULNERABILIDADES: per finding — title, Nivel de severidad, CWE, Código OWASP, Descripción General, Impacto, Detección (Ruta `path:line`), Mitigación (bullets), Referencias (bullets).
7. HALLAZGOS SOBRE PAQUETES Y DEPENDENCIAS: SCA findings or the fixed "no se identificaron" paragraph.
8. ERRORES Y PRÁCTICAS NO ADECUADAS EN EL CÓDIGO: commented-out code, files listed.
9. COBERTURA DE HERRAMIENTAS: Herramienta | Categoría | Estado | Detalle.

## 5. Ingest design pseudocode (the hostile surface)

```
ingest_zip(project, upload):
    assert upload.size <= MAX_ZIP_BYTES                     # 200 MiB, else ZipTooLarge
    analysis = analyses.create(project, status=QUEUED, source=ZIP)
    jail = WORKSPACE_ROOT / project.id / analysis.id / "src"   # fresh, 0o700
    with ZipFile(upload) as zf:
        entries = zf.infolist()
        if len(entries) > MAX_ENTRIES: raise TooManyEntries          # 50 000
        total = sum(e.file_size for e in entries)
        if total > MAX_UNCOMPRESSED: raise ZipTooLarge                # 1 GiB
        if total / max(compressed, 1) > MAX_RATIO: raise ZipBomb      # 100:1
        for e in entries:
            name = PurePosixPath(e.filename)
            if name.is_absolute() or ".." in name.parts or "\\" in e.filename: raise ZipSlipDetected
            if is_symlink(e) or is_device(e): skip + count            # never followed
            target = (jail / name).resolve()
            if not target.is_relative_to(jail): raise ZipSlipDetected
            stream-copy with a running byte counter; abort past MAX_UNCOMPRESSED
    detection = detect(jail)          # languages by extension, frameworks by manifests, lockfiles
    queue.enqueue(run_pipeline, analysis.id)
    audit("analysis.ingest", target=analysis.id)
    return analysis

ingest_git(project, url):
    parsed = urlparse(url); require scheme == "https", no userinfo, no port games
    addresses = getaddrinfo(host); if any is private/loopback/link-local/multicast: raise ForbiddenHost
    analysis = analyses.create(project, status=QUEUED, source=GIT, source_ref=url)
    queue.enqueue(run_pipeline, analysis.id)    # the clone happens in the worker, never in the request
```

Pipeline (worker):

```
run_pipeline(analysis_id):
    analysis.status = RUNNING
    if source == GIT: clone into jail (depth 1, timeout, followRedirects=false)
    for runner in [semgrep, gitleaks, osv, syft, lizard, cloc]:
        result = executor.run(runner.spec(jail, out_dir), timeout=runner.timeout)
        raw_tool_outputs.insert(tool, exit_code, stdout/stderr capped, output file bytes capped)
        tool_runs.insert(tool, category, status=ran|failed|missing, detail)   # coverage gap, never skipped
    findings = normalize(all SARIF) ; dedupe ; persist
    sbom = validate_cyclonedx(syft output) ; persist
    metrics = parse(lizard, cloc) ; persist
    practices = commented_code_scan(jail) ; persist
    analysis.status = DONE (or FAILED with a typed reason)
```

## 6. Cuts recorded for this push (scope-change log entry to follow)

- Day 10 "full day of fidelity" reduced to a first-pass structural match
  against the backend anchor. Pixel work remains open.
- Trivy config / Checkov and cloc duplication metrics deferred to the next
  cycle; Lizard + cloc line counts ship.
- Semgrep rule set is initial (JS/TS + Python + Vue `v-html`, 13 families, 32
  rules), not exhaustive. Verified against the institution's frontend anchor
  report: its three XSS findings (Vue `v-html`) are now covered; its
  "Dockerfile without USER" finding (CWE-250) is NOT — Semgrep cannot express
  the absence of an instruction, so that check is a follow-up (own detector in
  `app/analysis/metrics.py` or Trivy config, next cycle).
- End-to-end verified 2026-09-21 on `formulario_mincyt_front-desarrollo`
  through the Docker executor: six tools ran offline, 13 findings, SBOM of
  380 components, PDF/DOCX/Markdown rendered.

## Verdict

Proceed. The hostile surfaces (ZIP, git URL, snippet rendering, tool
execution) each have a named control in §3/§5 that maps to a threat-model row;
no new dependency lacks a free license; no P2+ code enters this slice.
