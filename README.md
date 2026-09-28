# Dioptra

> **Idiomas / Languages:** [Español](#español) · [English](#english)
>
> Excepción registrada a la regla "English everywhere" de `CLAUDE.md`: este
> README es bilingüe por pedido de `mmarin` (2026-09-24). / Recorded exception
> to CLAUDE.md's "English everywhere" rule: this README is bilingual at
> `mmarin`'s request (2026-09-24).

---

# Español

Plataforma web para el análisis de caja blanca de sistemas de terceros: un
pipeline de auditoría automático (SAST, CVE de dependencias, secretos,
métricas), un inventario de software por proyecto (SBOM/CBOM/VEX en CycloneDX,
cruzado contra una copia local de OSV + NVD), un flujo con compuertas que lleva
al programador desde el plan de pruebas hasta los tests que escribe él mismo, y
un reporte institucional editable con clasificación OWASP/CWE/CVSS.

Dos reglas definen todo lo demás:

- **La plataforma nunca escribe tests.** No hay IA en ninguna parte del
  producto. Genera un andamiaje determinista a partir del AST; las aserciones y
  la lógica son siempre del programador: escribir el test *es* el aprendizaje.
- **Nada se carga desde un servidor externo en ejecución.** Cada dependencia
  está instalada, fijada y servida desde el propio despliegue; los datos de
  vulnerabilidades son una copia local, actualizada por sincronización
  programada o por importación de archivo, nunca una consulta en vivo. La misma
  regla se aplica a los sistemas auditados: un `<script>` externo allí es un
  hallazgo (CWE-829).

Líder del proyecto: **Moises Marin** (`mmarin`).

## Estado

- **v1.0.0** (etiquetada 2026-09-23), fases P0–P5: autenticación, roles,
  bitácora, temas e i18n (P0); pipeline de auditoría y reporte institucional
  (P1); triage de hallazgos y editor de reporte versionado (P2); flujo E1–E5 con
  consignas deterministas (P3); andamiaje, sandbox y re-auditoría por mutación
  (P4); inventario de software con copia local OSV + NVD, bitácora en pantalla,
  secciones de cierre del reporte y auto-auditoría (P5).
- **Versión actual: 1.5.1.** Segundo ciclo, en curso: PHP/Laravel terminado
  (fase 7a); exportación de PDF asíncrona terminada (fase 8); ZIP de hasta
  1 GiB con barra de progreso del análisis terminado (fase 10); detección de
  respaldos, fotos subidas, `.env`, claves y logs incluidos en el código
  terminada (fase 11); Java/Spring pendiente (fase 7b); administración de
  usuarios terminada (fase 6); la 1.5.1 corrige que un informe grande de una
  herramienta se perdiera o se leyera incompleto, cierra los análisis que
  quedaron trabados y fija las herramientas por su huella SHA-256.
- **Numeración:** un cambio o corrección pequeña sube el tercer número, una
  fase completa el segundo, un cambio que rompe el contrato de la API el
  primero.
- El plan de trabajo está en `docs/work-plan-reference.html`, resumido en
  `docs/development-phases.md`.

## Ponerlo en marcha

**Producción** (un servidor, o frontend y backend en IPs distintas, PostgreSQL
en contenedor o instalado fuera de Docker, puertos, requisitos, firewall, primer
administrador, respaldos):
**[docs/deployment/README.md](docs/deployment/README.md)**.

Prueba rápida en una sola máquina:

```bash
cp .env.example .env
# completa DIOPTRA_JWT_SECRET (32+ caracteres), POSTGRES_PASSWORD y DIOPTRA_APP_DB_PASSWORD:
#   openssl rand -base64 48
# (Compose las lee al cargar el archivo, así que incluso `docker compose build` necesita el .env)
docker compose -f docker/docker-compose.yml up --build
```

La interfaz queda en <http://localhost:8080> y la API detrás del mismo origen,
en `/api/v1`. El servicio `migrate` aplica las migraciones como dueño del
esquema antes de que arranque la API; la API y los workers se conectan con el
rol restringido `dioptra_app`.

### Cuentas de prueba (solo desarrollo)

El seed se rechaza con `DIOPTRA_ENV=prod` y nunca inventa una contraseña: cada
una sale del entorno (`DIOPTRA_SEED_PASSWORD_<USUARIO>`), y toda cuenta creada
así debe cambiarla en su primer ingreso.

```bash
docker compose -f docker/docker-compose.yml exec api python -m app.seed
```

| Usuario | Rol | Hace |
|---|---|---|
| `srosales` | admin | cuentas, roles, proyectos |
| `mmarin` | analista | ejecuta análisis, revisa hallazgos, firma el reporte |
| `pperez` | programador | plan de pruebas, diseño de casos, escribe los tests |

Usuario = inicial + apellido, en minúsculas, sin puntos.

### Desarrollo con un solo comando (`scripts/dev.sh`)

```bash
scripts/dev.sh                 # API con recarga en :8000, interfaz en http://localhost:5173
scripts/dev.sh seed            # además crea las tres cuentas de prueba
scripts/dev.sh workers         # cola real: Valkey + los dos workers de RQ
scripts/dev.sh seed workers    # los argumentos se combinan
scripts/dev.sh reset workers   # BORRA los datos de desarrollo (base, cola, archivos
                               # subidos) y arranca de cero con las cuentas;
                               # pide escribir "delete" para confirmar
```

Usa (o arranca) el contenedor PostgreSQL `dioptra-dev-pg` en 127.0.0.1:55432.
Por defecto la cola corre en el mismo proceso; `workers` la cambia por el broker
`dioptra-dev-valkey` en 127.0.0.1:56379 y los mismos workers `analysis` y
`reports` que usa Compose. La sincronización de vulnerabilidades queda apagada,
y al final imprime las cuentas con sus contraseñas iniciales. Requisitos,
puertos y detalles: [docs/deployment/README.md §11](docs/deployment/README.md#11-desarrollo-local-scriptsdevsh).

`scripts/self_audit.py` pasa el código del repositorio por el pipeline de la
propia plataforma (la auto-auditoría del último día del plan).

### Herramientas de análisis

El servicio `worker` ejecuta cada herramienta dentro de la imagen
`dioptra-analysis` con `--network none` y límites de CPU, RAM y procesos; la API
nunca toca el daemon de Docker. Dos cosas dependen del operador:

- **Un directorio de datos, la misma ruta en el servidor y en los contenedores.**
  `DIOPTRA_DATA_DIR` (por defecto `/var/lib/dioptra`, del uid 10001) guarda el
  código de cada análisis, la base OSV, los volcados de vulnerabilidades
  pendientes y los PDFs terminados (se borran al descargarlos). Los montajes de
  `docker run` los resuelve el daemon del servidor, por eso la ruta debe ser
  idéntica en ambos lados.
- **Los datos de vulnerabilidades son locales.** Ejecuta
  `scripts/osv_db_download.sh /var/lib/dioptra/osv` en una máquina con internet
  (o copia ese directorio desde una). Sin él, OSV-Scanner aparece como brecha de
  cobertura en cada reporte: la plataforma nunca consulta un servicio en vivo.

## Desarrollar por partes

```bash
# backend
cd backend && uv sync && uv run pytest
DIOPTRA_ENV=dev DIOPTRA_JWT_SECRET=a-development-secret-of-32-plus-chars \
  uv run uvicorn app.main:create_app --factory --reload

# frontend (reenvía /api a localhost:8000)
cd frontend && npm ci && npm run dev
```

## Compuertas de calidad

`scripts/ci.sh` ejecuta todas; el workflow de CI solo llama a ese script.

| Compuerta | Comando | Falla cuando |
|---|---|---|
| Lint | `ruff check` / `oxlint` | patrones de estilo o de error |
| Tipos | `mypy --strict` / `tsc -b` | cualquier hueco de tipos |
| Tests | `pytest` / `vitest` | cambió un comportamiento |
| Paridad de idiomas | `vitest` (`src/locales/locales.test.ts`) | `es.json` y `en.json` no tienen las mismas claves |
| Licencias libres | `scripts/license_gate.py` | una dependencia no es libre |
| Sin CDN | `scripts/no_cdn_check.py` | el bundle apunta a otro servidor |
| Sin secretos | `gitleaks` | una credencial llega al repositorio |
| Migraciones | job `migrations` de CI | subir o bajar de versión falla sobre PostgreSQL real |

## Estructura

```
backend/    App FastAPI: auth, bitácora, ingesta, análisis, reportes, workflow, sandbox, inventario
frontend/   React 19 + Vite, servido localmente, es/en, claro/oscuro
docker/     Stack de Compose (uno o dos servidores) e imágenes
docs/       Arquitectura, compuertas, modelo de amenazas, UI, inventario, despliegue, mockups, plan
tasks/      Un archivo por fase: objetivo, entregables, definición de terminado
scripts/    Compuertas propias (licencias, sin CDN), CI, dev.sh, auto-auditoría
rules/      Reglas Semgrep propias
```

La gobernanza, las convenciones y las reglas duras están en `CLAUDE.md`.

---

# English

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

## Status

- **v1.0.0** (tagged 2026-09-23), phases P0–P5: authentication, roles, audit
  trail, themes and i18n (P0); the audit pipeline and the institutional report
  (P1); findings triage and the versioned report editor (P2); the E1–E5
  workflow with deterministic briefs (P3); scaffolds, the sandbox and the
  mutation re-audit (P4); the software inventory with the local OSV + NVD
  mirror, the audit-log screen, the report's closing sections and the
  self-audit (P5).
- **Current version: 1.5.1.** Second cycle, in progress: PHP/Laravel done
  (phase 7a); asynchronous PDF export done (phase 8); ZIP ingest up to 1 GiB
  with an analysis progress bar done (phase 10); detection of backups,
  uploaded photos, `.env` files, keys and logs committed to the code done
  (phase 11); Java/Spring pending (phase 7b); user administration done
  (phase 6); 1.5.1 fixes a large tool report being lost or read short, closes
  analyses left stuck, and pins the tools by their SHA-256 digest.
- **Numbering:** a small change or correction bumps the third number, a
  completed phase the second, a change that breaks the API contract the
  first.
- The work plan is `docs/work-plan-reference.html`, distilled in
  `docs/development-phases.md`.

## Run it

**Production** (one server, or frontend and backend on different IPs,
PostgreSQL in a container or installed outside Docker, ports, requirements,
firewall, first administrator, backups):
**[docs/deployment/README.md](docs/deployment/README.md)**.

Quick try on one machine:

```bash
cp .env.example .env
# fill DIOPTRA_JWT_SECRET (32+ chars), POSTGRES_PASSWORD and DIOPTRA_APP_DB_PASSWORD:
#   openssl rand -base64 48
# (Compose interpolates them at load time, so even `docker compose build` wants the .env)
docker compose -f docker/docker-compose.yml up --build
```

The UI is on <http://localhost:8080> and the API behind the same origin at
`/api/v1`. The one-shot `migrate` service applies the migrations as the schema
owner before the API starts; the API and the workers connect as the restricted
`dioptra_app` role.

### Seed accounts (development only)

Seeding is refused when `DIOPTRA_ENV=prod`, and it never invents a password —
each one comes from the environment (`DIOPTRA_SEED_PASSWORD_<USERNAME>`), and
every seeded account must change it on first login.

```bash
docker compose -f docker/docker-compose.yml exec api python -m app.seed
```

| Username | Role | Does |
|---|---|---|
| `srosales` | admin | accounts, roles, projects |
| `mmarin` | analyst | runs analyses, triages findings, signs the report |
| `pperez` | developer | test plan, case design, writes the tests |

Usernames are initial + last name, lowercase, no dots.

### Development in one command (`scripts/dev.sh`)

```bash
scripts/dev.sh                 # API with hot reload on :8000, UI on http://localhost:5173
scripts/dev.sh seed            # also creates the three seed accounts
scripts/dev.sh workers         # a real queue: Valkey + the two RQ workers
scripts/dev.sh seed workers    # arguments combine
scripts/dev.sh reset workers   # WIPES the dev data (database, queue, uploads)
                               # and starts from zero with the accounts;
                               # asks you to type "delete" to confirm
```

It uses (or starts) the `dioptra-dev-pg` PostgreSQL container on
127.0.0.1:55432. By default the queue runs inline; `workers` swaps that for the
`dioptra-dev-valkey` broker on 127.0.0.1:56379 and the same `analysis` and
`reports` workers Compose runs. The vulnerability sync stays off, and the
accounts are printed at the end with their initial passwords. Requirements,
ports and details: [docs/deployment/README.md §11](docs/deployment/README.md#11-local-development-scriptsdevsh).

`scripts/self_audit.py` runs the committed tree through the platform's own
pipeline (the plan's last-day self-audit).

### Analysis tools

The `worker` service runs every tool inside the `dioptra-analysis` image with
`--network none` and hard CPU / RAM / pids limits; the API never touches the
Docker daemon. Two things are operator choices:

- **One data directory, same path on host and containers.** `DIOPTRA_DATA_DIR`
  (default `/var/lib/dioptra`, owned by uid 10001) holds each analysis' code,
  the OSV database, the vulnerability-dump spool and the finished PDFs (deleted
  once downloaded). `docker run` bind mounts are resolved by the host daemon,
  which is why the path must be identical on both sides.
- **Vulnerability data is local.** Run
  `scripts/osv_db_download.sh /var/lib/dioptra/osv` on a connected host (or
  copy that directory from one). Without it, OSV-Scanner is reported as a
  coverage gap in every report — the platform never queries a vulnerability
  service live.

## Develop piece by piece

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
| Types | `mypy --strict` / `tsc -b` | any type hole |
| Tests | `pytest` / `vitest` | a behaviour changed |
| Locale parity | `vitest` (`src/locales/locales.test.ts`) | `es.json` and `en.json` disagree on keys |
| Free licences | `scripts/license_gate.py` | a dependency is not free |
| No CDN | `scripts/no_cdn_check.py` | the built bundle points at another host |
| No secrets | `gitleaks` | a credential reaches the repository |
| Migrations | CI `migrations` job | upgrade or downgrade breaks on real PostgreSQL |

## Layout

```
backend/    FastAPI app: auth, audit log, ingest, analysis, reports, workflow, sandbox, inventory
frontend/   React 19 + Vite bundle, served locally, es/en, light/dark
docker/     Compose stack (one or two servers) and images
docs/       Architecture, gates, threat model, UI model, inventory, deployment, mockups, work plan
tasks/      One file per phase: objective, deliverables, definition of done
scripts/    Our own gates (licences, no-CDN), CI, dev.sh, self-audit
rules/      Our own Semgrep rules
```

Governance, conventions and hard rules live in `CLAUDE.md`.
