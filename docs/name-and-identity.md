# Name and identity

> **Status: DECIDED 2026-08-17 by `mmarin`.** Supersedes the working title
> "Caja Blanca Studio". Applied across the repository in the same session, before
> the first commit.

## The name

**Dioptra** (Greek διόπτρα, "the thing you see through", from διά *through* +
ὄψις *sight*).

The dioptra is the surveying instrument described by Hero of Alexandria in the
first century: a sighting tube on a graduated mount, used to level aqueducts,
align tunnels dug from both ends, and measure angles against a fixed reference.
It is the direct ancestor of the theodolite.

## Why this name

Three reasons, in the order that decided it.

1. **You look through it.** White-box analysis is exactly that: the instrument
   does not bounce off the surface of the system, it passes through it. The
   product's own premise is legible in the etymology, without the name having to
   say "caja blanca" out loud.
2. **It measures against a reference.** A dioptra is useless on its own; it
   works by comparing what you see to a datum. That is the whole platform —
   findings against CWE/OWASP, coverage against the test brief, a test against
   the mutant that should have killed it. The factory has no standards; the
   instrument exists to hold work against one.
3. **An instrument does not judge the builder.** It shows the deviation and
   leaves the correction to the person. That is the tone the platform needs to
   be adopted rather than resented: this is transitional tooling whose purpose
   is to install a habit, not to grade people. The same reasoning ruled out
   names built on judgement or surveillance.

A practical fourth: a Spanish speaker reads and spells it correctly at first
sight, and it recalls *dioptría*, which already carries the idea of lenses and
correction.

## How to write it

- **Dioptra**, capitalised, no accent, no article, never translated, in both
  language versions of the UI and in reports.
- Never "Dioptra Studio", "Dioptra Platform" or any suffix. The bare noun is
  the name; a suffix would make it sound like a product line.
- Pronounced *DIOP-tra*.
- Brand mark: **`DP`**, two letters, in the `brandmark` element — same shape and
  radius as the anchor mockups.
- **"Análisis de caja blanca" remains the name of the TECHNIQUE**, never of the
  product. Report covers keep their institutional title ("Análisis de Caja
  Blanca — <sistema>"); the platform is only ever credited as Dioptra.

## Where the name appears in code

Single authoritative list. Anything not on it MUST NOT embed the product name.

| Surface | Value |
|---|---|
| Environment prefix | `DIOPTRA_` (`DIOPTRA_JWT_SECRET`, `DIOPTRA_ENV`, …) |
| Compose project / images | `dioptra`, `dioptra-api`, `dioptra-frontend` |
| PostgreSQL roles and database | `dioptra` (owner, runs the migrations from the one-shot `migrate` service), `dioptra_app` (runtime role of the API and the worker, `docker/initdb/01-runtime-role.sql`), database `dioptra` |
| Container user | `dioptra` (uid 10001, never root) |
| Python / npm package names | `dioptra-backend`, `dioptra-frontend` |
| Application logger | `dioptra` and its children, one per module: `dioptra.bootstrap`, `dioptra.inventory.import`, `dioptra.inventory.sync`, `dioptra.notify`, `dioptra.pipeline`, `dioptra.process`, `dioptra.queue`, `dioptra.reports`, `dioptra.reports.jobs`, `dioptra.seed`, `dioptra.sweep`, `dioptra.verify` (`backend/tests/test_loggers.py` keeps this row equal to the code) |
| Refresh cookie | `dioptra_refresh` |
| JWT issuer claim | `dioptra` |
| Browser storage keys | `dioptra.theme`, `dioptra.language` |
| Append-only trigger functions | `dioptra_audit_log_append_only()`, `dioptra_report_version_signed_immutable()` |
| Review panel agents | `.claude/agents/dioptra-*.md` |
| i18n keys | `app.name`, `app.brandInitials` in `es.json` / `en.json` |
| Browser tab title | `Dioptra` in `frontend/index.html` |
| Favicon | `frontend/public/favicon.svg` — the `DP` mark, `aria-label="Dioptra"` |
| Development helpers | `dioptra-dev-pg` (the development PostgreSQL container), `dioptra-dev-valkey` (the development broker of `scripts/dev.sh workers`, 127.0.0.1:56379), `~/.cache/dioptra-dev` (their data directory) — `scripts/dev.sh`; the self-audit project `dioptra-self-audit-<date>-<sha>` with system name `Dioptra` — `scripts/self_audit.py` |
| CycloneDX tool credit | `metadata.tools.components[].name = "Dioptra"` in the CBOM and VEX documents (`backend/app/inventory/documents.py`) |

Renaming again means changing this table first, then everything it lists; the
environment prefix and the cookie name invalidate running sessions, and the
PostgreSQL role requires a fresh volume or an `ALTER ROLE`.

## Alternatives considered

Recorded so the decision is not re-litigated from scratch.

Spanish round — instruments and roles:

| Candidate | Why not |
|---|---|
| Plomada | Strongest of the round: the tool that reveals whether something built by eye is straight. Lost only to Dioptra's added meaning of *seeing through*. |
| Testigo | Witness, and an engineering telltale, with "test" inside. Points at the report rather than at the measurement. |
| Atalaya | Watchtower: surveillance, not pedagogy. Wrong tone for a tool meant to be welcomed. |
| Diáfano | Transparency, but an adjective — no instrument, nothing to hold in your hand. |
| Lupa | Warm and instantly legible; too light beside a ministry seal. |
| Cotejo | Precise (formal comparison against a pattern) and cold. |

Greek round:

| Candidate | Why not |
|---|---|
| Gnomon | Best pure metaphor — the sundial rod that casts the shadow revealing the deviation, and in Greek also *judge* and *carpenter's square*. Rejected for the silent `g`: a name has to survive being spelled out over the phone. |
| Kanon | The measuring rod that gave us "canon" as norm. Excellent meaning, but it names only the standard, not the act of looking. |
| Elenchos | The Socratic cross-examination — conceptually the closest to mutation testing and to the platform's pedagogy. Rejected as unpronounceable in the factory. |
| Aletheia | Truth as un-concealment. Solemn, and an existing publication carries the name. |
| Stoa | The porch where discipline was taught; points at the habit, not at the instrument. |

## Revisit trigger

Reopen this file only if a trademark conflict appears in the deployment
jurisdiction, or if the platform outgrows white-box analysis to the point where
"seeing through" stops describing it.

Decided by **Moises Marin**.
