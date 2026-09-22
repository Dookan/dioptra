# UI model

> **Status: DESIGN SURFACE — tokens, both themes and i18n are built (P0, `frontend/src/theme/`, `frontend/src/locales/`); the screens are the target.** Visual anchor:
> @docs/mockups/index.html (10 screens, approved 2026-08-17).

## Principles (from the approved mockups)

1. **The user always knows where they are** — the workflow stepper is visible
   on every workflow screen and uses NAMES (Registro, Código, Análisis, Plan,
   Diseño, Tests, Verificación, Reporte), never E-codes.
2. **Next step always visible** — every screen opens with a "siguiente paso"
   banner stating what remains and what it unlocks.
3. **Plain language, zero jargon** — findings are explained as "¿Qué
   encontramos?" / "¿Cómo corregirlo?"; mutation testing is "rompimos el
   código a propósito; un buen test debe fallar". Buttons say what they do
   ("Es real — incluir en el reporte").
4. **Friendly, sober density** — greeting + avatars with initials, progress
   bars with percentages, no log consoles outside Bitácora.
5. **Offline is visible** — the inventory panel always shows the date of the
   last vulnerability-database update; nothing in the UI implies a live
   lookup.

## Screens added for the work plan (2026-08-28)

The 10 screens approved 2026-08-17 predate the work plan v1.0 (2026-08-21).
Added to `docs/mockups/index.html` on 2026-08-28, same tokens and principles:

- **Inventario** (screen 11, P5): tab "Inventario" in the tabs bar of every
  screen; statistics panel — components outdated / vulnerable, by severity,
  project, license, trend between versions; the last vulnerability-database
  update date always visible; buttons say what they do ("Descargar SBOM
  (CycloneDX)", "Descargar CBOM", "Descargar CSV", "Actualizar la base
  ahora", "Importar base de vulnerabilidades").
- **Reporte (E8)**: sections "Inventario" and "Anexos (diagramas, tests,
  SBOM/CBOM)" in the section list.
- **Diseño de casos (E5)**: the flow diagram is rendered Mermaid, with its
  editable Mermaid text underneath; the brief is computed from the code, not
  from the edited diagram, and the screen says so.

## Phase 1 deviations from the mockups (recorded 2026-09-21)

- **"Proyectos" tab** (`frontend/src/components/app-shell.tsx`): the mockups
  keep the project cards on *Inicio* and have no Proyectos tab. P1 ships a
  separate list + E1 form because the home of screen 02 (cards with progress)
  needs P2/P3 data. Decide at P2 whether the cards fold back into Inicio.
- **Status bar** (avatar · `mmarin · Analista` · "Paso N de 8" · version in
  mono) of screens 02–11 is not in the shell yet; it lands with the first
  workflow screen of P3, which is where "Paso N de 8" gets a meaning.
- **Drop zone** of screen 03 "2 · El código" (`.drop`, dashed accent) is a
  native file input in P1; the buttons say what they do ("Subir y analizar" /
  "Clonar y analizar"). The drag-and-drop affordance is deferred to P2.

## Tokens (frontend/src/theme/tokens.css — single source)

Light: ground `#FAFAF7`, surface `#FFFFFF`/`#F1F4F1`/`#E7EDE8`, line
`#E3E7E2`/`#C9D2CB`, ink `#1C2420`, muted `#5C6B62`, accent `#1F5E3C`,
err `#B3261E`, warn `#96660A`, info `#2F6DB3`.
Dark: ground `#121714`, surfaces `#1A211C`/`#202923`/`#27332B`, line
`#2A332D`/`#3A4740`, ink `#E8EDE9`, muted `#9AA89F`, accent `#7CC79A`,
err `#F2867F`, warn `#E0A94E`, info `#85B4E8`.
Radii: frames 14, cards 12, buttons 9, badges 5. Borders 1px hairline.

## Rules

- Both themes ALWAYS; every color through tokens; no literal colors in
  components.
- i18n: `es.json` (default) and `en.json` with CI-checked key parity; no
  visible string literals in components.
- Usernames rendered as initial + lastname (`mmarin`); avatar = two initials.
- All fonts and libraries bundled locally — the mockup note applies: no CDN.
- Mockup-fidelity gate: `dioptra-mockup-fidelity` compares implementation against
  @docs/mockups/index.html tokens, spacing, copy tone, and both themes.
