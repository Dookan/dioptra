# UI model

> **Status: IN_PROGRESS — tokens, both themes and i18n (P0), the projects screens (P1), the findings / report screens (P2), the E4 plan screen with the status bar, the E5 design screen (P3, 2026-09-22) the E6 test-writing screen and the E7 verification screen (P4, 2026-09-22), the Inventario and Bitácora screens (P5, 2026-09-22) are built.** Visual anchor:
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
  from the edited diagram, and the screen says so. (Rendering deviation
  recorded under "Phase 3 screens" below: the picture is our own SVG, the
  Mermaid text stays as text.)

## Phase 1 deviations from the mockups (recorded 2026-09-21)

- **"Proyectos" tab** (`frontend/src/components/app-shell.tsx`): the mockups
  keep the project cards on *Inicio* and have no Proyectos tab. P1 ships a
  separate list + E1 form because the home of screen 02 (cards with progress)
  needs P2/P3 data. Decide at P2 whether the cards fold back into Inicio.
- **Status bar** (avatar · `mmarin · Analista` · "Paso N de 8" · version in
  mono) of screens 02–11 — built in P3 (`app-shell.tsx`, shown whenever the
  route names an analysis; the step is `analysis.stage`).
- **Drop zone** of screen 03 "2 · El código" (`.drop`, dashed accent) is a
  native file input in P1; the buttons say what they do ("Subir y analizar" /
  "Clonar y analizar"). The drag-and-drop affordance is deferred to P2.

## Phase 2 screens (2026-09-22)

- Routes: `#/projects/:id/analyses/:aid/findings` (screen 04) and
  `#/projects/:id/analyses/:aid/report` (screen 09). The tabs bar shows
  Hallazgos and Reporte only when the route names an analysis; Inicio and
  Proyectos stay (the Proyectos deviation above is still open).
- **Hallazgos (E3)**: the "next step" banner counts what is left ("Te faltan
  N hallazgos por revisar", "k de M" progress); filters by severity, OWASP,
  tool and file; left list of cards, right detail with "¿Qué encontramos?" /
  "¿Por qué importa?" / "¿Cómo corregirlo?" (the catalog prose the PDF
  prints); the two mockup buttons. The written reason is mandatory for BOTH
  verdicts (CLAUDE.md → Auth), not only for "No aplica" as the mockup's
  caption suggests — the field is one textarea, ten characters minimum, and
  the server enforces it. A developer sees the screen without the form.
- **Reporte (E8)**: sections list with ✓ (edited) / ✎ (editing) / · states,
  export buttons, the "Versión N · editada por …" line, sign form; preview of
  one section as text with "✎ Editar esta sección"; the severity bars of the
  executive summary; the version-control table. No rich text (see
  docs/report-format.md).
- Progress widths are stepped CSS classes (`w0` … `w100`,
  `frontend/src/components/width-class.ts`): the app's CSP is
  `style-src 'self'`, so inline styles never render.

## Phase 3 screens (2026-09-22)

- Route `#/projects/:id/analyses/:aid/plan` (screen 05 "Plan de pruebas");
  the tabs bar gains **Workflow**, which opens the current workflow screen
  (E4 in P3; E5–E7 as they land). The stepper everywhere now follows
  `analysis.stage` from the server; nothing is hard-coded per screen.
- **Closing a stage** is one component (`components/advance-stage.tsx`): a
  primary button that stays visible but disabled while the gate looks closed
  (principle 2), then asks for the written reason and calls
  `POST …/stage/advance`. The server's refusal (`errors.workflow.gate.*`) is
  shown in plain words. Buttons: "Empezar la revisión de hallazgos" (project
  card, E2 → E3), "Pasar al plan de pruebas" (findings banner, E3 → E4),
  "Guardar plan y diseñar los casos →" (plan screen, saves then E4 → E5).
- **Diseño de casos (E5)**, route `#/…/design` (screen 06): the diagram is
  our own class-only SVG drawn from the server's layout, not a Mermaid
  render (the CSP forbids Mermaid's inline styles — `tasks/phase3-survey.md`
  §7); the Mermaid text sits underneath, editable by the developer at E5 and
  always shown as text; the note "la consigna se calcula del código, no del
  diagrama" is verbatim. The Workflow tab opens Plan until E4 closes, then
  Diseño. Day 15 fills the screen: "La consigna te pide" under the diagram
  (the minimum case count, then one line per brief item with its id chip —
  branch with line and side, boundary with its values, error path, malicious
  case naming the finding); the right panel "Tus casos, con tus palabras" is
  a numbered list (`C1`, `C2`, …) of one-line cases, each with the brief
  items as toggle chips ("Cubre:"), "Añadir un caso", "Guardar mis casos", a
  plain-words line that says what is still uncovered or how many cases are
  missing, then "Aprobar mis casos" (enabled only when saved, complete and
  enough — the server re-checks) and the note "Al aprobar, el sistema te
  prepara los archivos de test con estos N casos ya nombrados". The banner
  counts "k de N funciones con casos aprobados" and holds the stage button
  "Pasar a escribir los tests →" (`AdvanceStage`, enabled once every planned
  function is approved). Deviation recorded: the mockup's one button "Aprobar
  mis casos y pasar a escribir los tests →" is two actions — approval is per
  function, the transition is per analysis and needs a written reason. The
  analyst sees the brief and the cases read-only. Recorded deviations
  from screen 06: a `<select>` above the title chooses the planned function
  (the anchor shows one function with no navigation); "función N de M" sits
  in the panel's mono line, not in the status bar; the drawing has a small
  colour semantics the anchor lacks (diamonds for decisions and loops, red
  border on throw/raise, dashed back edges) explained by a one-line legend
  under the frame; the start pill reads "inicio · <name>". The Mermaid text
  under the drawing is the server's interchange text (English tokens
  `true`/`false`/`Start`) while the drawing is translated — `mmarin`'s call
  whether the anchor's Spanish Mermaid sample should be matched.
- The findings screen hides the verdict form once the analysis has left
  E3 (the server refuses with `stage_locked`; the UI mirrors it).
- The status bar uses the mockups' long-form stage names (`statusbar.stage.*`:
  "Análisis y revisión", "Plan de pruebas", "Escribiendo tests"…) while the
  stepper keeps the short names (`stepper.*`) — two vocabularies, as in the
  anchor.
- The plan screen's plain-words reason per function ("Muy compleja (12
  caminos posibles) y con 1 hallazgo…") is i18n copy keyed on the server's
  `ccn` / `findings` numbers; the ranking and the score are the server's.

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

## Phase 4 screens (2026-09-22)

- Route `#/projects/:id/analyses/:aid/tests` (screen 07 "Escribir los tests
  (E6)"); the **Workflow** tab now opens Plan until E4 closes, Diseño until
  E5 closes, then Escribir tests.
- **Escribir los tests (E6)**: left panel "Lo que te prepara la plataforma" —
  the generated file shown in a `<pre>` as text, with the file name and the
  runner named in plain words, and the approved cases listed with a chip per
  case that turns green when the stored file has a body for it; the caption
  under each says "Ya escribiste algo en este caso" / "Todavía vacío", never
  "correcto". Right panel "Tu archivo de tests": one textarea that opens on
  the scaffold (the developer edits it, never a blank page), "Guardar mi
  archivo" and "Volver al andamiaje", plus the line "Se guarda como texto y
  no se ejecuta aquí". The banner counts "Llevas k de N casos escritos" and
  holds the stage button "Pasar a ejecutar y medir →" (`AdvanceStage`,
  enabled once every case has a body; the server re-checks).
- The screen states the platform's limit in its own subtitle: "Las
  aserciones las escribes tú: escribir la prueba es el aprendizaje." A
  syntax error in the stored file is said plainly ("hasta entonces ningún
  caso cuenta como escrito"), because that is exactly what the gate does.
- The analyst and the admin see the whole screen with the textarea read-only
  (they need the tests to judge the report) and no save button.
- Recorded deviations from screen 07: the anchor's progress bar ("2 de 5 casos
  listos · 40 %") is dropped — the count lives in the "next step" banner, which
  every workflow screen already has and the anchor for 07 does not; the
  anchor's `.ck` tick list becomes the `.chip` list (a different element, so
  the case id stays readable — the id is what the gate matches in the file);
  the anchor's syntax-highlighted code block becomes plain text, deliberately,
  because the audited function's name and the developer's titles are in it;
  a `<select>` plus "función N de M" is added, as on screen 06 (the anchor
  shows one function with no navigation); and `.pagehead` + `.nextstep` are
  added to a screen the anchor gives neither, as on 04, 05, 06 and 09. The
  anchor's ghost button "← Revisar mis casos" IS implemented and returns to
  the design screen.

- Route `#/projects/:id/analyses/:aid/verify` (screen 08 "Verificación (E7)");
  the Workflow tab reaches it once the stage is `verification`.
- **Verificación (E7)**: the subtitle states the method in the mockups' own
  words — "Tus tests corren dentro de un contenedor aislado, sin red. Después
  rompemos el código a propósito: un buen test debe fallar." The left column
  lists one card per planned function with a Pasa/Falla chip (solid accent for
  a pass, like E6's written chip), the coverage line in plain percentages, and
  then every reason the run failed as its own sentence: the surviving mutant
  with its line, the brief items not covered as id chips, the cases that
  assert nothing, the cases that failed. Nothing is shown as a score. The
  right column holds the two actions: "Ejecutar y medir" and, only when
  something failed, "Reabrir el diseño de las que fallaron" behind a written
  reason. The screen disables the button below ten characters; the FLOOR is
  the server's (`verify.reopen_design` → `clean_justification`, the same
  helper the stage transitions and the triage verdicts use), because the
  screen is never the enforcement.
- The copy says the stage does not move backwards ("La etapa no retrocede:
  sigues en Verificación"), because that is what the machine does.
- P5: each surviving mutant carries the sandbox's text for it (the diff for
  the first fifteen, the id for the rest) and, for the developer, a
  "Marcar como equivalente" button that opens a written-reason field (ten
  characters, the server's floor); the note under it says what an
  equivalent mutant is in plain words and that it is discounted on the next
  run. Mutants already excused are listed apart ("Mutantes ya justificados
  como equivalentes: N"). The analyst and the admin see every result and
  none of the three buttons.
- Mutant text and the sandbox's stderr come from the audited code's own
  tooling: both render as React text nodes, the stderr inside a `.codeblock`.
- The analyst and the admin see every result and neither button.
- Recorded deviations from screen 08: the anchor shows ONE function with two
  fixed questions side by side ("¿Probaste todo lo pedido?" / "¿Tus tests
  detectan errores de verdad?") in a `1fr 1fr` split; the plan has N
  functions, so the implementation lists one result card per function in a
  `1fr 340px` split with "Resultado por función" / "Qué puedes hacer". The
  anchor's coverage progress bar is dropped — the two percentages are a
  sentence instead. The anchor puts the "← Revisar mis casos" ghost button
  inside the banner; the implementation keeps the reopen in the right panel
  because it needs a written reason first, which does not fit a banner
  button. That last one is `mmarin`'s call to overrule.

## Phase 5 screens (2026-09-22)

- Routes `#/inventory` (screen 11 "Inventario") and `#/audit` (screen 10,
  its Bitácora half). The tabs bar shows **Inventario** and **Bitácora**
  after Reporte on EVERY route, as every tabs bar of mockups 02–11 does.
  Neither is a workflow screen: no stepper, no status-bar step.
- **Inventario**: `pagehead` with the totals sentence verbatim from the
  anchor ("N componentes en M proyectos. K tienen vulnerabilidades conocidas
  sin resolver y J están fuera de versión."); the info-bordered `nextstep`
  carries the local copy's date ("Base de vulnerabilidades: copia local del
  …", or "todavía no hay copia local", or "sin copia local y sincronización
  desactivada") and the two buttons, which open a written-reason field
  before enqueuing — "Actualizar la base ahora" is absent when the operator
  disabled the sync, and both are absent for the developer; the three
  `cards` (open CVEs by severity and "no aplica" count; outdated with the
  stepped progress bar and the note "frente a la última versión conocida en
  la copia local"; licences as chips + the CBOM line); `cols` 330px/1fr with
  "Por proyecto" rows (a row is a button that selects the project the four
  download buttons act on; the trend line is `ok`/`bad` through tokens) and
  the right panel "Componentes con vulnerabilidades abiertas" with the
  Todos / Altas / Sin resolver `radio`s filtering on the client, one
  `rowline` per match (severity letter in `.prio`, name, mono version,
  project, CVE · CVSS · corregido en · the analyst's justification when "No
  aplica"), the anchor's hint sentence verbatim, and the CBOM `checkline`s
  (✓ or ! in `.ck`, mono algorithm, primitive in plain words, path:line,
  "algoritmo débil"). Recorded deviations: a fourth download button
  "Descargar VEX" (the plan lists VEX as an export; the anchor shows three);
  the project row's version is "análisis N · date" — the platform has no
  semantic version of the audited system, the anchor's "v1.3" is
  illustrative; the "Usuarios" half of mockup 10 is not built (no endpoint,
  not in the plan's day table — `tasks/phase5-survey.md` §8).
- **Reporte (E8)**, recorded deviation: mockup 09 lists "Inventario (SBOM y
  CVE abiertos)" and "Anexos" among the sections; the built sections 7–10
  are composed from workflow rows and have no analyst prose, so the editor's
  list keeps only the six editable sections. Every export carries 7–10.
- **Bitácora**: one panel, the Hoy / Semana / Todo `radio`s become the
  `since` parameter; each row is `time · actor · sentence` with the target
  and the written justification in `.sub`; the sentence is an i18n key per
  action code, and an action the screen has no sentence for shows its code
  in mono, never a blank. The server scopes the rows by role; the subtitle
  says which scope the reader has.
