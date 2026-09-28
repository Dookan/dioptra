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
- **The ingest panel is analyst/admin only** (2026-09-23): E1–E2 belongs to
  them (`docs/roles-and-permissions.md`), the server already refuses a
  developer, and the screen used to offer the upload to one AND tell them
  "Siguiente paso: sube el código" in the banner. The developer now gets the
  same "2 · El código" heading with one sentence saying an analyst uploads it,
  and a banner that names what they are waiting for. Asked by `mmarin`. The
  sibling case is NOT fixed: at the triage stage the banner still says
  "Confirma o descarta cada hallazgo" to a developer and to an admin, neither
  of whom may triage — it lands with the per-action role vocabulary named as a
  non-goal in `tasks/phase6-user-administration.md`.

## Descargar PDF — a job with a dialog and a toast (phase 8, 2026-09-23)

- **Supersedes the PDF half of the section below.** "Descargar PDF" (screen
  03) and "Exportar PDF" (screen 09) open a native `<dialog>` first
  (`report-jobs/pdf-export-button.tsx`) that says a large report can take
  several minutes and that no other PDF can be asked for meanwhile, with
  "Preparar el PDF" / "Cancelar". Confirming starts a worker job; DOCX,
  Markdown and the SBOM keep the synchronous busy state below.
- A **toast at the bottom right** (`report-jobs/report-job-provider.tsx`,
  mounted above every authenticated screen) follows the job: "Tu reporte está
  en cola" with how many are ahead — never "preparando" while it only waits,
  because with one worker a queued job is not being worked on — then
  "Estamos preparando tu reporte" with "Lleva m:ss" underneath, then "El
  reporte está listo · La descarga empezó", after which it closes itself in
  four seconds. A failure says why in plain words and offers "Cerrar". The
  word is **reporte**, the anchor's, not "informe". Accessibility, from the
  panel: only the status sentences sit in the `role="status"` region; the
  clock is `aria-hidden` beside it, because inside it would be re-announced
  every two seconds for minutes; and the empty toast is VISUALLY hidden,
  never `display:none`, so the region is in the accessibility tree before its
  first sentence. The dialog carries `aria-describedby` on its two
  sentences, and confirming moves focus to the "why is this disabled" note,
  since the dialog would otherwise return it to a button it just disabled.
- **Where, and the trade-off**: `mmarin` chose the toast over a strip under
  the tabs bar (survey §7.5). A toast is easier to miss and this one blocks
  the person's next PDF, so it is **not dismissible while queued or
  running**, and every disabled PDF button says why beside itself ("Ya estás
  preparando un PDF; podrás pedir otro cuando termine") — the toast is never
  the only place that explains a disabled button. Below 520 px it spans the
  width at the bottom.
- **Feedback starts at the click, not at the server's answer** ("Pidiendo tu
  reporte…", button disabled): behind a real worker the POST returns in
  milliseconds, but with `dev.sh`'s inline queue it lasts the whole render and
  the screen said nothing for ~50 s (`mmarin`, 2026-09-23).
- A reload, or a new login, asks `GET /api/v1/report-jobs/mine` once and
  recovers the toast — and the download of a PDF that finished while the tab
  was closed.
- Recorded deviations: the anchor has no modal and no toast anywhere; both
  follow the date popover's elevation (a surface step up, the anchor's float
  shadow). The dialog's backdrop is `rgba(0, 0, 0, 0.35)` — a literal, like
  that shadow, because the token set has no scrim; `mmarin`'s call whether it
  becomes a token. **Not checked on screen yet**: no test applies
  `components.css` (see the note under "Hallazgos (E3) — código de
  terceros"), so the toast's placement in both themes needs the same look.

## Descargas del reporte (screen 03) — 2026-09-23

- The export buttons carry a **busy state**: the one in flight reads
  "Preparando…", every download button is disabled while it runs, and a
  `role="status"` line underneath says the document is being composed and that
  a large PDF can take close to a minute.
- **Why it exists, measured**: the server composes the PDF with WeasyPrint,
  which took **58 s** on a real Laravel analysis (687 findings, 1 369 SBOM
  components; the HTML of the same report takes 0.5 s). The buttons used to
  stay enabled and say nothing, so the screen read as frozen — and a second
  click stacked another minute of CPU-bound server work on top of the first.
  Reported by `mmarin`.
- **The anchor draws no download buttons on screen 03 at all** — mockup 09 is
  the only screen with exports ("Exportar PDF / DOCX / Markdown"). These
  buttons are a P1 addition, so there is nothing to match them against; the
  busy state follows the product's own patterns instead.
- The hint uses `.sub`, not the anchor's `.hint`, which is the element mockup
  03 uses for exactly this kind of "how long will this take" line. `--hint`
  resolves to `--t3`, recorded in `components.css` as below AA at that size,
  and this text is load-bearing — so `.sub` on purpose. It shows for the PDF
  only: the other formats are sub-second.
- The wait itself is not a UI problem and is NOT fixed here: rendering is
  synchronous in the request. **Profiled on the same report** (2026-09-23):
  Jinja 0.45 s, WeasyPrint parse 2.1 s, `write_pdf` the rest — 70 s of layout
  plus 21 s of PDF writing under cProfile, over a **516-page** document. No
  pathology and nothing of ours in the hot path: the cost is proportional to
  the document. So the two real levers are making the report smaller (422 of
  those 687 findings are in `vendor/`) or moving the export to the RQ queue.
  Both are `mmarin`'s call. nginx already allows it: `proxy_read_timeout 600s`
  on `/api/`, so the request is not cut off.

## Subida del ZIP (screen 03) — phase 10, 2026-09-28

- "Subir y analizar" now shows a **progress bar under the form** while the
  archive is sent (`.progress.upload`: the anchor's `.pbar` / `.pfill`, full
  width, stepped `w0`…`w100` classes because the CSP forbids inline styles).
  The sentence "Subiendo el archivo…" is announced by a visually hidden
  `role="status"` region (`.srlive`) that is mounted EMPTY with the form and
  only changes its text — a region inserted already filled is the
  announcement screen readers drop (phase-8 rule; the panel caught the first
  version doing exactly that). The visible bar, its copy of the sentence and
  the percentage are `aria-hidden`; the bar is floored to the same 5-point
  steps as the number so it never reads "done" beside "97 %". At
  100 % the sentence becomes "Archivo recibido. Preparando el análisis…",
  which is true: the server answers once the last byte is on disk.
- **Why** (`tasks/phase10-survey.md`): the cap went from 200 MiB to 1 GiB, and
  a GiB on a slow LAN is minutes of sending. `fetch` reports no upload
  progress, so this one request uses `XMLHttpRequest`
  (`api/client.ts::apiUploadFile`).
- A too-large refusal names the limit ("pesa más de 1024 MiB"); nginx's own
  HTML 413, which the API never sees, reads as "too large" rather than as an
  internal error.
- A hostile or broken archive is now refused by the WORKER, so it shows on the
  analysis card, not under the button: the card says the same plain sentence
  the upload used to show (`errors.ingest.*`), then the code.
- **The analysis has its own bar too** (`mmarin`, same day): while an
  analysis RUNS, its card shows "Paso N de 8: <what the step does in plain
  words, then the tool's name>", a bar of steps done and "Lleva m:ss". The
  bar counts steps, not time — one tool is most of a long run — so the step is
  named and the clock shown; the card's own `.srlive` region, mounted while
  the analysis is still queued, announces each step, and the visible block
  and its ticking clock are `aria-hidden`. Both bars share `.progress.wide`.
  An acquisition says "descomprimiendo el código" for a ZIP and
  "clonando el repositorio" for git; a step the screen has no words for shows
  only "Paso N de M".
- Recorded deviation: mockup 03 draws no upload progress; it follows the
  anchor's own `.progress` element from screens 02, 04 and 09.
- **Checked on screen by `mmarin`, 2026-09-28** — both bars, the upload's and
  the analysis', read right. No test applies `components.css`, so a change to
  `.progress.wide`, `.srlive` or the clock needs the same look again.

## Registro (screen 03) — 2026-09-23

- "Fecha de instalación" is our own calendar picker
  (`components/date-picker.tsx`): a field that opens a month grid (Monday
  first, month and weekday names from `Intl` in the UI language, today
  outlined, the chosen day filled with the accent, days after today disabled,
  "Hoy" / "Borrar la fecha" underneath, arrows / Enter / Escape on the
  keyboard). The value it hands over is ISO `YYYY-MM-DD` built from LOCAL
  calendar parts, displayed formatted for the locale; the server stores a
  `date` and refuses text or a future date
  (`errors.projects.installedAtInFuture`); the report and the screens format
  it themselves. No library: tokens only, both themes — the popover sits a
  surface step above the panel it opens in, because `--s1` on `--s1` left the
  hairline as the only elevation cue.
  The day cells are plain buttons in a labelled group, NOT
  `role="grid"`/`gridcell`: that contract needs `role="row"` owners, and a
  gridcell role on a button hides that it is activatable. The field names
  itself with its label AND its value (`aria-labelledby`), so the chosen date
  is announced rather than only the label. Both glyphs on these screens are
  inline SVG, never a font character, so neither can land as a tofu box.
  The anchor draws the field as plain text. Asked by `mmarin` ("un selector
  de fecha bonito e intuitivo", replacing the native input of the same day).

## Login (screen 01) — deviation recorded 2026-09-23

- The password field has an eye glyph INSIDE the input, on the right
  (`components/password-input.tsx`: an inline SVG button, icon-only, named
  "Mostrar la contraseña" / "Ocultar la contraseña" through `aria-label` and
  `title`, with `aria-pressed`) that the anchor does not draw. It only
  flips the input's `type`, i.e. how the browser PAINTS the characters: the
  value stays in React state and is sent in the same POST body as before,
  nothing goes into the URL, a header or storage, and the field is re-masked on
  every submit so a typed password is not left readable behind a spinner.
  The forced password-change screen uses the same component on both of its
  fields, each with its own eye. Asked by `mmarin`.

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
- **Diseño de casos, second pass (2026-09-24, `mmarin`)** — recorded
  deviations from screen 06: `.cols.design` is two EQUAL columns, not the
  anchor's `380px 1fr` — the anchor draws a toy diagram that fits 380 px,
  a real function's is 690 px or wider and the developer saw a sliver of it
  behind two scrollbars; the diagram frame is as tall as the window allows
  (`max-height` relative to the viewport) and scrolls inside itself with
  token-coloured scrollbars (the `.scrollpane` recipe); node labels are
  WRAPPED by the server to fit their shape (`PlacedNode.lines`, bounded lines
  and characters per shape) with the full label as the hover `<title>`, and
  loops get the same diamond overhang as decisions; the "sí"/"no" edge labels
  sit on each branch's own horizontal run. The picture is still ours and the
  brief is still computed from the AST. **Needs an on-screen look in both
  themes**: text scaled down on a very wide diagram, diamonds at the frame's
  edge, the frame's scrollbar against the page's on a laptop-height window.
- **The stage buttons move the person on** (2026-09-24): after the server
  accepts "Guardar plan y diseñar los casos →", "Pasar a escribir los tests
  →", "Pasar a ejecutar y medir →" and the E7 → E8 advance, the screen
  navigates to the one the arrow names. Only after the server's answer: a
  refused transition stays on the screen with its reason.
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

## Plan de pruebas (E4) — búsqueda y el tope dicho en voz alta, 2026-09-23

- The ranking shows at most `MAX_ROWS` (200) of the measured functions, and
  the screen now **says which**: "Mostrando 200 de 5000 funciones medidas. Usa
  el buscador para llegar a las que no caben." When nothing was cut it says so
  too, so the sentence is never a warning the reader learns to ignore.
- A **search box** above the ranking filters by path or function name. The
  filter is the SERVER's (`GET …/risk-matrix?q=`), applied before the cap and
  debounced by 250 ms — a client-side `rows.filter` could only narrow what
  already survived truncation, which is precisely the function the developer
  cannot see.
- **Why** (phase-7a walk, 2026-09-23): a real Laravel application measured
  **5 000 functions**, and the 200 highest-scoring were ALL hand-vendored
  JavaScript (`public/Datatables/…`, minified jQuery). The developer could not
  reach a single function of their own team's code through the UI, and nothing
  on screen said anything was missing. The ranking also puts dependency
  directories last now, but that alone does not fix it: a library copied into
  `public/` by hand is not in a dependency directory and no path rule can know
  it is one. The count and the search box are what fix it.
- The field wears the anchor's `.input` contract; `.filterbar` carries layout
  only. Authoring a second text-field style here is what first produced a
  search box whose fill was `--s1` on `--ground` — **1.02:1** in light mode,
  i.e. no visible boundary — beside a rationale textarea with the anchor's
  metrics on the same screen (mockup-fidelity, 2026-09-23). The count line
  needed `.filterbar + .sub`, because `.sub` deliberately has no bare rule.
- The selection is held as a map of the chosen functions, NOT as keys
  intersected with what is on screen: the filter changes `rows`, so the old
  shape silently dropped a ticked function from the saved plan when the
  developer searched again (invariant checker, 2026-09-23).
- Recorded deviation: mockup 05 draws the ranking with no search box and no
  count, because the anchor's example project has a handful of functions. This
  follows the product's own `.sub` + `role="status"` pattern, like the findings
  pager.

## Hallazgos (E3) — paginación, 2026-09-23

- The list paints **25 findings at a time**, with a pager underneath
  (`.pager`: previous / next and a `role="status"` line saying which page and
  how many of how many). The filters apply BEFORE the page, and changing any
  filter returns to the first page — otherwise a narrowed list leaves the
  reader on a page that no longer exists.
- **Why, measured**: a real Laravel application produced **687 findings** and
  the screen rendered a card for every one of them, which froze the browser.
  The server was never involved — it answered the whole list in **0.08 s** and
  refused the stage transition in under a millisecond. `mmarin` reported it
  from real use (2026-09-23).
- Paging is **client-side**: the payload is one request (0.6 MiB for 687, and
  `max_findings_per_analysis` caps an analysis at 2 000, so ~1.8 MiB worst
  case). **Revisit trigger**: raising that cap, or a browser reaching the API
  over a slow link.
- **Card harmony and the detail panel** (same report, `mmarin`): long titles
  and long paths overflowed their card, so no two cards were the same height,
  and because the detail sits at the TOP of the right column, clicking a card
  near the bottom of the list updated something off-screen — it read as
  "nothing happened", with an empty column beside the scroll. Fixed in
  `.cols.findings`: the title and the path are each clamped to two lines AND
  floored at two lines (`line-height` pinned so the reserve is exact), with
  `overflow-wrap: anywhere` because paths and rule ids have nowhere to break;
  the detail panel is `position: sticky` so it follows the list, scrolling
  inside itself rather than adding a second page scrollbar. Below 900 px the
  layout is one column and the panel is deliberately NOT sticky — it would
  cover the list it belongs to.
- **Two independent panes, not a scrolling page** (`mmarin`, same session,
  after seeing it): "primero baja la barra de la página y después bajan las
  tarjetas — deberían bajar las tarjetas si tengo el puntero sobre la caja de
  las tarjetas". The first attempt put the scroll on the DETAIL panel and left
  the page scrolling the list, which is backwards for a master-detail screen.
  Both columns are now capped to the viewport and scroll inside themselves: the
  card list is the scroll region (`.listpane > .list.scrollpane`), the pager
  sits OUTSIDE it so it does not scroll away, and the detail keeps its own.
  Below 900 px the panes stack, nothing is sticky or capped, and the page
  scrolls — which is right when there is no second column to scroll against.
- **A scroll region has to look like one** (`mmarin`, same session): sticky and
  internally scrollable was not discoverable — nothing said the box scrolled on
  its own. `.scrollpane` gives it a thin token-coloured scrollbar
  (`scrollbar-color` for Firefox, `::-webkit-scrollbar` for Chromium; no new
  colour, `--line-strong` at rest and `--t3` on hover), firms the border on
  hover and `:focus-within`, and carries the same `--acc` focus ring every
  other focusable surface uses. It is also an **accessibility fix, not only a
  visual one**: a scrollable region that is not focusable cannot be scrolled by
  keyboard, so the panel takes `tabIndex={0}` and an `aria-label`
  (`findings.detailLabel`) — which is what makes the `<section>` a named region
  rather than an anonymous box, announced when the reader tabs into it.
- Recorded deviation: mockup 04 draws a short list and no pager, so there is
  nothing to match this against; it follows the product's own button and
  `.sub` patterns. The pager uses `.sub` rather than `.hint` for the same
  reason the download hint does — `--t3` is below AA at that size and this
  line tells the analyst where they are.

## Hallazgos (E3) — código de terceros, 2026-09-23

- The screen has **two lists**, both in the LEFT pane. The working queue holds
  the findings of the audited project's OWN code; at the foot of the same pane,
  a collapsed `<details class="panel deps">` — "Hallazgos en código de terceros
  (N)" — holds the SAST and secret findings the platform found inside a dependency directory (an SCA finding and, since phase 11, a sensitive artefact stay in the queue wherever they sit).
  It sits inside the pane rather than after the grid **on purpose**: the detail
  panel is `sticky` only within `.cols.findings`, so a section placed after the
  grid would update a detail that had already scrolled off above — which is the
  exact "parece que no pasa nada" complaint this file records as fixed for the
  queue. Open, it shares the pane's height with the queue and scrolls on its
  own; below 900 px both caps are lifted and the page scrolls, because a nested
  scroll on a phone traps the reader's gesture. The second list has its own
  pager, the same cards, and **no verdict form**: selecting one shows the
  detail with a `.sub.warn` sentence saying it comes from a dependency, that it
  is in the report and in the inventory, and that it is not the analyst's to
  adjudicate.
- The queue's "next step" banner counts only the queue, so "Te faltan N
  hallazgos por revisar" is now a number the analyst can actually reach. The
  third-party count is NOT in that banner — it is on the section's own summary
  line ("Hallazgos en código de terceros (N)"), which is always on the page.
  Deliberate: the banner states the next STEP, and reading dependency findings
  is not a step. Revisit if an analyst reports being surprised by what the
  report printed.
- **Why** (`mmarin`, 2026-09-23, from real use): a Laravel application produced
  687 findings, **430 of them inside `vendor/`** — Symfony, Laravel and DomPDF
  source the analyst can neither fix nor sensibly write 430 separate
  justifications about. The queue is now 257. Nothing was suppressed: the
  findings are still produced, stored, exported in every format and carried by
  the inventory; what changed is only who is required to adjudicate them.
- The section is collapsed by default and says its count on the summary line,
  because "invisible" and "not in the queue" are different things and the
  analyst has to be able to see what the report will print.
- **Checked on screen by `mmarin`, 2026-09-23.** Worth writing down because no
  test can: `components.css` is imported only by `main.tsx`, which the Vitest
  suite never loads, jsdom applies no stylesheet and nothing asserts a computed
  style. Every CSS claim in this file — the two scroll panes, the token-coloured
  scrollbar in both themes, the two-line clamp and floor, the height the two
  lists share when the dependency section opens — rests on that look, not on
  CI. A change to these rules needs the same look again.

## Verificación (E7) — 2026-09-23

- A run whose mutation could not be measured carries one extra sentence on its
  result card (`verify.mutationNotMeasured`, `.sub.warn`): the mutation tool
  works only inside classes, so a free PHP function yields no mutant, and the
  line says explicitly that an empty survivor list here does not mean the
  tests killed them. `.caserow .sub.warn` is its own descendant rule —
  `warn` alone matches nothing in `components.css`, so without it the sentence
  would render identically to the measurements above it.
- It states the TOOL's limit, never the developer's. Background:
  `docs/workflow-gates.md` → E7 re-audit rules, and `tasks/phase7a-php.md`.

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
