# UI model

> **Status: DESIGN SURFACE — not yet implemented.** Visual anchor:
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
