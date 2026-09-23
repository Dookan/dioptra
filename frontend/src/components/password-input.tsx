/**
 * A password field with an eye glyph inside it that shows or hides the text.
 *
 * The toggle only flips the input's `type`, which changes how the BROWSER
 * paints the characters. Nothing else changes: the value stays in React
 * state, it is submitted in the same request body as before, and it is never
 * written anywhere else. Revealing is an on-screen affordance, not a
 * transport decision — and it is reset to masked on every submit so a typed
 * password is not left readable behind a spinner.
 *
 * Known, accepted delta: while the field is `text`, a browser's own
 * session-restore store can capture its value on an unload, which it never
 * does for `password`. Nothing new reaches the network, this app's storage or
 * the DOM; only "reveal, then reload without submitting" is exposed, and the
 * submit-time re-mask covers the normal path.
 */
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

interface Props {
  id: string;
  name?: string;
  autoComplete: 'current-password' | 'new-password';
  value: string;
  onChange: (value: string) => void;
  /** Bumped by the owner to force the field back to masked (e.g. on submit). */
  maskSignal?: number;
}

/** An open eye; with `off`, the same eye crossed out. Stroke follows `currentColor`. */
function EyeGlyph({ off }: { off: boolean }): React.ReactNode {
  return (
    <svg
      className="eye-glyph"
      viewBox="0 0 24 24"
      width="18"
      height="18"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z" />
      <circle cx="12" cy="12" r="3" />
      {off && <path d="M4 4l16 16" />}
    </svg>
  );
}

export function PasswordInput({
  id,
  name,
  autoComplete,
  value,
  onChange,
  maskSignal = 0,
}: Props): React.ReactNode {
  const { t } = useTranslation();
  const [revealed, setRevealed] = useState(false);
  const [seenSignal, setSeenSignal] = useState(maskSignal);
  // Re-mask whenever the owner bumps the signal (derived state, no effect).
  if (seenSignal !== maskSignal) {
    setSeenSignal(maskSignal);
    setRevealed(false);
  }
  const action = revealed ? t('password.hide') : t('password.show');

  return (
    <div className="password">
      <input
        id={id}
        className="input"
        name={name}
        type={revealed ? 'text' : 'password'}
        autoComplete={autoComplete}
        autoCapitalize="none"
        spellCheck={false}
        required
        value={value}
        onChange={(event) => {
          onChange(event.target.value);
        }}
      />
      {/*
       * Icon-only, so the accessible name IS the label; `title` repeats it as a
       * tooltip. The name names the ACTION and flips with the state, so there is
       * deliberately no `aria-pressed`: a flipping name plus a pressed state
       * describe opposite things and a screen reader would read them together
       * ("Ocultar la contraseña, presionado").
       */}
      <button
        type="button"
        className="eye"
        aria-label={action}
        title={action}
        aria-controls={id}
        onClick={() => {
          setRevealed((current) => !current);
        }}
      >
        <EyeGlyph off={revealed} />
      </button>
    </div>
  );
}
