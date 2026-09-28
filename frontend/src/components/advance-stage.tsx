/**
 * The one way forward: a button that asks for the written reason and calls
 * `POST …/stage/advance`. The server checks the role and the gate; this
 * component only shows what the server answers (docs/workflow-gates.md).
 */
import { useId, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import * as api from '../api/projects';
import type { Analysis } from '../api/projects';
import { useAuth } from '../auth/auth-context';

/** Mirrors backend/app/core/text.py::MIN_JUSTIFICATION_CHARS — the server is the gate. */
const MIN_JUSTIFICATION = 10;

interface Props {
  analysis: Analysis;
  /** Button copy, e.g. "Pasar al plan de pruebas". */
  label: string;
  /** Whether the gate looks open from here; the server decides anyway. */
  ready: boolean;
  /** Why it is not ready yet, shown instead of the form. */
  blockedHint?: string;
  onAdvanced: (analysis: Analysis) => void;
  /** Runs before the transition (e.g. save the plan); a rejection cancels it. */
  beforeAdvance?: () => Promise<boolean>;
}

export function AdvanceStage({
  analysis,
  label,
  ready,
  blockedHint,
  onAdvanced,
  beforeAdvance,
}: Props): React.ReactNode {
  const { t } = useTranslation();
  const { accessToken } = useAuth();
  const reasonId = useId();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [errorKey, setErrorKey] = useState<string | null>(null);

  const collapsed = reason.split(/\s+/).filter(Boolean).join(' ');
  const tooShort = collapsed.length < MIN_JUSTIFICATION;

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (accessToken === null || tooShort) return;
    setBusy(true);
    setErrorKey(null);
    try {
      if (beforeAdvance !== undefined && !(await beforeAdvance())) return;
      onAdvanced(await api.advanceStage(accessToken, analysis.id, collapsed));
      setOpen(false);
      setReason('');
    } catch (error) {
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
    } finally {
      setBusy(false);
    }
  }

  if (!ready || !open) {
    // Visible but disabled while the gate looks closed: the next step is always
    // on screen (docs/ui-model.md → principle 2), never hidden.
    return (
      <div className="advance-cta">
        <button
          type="button"
          className="btn primary"
          disabled={!ready}
          onClick={() => {
            setOpen(true);
          }}
        >
          {label}
        </button>
        {!ready && blockedHint !== undefined && <span className="hint">{blockedHint}</span>}
      </div>
    );
  }

  return (
    <form
      className="advance"
      noValidate
      onSubmit={(event) => {
        void submit(event);
      }}
    >
      <div className="field">
        <label htmlFor={reasonId}>{t('workflow.advance.reasonLabel')}</label>
        <textarea
          id={reasonId}
          className="input textarea"
          rows={2}
          value={reason}
          placeholder={t('workflow.advance.reasonPlaceholder')}
          onChange={(event) => {
            setReason(event.target.value);
          }}
        />
        <span className="hint">{t('workflow.advance.reasonHint', { min: MIN_JUSTIFICATION })}</span>
      </div>
      {errorKey !== null && (
        <p className="alert" role="alert">
          {t(errorKey)}
        </p>
      )}
      <div className="actions">
        <button type="submit" className="btn primary" disabled={busy || tooShort}>
          {label}
        </button>
        <button
          type="button"
          className="btn ghost"
          onClick={() => {
            setOpen(false);
            setErrorKey(null);
          }}
        >
          {t('workflow.advance.cancel')}
        </button>
      </div>
    </form>
  );
}
