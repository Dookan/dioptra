/**
 * "Cancelar el análisis" (phase 12): one confirmation, no written reason.
 *
 * `mmarin`: fast and without friction. The dialog is the only guard against a
 * mis-click on a run that may have taken ten minutes, and it is one click. A
 * queued analysis is cancelled at once; a running one is stopped by its
 * worker within seconds, and the card says so meanwhile. The server decides
 * who may cancel (the creator, still an analyst, or an admin); this only
 * hides the button from the others.
 */
import { useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { ApiError } from '../api/client';
import * as api from '../api/projects';
import type { Analysis } from '../api/projects';
import { useAuth } from '../auth/auth-context';

function mayCancel(
  user: { id: string; role: string } | null | undefined,
  analysis: Analysis,
): boolean {
  if (analysis.status !== 'queued' && analysis.status !== 'running') return false;
  if (user === null || user === undefined) return false;
  if (user.role === 'admin') return true;
  return user.role === 'analyst' && analysis.created_by_id === user.id;
}

export function CancelAnalysis({
  analysis,
  onChange,
  onCancelled,
}: {
  analysis: Analysis;
  onChange: (analysis: Analysis) => void;
  /** Moves focus to a stable place on the card: this button may unmount. */
  onCancelled: () => void;
}): React.ReactNode {
  const { t } = useTranslation();
  const { user, accessToken } = useAuth();
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const bodyId = useId();
  const [busy, setBusy] = useState(false);
  const [errorKey, setErrorKey] = useState<string | null>(null);

  if (!mayCancel(user, analysis)) return null;

  function open(): void {
    const element = dialog.current;
    if (element === null) return;
    if (typeof element.showModal === 'function') element.showModal();
    else element.setAttribute('open', '');
  }

  function close(): void {
    const element = dialog.current;
    if (element === null) return;
    if (typeof element.close === 'function') element.close();
    else element.removeAttribute('open');
  }

  async function confirm(): Promise<void> {
    close();
    if (accessToken === null || busy) return;
    setBusy(true);
    setErrorKey(null);
    try {
      onChange(await api.cancelAnalysis(accessToken, analysis.id));
      onCancelled();
    } catch (error) {
      setErrorKey(error instanceof ApiError ? error.messageKey : 'errors.internal');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="row">
      {/* Stays enabled while the worker stops: a second click also closes a
          cancel whose worker died (the server sweeps first, survey §9.1). */}
      {/* Never disabled in flight: disabling the element the dialog returns
          focus to drops focus to <body>. The busy guard ignores a second
          confirm, and the server answers a repeat the same way. */}
      <button type="button" className="btn ghost" onClick={open}>
        {t('analysis.cancel.button')}
      </button>
      {errorKey !== null && (
        <span className="alert inline" role="alert">
          {t(errorKey)}
        </span>
      )}
      <dialog ref={dialog} className="dialog" aria-labelledby={titleId} aria-describedby={bodyId}>
        <h3 id={titleId}>{t('analysis.cancel.title')}</h3>
        <p id={bodyId}>{t('analysis.cancel.body')}</p>
        <div className="actions">
          <button type="button" className="btn primary" onClick={() => void confirm()}>
            {t('analysis.cancel.confirm')}
          </button>
          <button type="button" className="btn ghost" onClick={close}>
            {t('analysis.cancel.back')}
          </button>
        </div>
      </dialog>
    </div>
  );
}
