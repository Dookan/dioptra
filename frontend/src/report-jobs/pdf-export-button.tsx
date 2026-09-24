/**
 * "Descargar PDF": asks first, then hands the export to the worker (phase 8).
 *
 * The dialog says, before anything starts, that a large report takes minutes
 * and that no other PDF can be asked for meanwhile (`mmarin`, survey §4). While
 * the person has a job, the button is disabled AND says why beside itself —
 * the toast is never the only place that explains a disabled button.
 */
import { useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { useReportJobs } from './report-job-context';

interface Props {
  analysisId: string;
  label: string;
  className: string;
  /** The screen's own reasons (analysis not finished, no session). */
  disabled?: boolean;
  version?: number;
}

export function PdfExportButton({
  analysisId,
  label,
  className,
  disabled = false,
  version,
}: Props): React.ReactNode {
  const { t } = useTranslation();
  const { busy, start } = useReportJobs();
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const bodyId = useId();
  const noteId = useId();
  const note = useRef<HTMLSpanElement>(null);
  // Confirming disables the very button the dialog would return focus to, so
  // focus goes to the sentence that says why instead of falling to <body>.
  const [focusNote, setFocusNote] = useState(false);

  useEffect(() => {
    if (focusNote && busy) {
      note.current?.focus();
      setFocusNote(false);
    }
  }, [focusNote, busy]);

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

  return (
    <>
      <button
        type="button"
        className={className}
        disabled={disabled || busy}
        aria-describedby={busy ? noteId : undefined}
        onClick={open}
      >
        {label}
      </button>
      {busy && (
        <span id={noteId} ref={note} className="sub" tabIndex={-1}>
          {t('reportJob.blocked')}
        </span>
      )}
      <dialog ref={dialog} className="dialog" aria-labelledby={titleId} aria-describedby={bodyId}>
        <h3 id={titleId}>{t('reportJob.dialog.title')}</h3>
        <div id={bodyId}>
          <p>{t('reportJob.dialog.body')}</p>
          <p className="sub">{t('reportJob.dialog.oneAtATime')}</p>
        </div>
        <div className="actions">
          <button
            type="button"
            className="btn primary"
            onClick={() => {
              close();
              void start(analysisId, version).then((started) => {
                if (started) setFocusNote(true);
              });
            }}
          >
            {t('reportJob.dialog.confirm')}
          </button>
          <button type="button" className="btn ghost" onClick={close}>
            {t('reportJob.dialog.cancel')}
          </button>
        </div>
      </dialog>
    </>
  );
}
