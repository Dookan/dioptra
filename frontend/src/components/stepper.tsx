/**
 * Workflow stepper. Stage NAMES, never E-codes (docs/ui-model.md → principle 1).
 * Mockup anchor: `.steps` in screens 05–09.
 */
import { useTranslation } from 'react-i18next';

import { STAGES } from './stages';

interface Props {
  /** Index of the current stage; everything before it is done. */
  current: number;
}

export function Stepper({ current }: Props): React.ReactNode {
  const { t } = useTranslation();
  return (
    <ol className="steps" aria-label={t('stepper.label')}>
      {STAGES.map((stage, index) => {
        const state = index < current ? 'done' : index === current ? 'now' : undefined;
        return (
          <li
            key={stage}
            className={state === undefined ? 'stp' : `stp ${state}`}
            aria-current={state === 'now' ? 'step' : undefined}
          >
            <span className="dot" aria-hidden="true">
              {state === 'done' ? '✓' : index + 1}
            </span>
            {t(`stepper.${stage}`)}
          </li>
        );
      })}
    </ol>
  );
}
