import { useTranslation } from 'react-i18next';

import { SUPPORTED_LANGUAGES, storeLanguage, type Language } from '../i18n';

export function LanguageToggle(): React.ReactNode {
  const { t, i18n } = useTranslation();
  const current = i18n.resolvedLanguage as Language;

  return (
    <div className="lang" role="group" aria-label={t('language.label')}>
      {SUPPORTED_LANGUAGES.map((language) => (
        <button
          key={language}
          type="button"
          className={language === current ? 'on' : undefined}
          aria-pressed={language === current}
          onClick={() => {
            void i18n.changeLanguage(language);
            storeLanguage(language);
          }}
        >
          {t(`language.${language}`)}
        </button>
      ))}
    </div>
  );
}
