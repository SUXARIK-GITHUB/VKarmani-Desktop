import { tr, type UiLanguage } from '../i18n';

interface SupportTabProps {
  language: UiLanguage;
}

export function SupportTab({ language }: SupportTabProps) {
  return (
    <div className="support-empty-screen">
      <section className="vk-card support-empty-panel" aria-label={tr(language, 'Поддержка', 'Support')}>
        <span className="section-kicker">VKarmani</span>
        <h2>{tr(language, 'Поддержка', 'Support')}</h2>
        <p>{tr(language, 'Раздел поддержки будет добавлен позже.', 'The support section will be added later.')}</p>
      </section>
    </div>
  );
}
