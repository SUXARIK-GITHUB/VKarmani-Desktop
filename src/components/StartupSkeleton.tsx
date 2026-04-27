import { tr, type UiLanguage } from '../i18n';

export function StartupSkeleton({ language }: { language: UiLanguage }) {
  return (
    <div className="tab-stack compact-tab-stack">
      <section className="panel skeleton-panel">
        <div className="panel-header compact compact-header-row">
          <div>
            <span className="chip subdued">{tr(language, 'Подготовка', 'Preparing')}</span>
            <h3>{tr(language, 'Загружаем клиент', 'Loading client')}</h3>
            <p className="muted">{tr(language, 'Проверяем runtime, профиль, proxy и последние сессии…', 'Checking runtime, profile, proxy, and recent sessions…')}</p>
          </div>
        </div>
        <div className="skeleton-grid" aria-hidden="true">
          <span className="skeleton-line wide" />
          <span className="skeleton-line" />
          <span className="skeleton-card" />
          <span className="skeleton-card" />
          <span className="skeleton-card" />
        </div>
      </section>
    </div>
  );
}
