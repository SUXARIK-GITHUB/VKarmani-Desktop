import { FolderOpen, Plus, RefreshCw, Trash2, X } from 'lucide-react';
import { useMemo, useState } from 'react';
import { tr, type UiLanguage } from '../i18n';
import type { RunningAppInfo, SplitTunnelEntry } from '../types/vpn';

interface SplitTunnelModalProps {
  open: boolean;
  language: UiLanguage;
  entries: SplitTunnelEntry[];
  runningApps: RunningAppInfo[];
  isLoadingApps: boolean;
  isPickingExecutable?: boolean;
  onClose: () => void;
  onAddEntry: (kind: SplitTunnelEntry['kind'], value: string) => boolean;
  onToggleEntry: (entryId: string) => void;
  onRemoveEntry: (entryId: string) => void;
  onPickExecutable: () => Promise<void> | void;
  onRefreshRunningApps: () => Promise<void> | void;
}

function getAppValue(app: RunningAppInfo) {
  return app.path || app.name;
}

export function SplitTunnelModal({
  open,
  language,
  entries,
  runningApps,
  isLoadingApps,
  isPickingExecutable = false,
  onClose,
  onAddEntry,
  onToggleEntry,
  onRemoveEntry,
  onPickExecutable,
  onRefreshRunningApps
}: SplitTunnelModalProps) {
  const [appValue, setAppValue] = useState('');
  const [serviceValue, setServiceValue] = useState('');
  const activeCount = useMemo(() => entries.filter((entry) => entry.enabled && entry.value.trim()).length, [entries]);

  if (!open) {
    return null;
  }

  return (
    <div className="vk-modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section className="vk-modal-card split-tunnel-modal" role="dialog" aria-modal="true" aria-label={tr(language, 'Приложения TUN', 'TUN applications')} onMouseDown={(event) => event.stopPropagation()}>
        <header className="vk-modal-header">
          <div>
            <span className="section-kicker">TUN</span>
            <h2>{tr(language, 'Приложения и службы', 'Applications and services')}</h2>
          </div>
          <button type="button" className="vk-modal-close" onClick={onClose} aria-label={tr(language, 'Закрыть', 'Close')}>
            <X size={22} />
          </button>
        </header>

        <div className="vk-modal-scroll">
          <p className="split-tunnel-help">
            {tr(language, 'Добавьте приложения или службы, которые должны идти через TUN. Можно выбрать exe-файл, вставить путь вручную или выбрать процесс из списка.', 'Add applications or services that should use TUN. You can choose an exe file, paste a path manually, or select a running process.')}
          </p>

          <div className="split-tunnel-add-grid">
            <label className="split-field">
              <span>{tr(language, 'Приложение или путь', 'Application or path')}</span>
              <input value={appValue} onChange={(event) => setAppValue(event.target.value)} placeholder="chrome.exe или C:\Program Files\..." />
            </label>
            <button type="button" className="vk-secondary-action" onClick={() => { if (onAddEntry('app', appValue)) setAppValue(''); }}>
              <Plus size={17} /> {tr(language, 'Добавить', 'Add')}
            </button>
            <button type="button" className="vk-secondary-action" onClick={() => void onPickExecutable()} disabled={isPickingExecutable}>
              <FolderOpen size={17} /> {isPickingExecutable ? tr(language, 'Открываем…', 'Opening…') : tr(language, 'Выбрать .exe', 'Choose .exe')}
            </button>
          </div>

          <div className="split-tunnel-add-grid service">
            <label className="split-field">
              <span>{tr(language, 'Служба Windows', 'Windows service')}</span>
              <input value={serviceValue} onChange={(event) => setServiceValue(event.target.value)} placeholder="Dnscache, WinHttpAutoProxySvc…" />
            </label>
            <button type="button" className="vk-secondary-action" onClick={() => { if (onAddEntry('service', serviceValue)) setServiceValue(''); }}>
              <Plus size={17} /> {tr(language, 'Добавить службу', 'Add service')}
            </button>
          </div>

          <section className="split-section">
            <div className="split-section-title">
              <strong>{tr(language, `Активные правила: ${activeCount}`, `Active rules: ${activeCount}`)}</strong>
            </div>
            <div className="split-entry-list">
              {entries.map((entry) => (
                <div className={`split-entry ${entry.enabled ? 'enabled' : ''}`} key={entry.id}>
                  <button type="button" className="split-entry-toggle" onClick={() => onToggleEntry(entry.id)}>
                    <span>{entry.enabled ? tr(language, 'Вкл', 'On') : tr(language, 'Выкл', 'Off')}</span>
                  </button>
                  <div>
                    <strong>{entry.kind === 'app' ? tr(language, 'Приложение', 'Application') : tr(language, 'Служба', 'Service')}</strong>
                    <small>{entry.value}</small>
                  </div>
                  <button type="button" className="split-entry-delete" onClick={() => onRemoveEntry(entry.id)} aria-label={tr(language, 'Удалить', 'Delete')}>
                    <Trash2 size={18} />
                  </button>
                </div>
              ))}
              {!entries.length ? <div className="split-empty">{tr(language, 'Пока нет выбранных приложений или служб.', 'No applications or services selected yet.')}</div> : null}
            </div>
          </section>

          <section className="split-section">
            <div className="split-section-title">
              <strong>{tr(language, 'Запущенные приложения', 'Running applications')}</strong>
              <button type="button" className="vk-secondary-action compact" onClick={() => void onRefreshRunningApps()} disabled={isLoadingApps}>
                <RefreshCw size={16} className={isLoadingApps ? 'spin-icon' : ''} />
                {tr(language, 'Обновить', 'Refresh')}
              </button>
            </div>
            <div className="running-app-list">
              {runningApps.slice(0, 80).map((app) => {
                const value = getAppValue(app);
                return (
                  <button type="button" className="running-app-row" key={`${app.pid}-${value}`} onClick={() => onAddEntry('app', value)}>
                    <strong>{app.name}</strong>
                    <small>{app.path || app.title || `PID ${app.pid}`}</small>
                  </button>
                );
              })}
              {!runningApps.length ? <div className="split-empty">{isLoadingApps ? tr(language, 'Загружаем список приложений…', 'Loading application list…') : tr(language, 'Список приложений пуст.', 'The application list is empty.')}</div> : null}
            </div>
          </section>
        </div>
      </section>
    </div>
  );
}
