import { FolderOpen, Plus, RefreshCw, Trash2, X } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { tr, type UiLanguage } from '../i18n';
import type { RoutingPolicy, RunningAppInfo, SplitTunnelEntry, TunnelMode, TunRoutingMode, WindowsServiceInfo } from '../types/vpn';
import { listNativeWindowsServices } from '../services/runtime';
import { activePolicyEntries } from '../utils/appPolicies';
import '../styles/policies.css';

interface SplitTunnelModalProps {
  open: boolean;
  language: UiLanguage;
  entries: SplitTunnelEntry[];
  runningApps: RunningAppInfo[];
  isLoadingApps: boolean;
  isPickingExecutable?: boolean;
  onClose: () => void;
  onAddEntry: (kind: SplitTunnelEntry['kind'], value: string, policy?: RoutingPolicy) => boolean;
  onChangePolicy: (entryId: string, policy: RoutingPolicy) => void;
  tunnelMode: TunnelMode;
  tunRoutingMode: TunRoutingMode;
  onToggleEntry: (entryId: string) => void;
  onRemoveEntry: (entryId: string) => void;
  onPickExecutable: (policy?: RoutingPolicy) => Promise<void> | void;
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
  onChangePolicy,
  tunnelMode,
  tunRoutingMode,
  onRemoveEntry,
  onPickExecutable,
  onRefreshRunningApps
}: SplitTunnelModalProps) {
  const [appValue, setAppValue] = useState('');
  const [serviceValue, setServiceValue] = useState('');
  const [appSearch, setAppSearch] = useState('');
  const [policy, setPolicy] = useState<RoutingPolicy>('VPN');
  const [services, setServices] = useState<WindowsServiceInfo[]>([]);
  const [servicesBusy, setServicesBusy] = useState(false);
  const [servicesError, setServicesError] = useState(false);
  const serviceGeneration = useRef(0);
  const dialog = useRef<HTMLElement>(null);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const refreshServices = useCallback(async () => {
    const generation = ++serviceGeneration.current;
    setServicesBusy(true); setServicesError(false);
    try { const next = await listNativeWindowsServices(); if (generation === serviceGeneration.current) setServices(next); }
    catch { if (generation === serviceGeneration.current) setServicesError(true); }
    finally { if (generation === serviceGeneration.current) setServicesBusy(false); }
  }, []);
  useEffect(() => {
    if (!open) return;
    void refreshServices();
    const previous = document.activeElement as HTMLElement | null;
    const focusable = () => Array.from(dialog.current?.querySelectorAll<HTMLElement>('button:not(:disabled),input:not(:disabled),select:not(:disabled),[tabindex="0"]') ?? []);
    focusable()[0]?.focus();
    const key = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); closeRef.current(); }
      if (event.key !== 'Tab') return;
      const elements = focusable(); const first = elements[0]; const last = elements[elements.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    };
    window.addEventListener('keydown', key, true);
    return () => { serviceGeneration.current++; window.removeEventListener('keydown', key, true); previous?.focus(); };
  }, [open, refreshServices]);
  const query = appSearch.trim().toLowerCase();
  const filteredEntries = entries.filter(entry => `${entry.kind} ${entry.value} ${entry.policy ?? 'VPN'}`.toLowerCase().includes(query));
  const filteredServices = services.filter(service => `${service.name} ${service.displayName} ${service.exePath}`.toLowerCase().includes(query));
  const activeCount = useMemo(() => activePolicyEntries(entries, tunRoutingMode).length, [entries, tunRoutingMode]);
  const filteredRunningApps = useMemo(() => {
    const query = appSearch.trim().toLowerCase();
    if (!query) {
      return runningApps;
    }

    return runningApps.filter((app) => [app.name, app.path, app.title, String(app.pid)]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query)));
  }, [appSearch, runningApps]);

  const stopModalEvent = useCallback((event: React.SyntheticEvent) => {
    event.stopPropagation();
  }, []);

  const closeOnBackdrop = useCallback((event: React.MouseEvent<HTMLDivElement>) => {
    if (event.target === event.currentTarget) {
      onClose();
    }
  }, [onClose]);

  if (!open) {
    return null;
  }

  return (
    <div className="vk-modal-backdrop" role="presentation" onMouseDown={closeOnBackdrop}>
      <section
        ref={dialog}
        className="vk-modal-card split-tunnel-modal"
        role="dialog"
        aria-modal="true"
        aria-label={tr(language, 'Приложения TUN', 'TUN applications')}
        onMouseDown={stopModalEvent}
        onClick={stopModalEvent}
        onKeyDown={stopModalEvent}
      >
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
            {tunRoutingMode === 'selected' ? tr(language, 'Выбранные VPN-программы идут через VPN, DIRECT и остальные — напрямую.', 'Selected VPN applications use the VPN; DIRECT and unselected apps go directly.') : tr(language, 'Все приложения идут через VPN, кроме DIRECT. Сохранённые VPN-правила выбранных приложений сейчас не применяются.', 'All applications use the VPN except DIRECT. Saved selected-application VPN rules are inactive in this mode.')} {' '}{tr(language, 'Путь к exe относится только к этому файлу; имя exe — ко всем процессам с этим именем.', 'An exe path targets that file; an exe name targets every process with that name.')}
          </p>
          {tunnelMode === 'proxy' && <p className="split-tunnel-help policy-warning">{tr(language, 'Сейчас Proxy: эти process rules работают только в TUN. Программа, вручную использующая SOCKS/HTTP proxy, не получает строгую DIRECT-изоляцию.', 'Proxy mode: these process rules apply only in TUN. An app manually using SOCKS/HTTP proxy has no strict DIRECT isolation.')}</p>}
          <div className="policy-toolbar">
            <label className="split-field"><span>{tr(language, 'Поиск правил, программ и служб', 'Search rules, applications and services')}</span><input value={appSearch} onChange={event => setAppSearch(event.target.value)} placeholder={tr(language, 'Имя или путь…', 'Name or path…')} /></label>
            <label className="split-field"><span>{tr(language, 'Новое правило', 'New rule')}</span><select value={policy} onChange={event => setPolicy(event.target.value as RoutingPolicy)}><option value="VPN">VPN</option><option value="DIRECT">DIRECT</option></select></label>
          </div>

          <div className="split-tunnel-add-grid">
            <label className="split-field">
              <span>{tr(language, 'Приложение или путь', 'Application or path')}</span>
              <input
                value={appValue}
                onChange={(event) => setAppValue(event.target.value)}
                onMouseDown={stopModalEvent}
                onClick={stopModalEvent}
                onKeyDown={stopModalEvent}
                autoComplete="off"
                spellCheck={false}
                placeholder={tr(language, 'chrome.exe или C:\\Program Files\\...', 'chrome.exe or C:\\Program Files\\...')}
              />
            </label>
            <button type="button" className="vk-secondary-action" onClick={() => { if (onAddEntry('app', appValue, policy)) setAppValue(''); }}>
              <Plus size={17} /> {tr(language, 'Добавить', 'Add')}
            </button>
            <button type="button" className="vk-secondary-action" onClick={() => void onPickExecutable(policy)} disabled={isPickingExecutable}>
              <FolderOpen size={17} /> {isPickingExecutable ? tr(language, 'Открываем…', 'Opening…') : tr(language, 'Выбрать .exe', 'Choose .exe')}
            </button>
          </div>

          <div className="split-tunnel-add-grid service">
            <label className="split-field">
              <span>{tr(language, 'Служба Windows', 'Windows service')}</span>
              <input
                value={serviceValue}
                onChange={(event) => setServiceValue(event.target.value)}
                onMouseDown={stopModalEvent}
                onClick={stopModalEvent}
                onKeyDown={stopModalEvent}
                autoComplete="off"
                spellCheck={false}
                placeholder="Dnscache, WinHttpAutoProxySvc…"
              />
            </label>
            <button type="button" className="vk-secondary-action" onClick={() => { if (onAddEntry('service', serviceValue, policy)) setServiceValue(''); }}>
              <Plus size={17} /> {tr(language, 'Добавить службу', 'Add service')}
            </button>
          </div>

          <section className="split-section">
            <div className="split-section-title">
              <strong>{tr(language, `Активные правила: ${activeCount}`, `Active rules: ${activeCount}`)}</strong>
            </div>
            <div className="split-entry-list">
              {filteredEntries.map((entry) => (
                <div className={`split-entry ${entry.enabled ? 'enabled' : ''}`} key={entry.id}>
                  <button type="button" className="split-entry-toggle" onClick={() => onToggleEntry(entry.id)}>
                    <span>{entry.enabled ? tr(language, 'Вкл', 'On') : tr(language, 'Выкл', 'Off')}</span>
                  </button>
                  <div>
                    <strong>{entry.kind === 'app' ? tr(language, 'Приложение', 'Application') : tr(language, 'Служба', 'Service')}</strong>
                    <small>{entry.value}</small>
                    {entry.invalidReason && <small className="policy-warning">{tr(language, 'Правило из старых настроек отключено: проверьте тип и exe/имя службы. Исходная запись сохранена.', 'Legacy rule disabled: review target type and exe/service name. Original entry is preserved.')} ({entry.invalidReason})</small>}
                    <select aria-label={tr(language, `Политика: ${entry.value}`, `Policy: ${entry.value}`)} value={entry.policy ?? 'VPN'} onChange={event => onChangePolicy(entry.id, event.target.value as RoutingPolicy)}><option value="VPN">VPN</option><option value="DIRECT">DIRECT</option></select>
                  </div>
                  <button type="button" className="split-entry-delete" onClick={() => onRemoveEntry(entry.id)} aria-label={tr(language, 'Удалить', 'Delete')}>
                    <Trash2 size={18} />
                  </button>
                </div>
              ))}
              {!entries.length ? <div className="split-empty">{tr(language, 'Пока нет выбранных приложений или служб.', 'No applications or services selected yet.')}</div> : null}
              {entries.length > 0 && !filteredEntries.length && <div className="split-empty">{tr(language, 'Правила не найдены.', 'No rules found.')}</div>}
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
            <label className="split-field running-app-search">
              <span>{tr(language, 'Поиск по приложениям', 'Search applications')}</span>
              <input
                value={appSearch}
                onChange={(event) => setAppSearch(event.target.value)}
                onMouseDown={stopModalEvent}
                onClick={stopModalEvent}
                onKeyDown={stopModalEvent}
                autoComplete="off"
                spellCheck={false}
                placeholder={tr(language, 'Например: chrome, telegram, discord…', 'For example: chrome, telegram, discord…')}
              />
            </label>
            <div className="running-app-list">
              {filteredRunningApps.slice(0, 160).map((app) => {
                const value = getAppValue(app);
                return (
                  <button type="button" className="running-app-row" key={`${app.pid}-${value}`} onClick={() => onAddEntry('app', value, policy)}>
                    <strong>{app.name}</strong>
                    <small>{app.path || app.title || `PID ${app.pid}`}</small>
                  </button>
                );
              })}
              {!runningApps.length ? <div className="split-empty">{isLoadingApps ? tr(language, 'Загружаем список приложений…', 'Loading application list…') : tr(language, 'Список приложений пуст.', 'The application list is empty.')}</div> : null}
              {runningApps.length > 0 && !filteredRunningApps.length ? <div className="split-empty">{tr(language, 'По этому поиску приложений не найдено.', 'No applications found for this search.')}</div> : null}
            </div>
          </section>
          <section className="split-section">
            <div className="split-section-title"><strong>{tr(language, 'Службы Windows', 'Windows services')}</strong><button type="button" className="vk-secondary-action compact" disabled={servicesBusy} onClick={() => void refreshServices()}><RefreshCw size={16} className={servicesBusy ? 'spin-icon' : ''} />{tr(language, 'Обновить', 'Refresh')}</button></div>
            <p className="split-tunnel-help">{tr(language, 'Поддерживается только выделенный exe. Общий svchost/PID/exe не разделяется по имени службы; такое правило применяться не будет.', 'Only a dedicated exe is supported. A shared svchost/PID/exe cannot be isolated by service name; such a rule is not applied.')}</p>
            {servicesError && <p role="alert" className="split-empty">{tr(language, 'Список служб недоступен. Повторите загрузку.', 'Service list unavailable. Retry loading.')}</p>}
            <div className="running-app-list">{filteredServices.slice(0,160).map(service => <button type="button" className="running-app-row" key={service.name} disabled={!service.supported} onClick={() => onAddEntry('service', service.name, policy)}><strong>{service.displayName} · {service.name}</strong><small>{service.supported ? service.exePath : tr(language, 'Общий host или неподдерживаемый target', 'Shared host or unsupported target')}</small></button>)}</div>
            {!services.length && !servicesError && <div className="split-empty">{servicesBusy ? tr(language, 'Загружаем службы…', 'Loading services…') : tr(language, 'Службы доступны в Windows-клиенте.', 'Services are available in the Windows client.')}</div>}
            {services.length > 0 && !filteredServices.length && <div className="split-empty">{tr(language, 'Службы не найдены.', 'No services found.')}</div>}
          </section>
        </div>
      </section>
    </div>
  );
}
