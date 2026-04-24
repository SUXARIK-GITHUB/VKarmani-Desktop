import { useEffect, useState, type FormEvent } from 'react';
import {
  Activity,
  ArrowRightLeft,
  Clock3,
  Cpu,
  Globe2,
  MapPin,
  MonitorCog,
  MousePointer2,
  Plus,
  Power,
  ShieldCheck,
  Signal,
  Sparkles,
  Trash2,
  Waypoints,
  Wifi,
  X
} from 'lucide-react';
import { tr, type UiLanguage } from '../i18n';
import { listNativeRunningApps, writeNativeInterfaceLog } from '../services/runtime';
import type {
  ConnectionState,
  RuntimeStatus,
  RunningAppInfo,
  SplitTunnelEntry,
  TunnelMode,
  VpnServer
} from '../types/vpn';
import { getServerDisplayLabel, getServerPrimaryLabel, getServerSecondaryLabel } from '../utils/serverDisplay';

interface OverviewTabProps {
  connectionState: ConnectionState;
  connectLabel: string;
  statusText: string;
  selectedServer: VpnServer | null;
  primaryExternalIp: string;
  vpnExternalIp: string;
  sessionDurationText: string;
  diagnosticsStatus: string;
  runtimeStatus: RuntimeStatus;
  language: UiLanguage;
  showDiagnostics: boolean;
  tunnelMode: TunnelMode;
  splitTunnelEntries: SplitTunnelEntry[];
  onToggleConnection: () => void;
  onTunnelModeChange: (value: TunnelMode) => void;
  onAddSplitTunnelEntry: (kind: SplitTunnelEntry['kind'], value: string) => boolean;
  onToggleSplitTunnelEntry: (entryId: string) => void;
  onRemoveSplitTunnelEntry: (entryId: string) => void;
  profileSyncMessage?: string;
  isBusy: boolean;
  canConnect: boolean;
  isSyncingProfile?: boolean;
}

export function OverviewTab({
  connectionState,
  connectLabel,
  statusText,
  selectedServer,
  primaryExternalIp,
  vpnExternalIp,
  sessionDurationText,
  diagnosticsStatus,
  runtimeStatus,
  language,
  showDiagnostics,
  tunnelMode,
  splitTunnelEntries,
  onToggleConnection,
  onTunnelModeChange,
  onAddSplitTunnelEntry,
  onToggleSplitTunnelEntry,
  onRemoveSplitTunnelEntry,
  isBusy,
  canConnect
}: OverviewTabProps) {
  const [isSplitTunnelEditorOpen, setIsSplitTunnelEditorOpen] = useState(false);
  const [programValue, setProgramValue] = useState('');
  const [serviceValue, setServiceValue] = useState('');
  const [runningApps, setRunningApps] = useState<RunningAppInfo[]>([]);
  const [isRunningAppsOpen, setIsRunningAppsOpen] = useState(false);
  const [isLoadingRunningApps, setIsLoadingRunningApps] = useState(false);

  useEffect(() => {
    if (isSplitTunnelEditorOpen) {
      void writeNativeInterfaceLog(
        'Открыт редактор TUN списка.',
        `Активных правил: ${splitTunnelEntries.filter((entry: SplitTunnelEntry) => entry.enabled).length}`
      );
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsSplitTunnelEditorOpen(false);
      }
    };

    if (isSplitTunnelEditorOpen) {
      window.addEventListener('keydown', handleKeyDown);
      return () => window.removeEventListener('keydown', handleKeyDown);
    }

    return undefined;
  }, [isSplitTunnelEditorOpen, splitTunnelEntries]);

  const primaryServerLabel = selectedServer ? getServerPrimaryLabel(selectedServer) : '—';
  const secondaryServerLabel = selectedServer ? getServerSecondaryLabel(selectedServer, showDiagnostics) : undefined;
  const connectionLocation = selectedServer
    ? getServerDisplayLabel(selectedServer, showDiagnostics)
    : tr(language, 'Список серверов загружается…', 'Loading server list…');
  const primaryExternalIpLabel = primaryExternalIp && primaryExternalIp !== '—'
    ? primaryExternalIp
    : tr(language, 'Определяется…', 'Detecting…');
  const vpnExternalIpLabel = connectionState === 'connected'
    ? (vpnExternalIp && vpnExternalIp !== '—' ? vpnExternalIp : tr(language, 'Определяется…', 'Detecting…'))
    : tr(language, 'Определится после подключения', 'Will be detected after connection');
  const splitTunnelEnabledCount = splitTunnelEntries.filter((entry: SplitTunnelEntry) => entry.enabled).length;
  const nextTunnelMode = tunnelMode === 'proxy' ? 'tun' : 'proxy';
  const currentModeLabel = tunnelMode === 'tun' ? 'TUN' : tr(language, 'Прокси', 'Proxy');
  const nextModeHint = tunnelMode === 'tun'
    ? tr(language, 'Переключить на прокси', 'Switch to proxy')
    : tr(language, 'Переключить на TUN', 'Switch to TUN');
  const routingReadiness = runtimeStatus.coreInstalled
    ? tr(language, 'готов к подключению', 'ready to connect')
    : tr(language, 'конфиг ещё не собран', 'runtime not ready yet');

  function handleProgramSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (onAddSplitTunnelEntry('app', programValue)) {
      setProgramValue('');
    }
  }

  async function handleOpenRunningApps() {
    setIsLoadingRunningApps(true);
    setIsRunningAppsOpen(true);
    try {
      const apps = await listNativeRunningApps();
      setRunningApps(apps);
      void writeNativeInterfaceLog('Открыт список запущенных приложений для TUN.', `Найдено: ${apps.length}`);
    } catch (error) {
      setRunningApps([]);
      void writeNativeInterfaceLog('Не удалось получить список запущенных приложений.', error instanceof Error ? error.message : String(error));
    } finally {
      setIsLoadingRunningApps(false);
    }
  }

  function handleSelectRunningApp(app: RunningAppInfo) {
    const value = app.path?.trim() || (app.name.endsWith('.exe') ? app.name : `${app.name}.exe`);
    if (onAddSplitTunnelEntry('app', value)) {
      setProgramValue('');
    }
    setIsRunningAppsOpen(false);
  }

  function handleServiceSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (onAddSplitTunnelEntry('service', serviceValue)) {
      setServiceValue('');
    }
  }

  return (
    <div className="tab-stack compact-tab-stack overview-screen">
      <section className="hero-banner compact-hero-banner">
        <div className="hero-copy">
          <span className={`chip status-chip ${connectionState}`}>{statusText}</span>
          <h1>{tr(language, 'VPN VKarmani - для людей и компаний', 'VPN VKarmani - for people and companies')}</h1>
        </div>

        <article className="hero-status-card">
          <div className="hero-status-card-header">
            <strong>{tr(language, 'Статус соединения', 'Connection status')}</strong>
          </div>

          <div className="hero-badges compact-hero-badges hero-status-list">
            <div>
              <Signal size={15} />
              <span>{statusText}</span>
            </div>
            <div>
              <Globe2 size={15} />
              <span>{primaryExternalIpLabel}</span>
            </div>
            <div>
              <Sparkles size={15} />
              <span>{diagnosticsStatus}</span>
            </div>
          </div>
        </article>
      </section>

      <div className="overview-grid compact-overview-grid">
        <div className="overview-main-stack">
          <article className="connection-card glow-card">
            <div className="connection-ring-wrap">
              <button
                className={`power-button ${connectionState}`}
                onClick={onToggleConnection}
                disabled={isBusy || (!canConnect && connectionState === 'idle')}
                aria-label={connectLabel}
              >
                <Power size={34} />
              </button>
            </div>

            <div className="connection-text">
              <h2>{connectLabel}</h2>
              <p>{connectionLocation}</p>

              <div className="inline-stats wrap-inline-stats">
                <span>
                  <Wifi size={14} /> {selectedServer?.protocol ?? '—'}
                  {selectedServer?.transportLabel ? ` / ${selectedServer.transportLabel}` : ''}
                </span>
                <span>
                  <Activity size={14} /> {tr(language, 'Нагрузка', 'Load')} {selectedServer?.load ?? 0}%
                </span>
                <span className={`mode-status-pill ${tunnelMode}`}>
                  <Waypoints size={14} /> {tunnelMode === 'tun' ? tr(language, 'TUN активен', 'TUN active') : tr(language, 'Прокси активен', 'Proxy active')}
                </span>
                {showDiagnostics ? (
                  <span>
                    <MapPin size={14} /> {selectedServer?.host ? `${selectedServer.host}:${selectedServer.port ?? 443}` : tr(language, 'Узел появится после синхронизации', 'Node will appear after sync')}
                  </span>
                ) : null}
              </div>

              <div className="inline-stats wrap-inline-stats">
                <span>
                  <ShieldCheck size={14} /> {routingReadiness}
                </span>
                {tunnelMode === 'tun' ? (
                  <span>
                    <MonitorCog size={14} /> {tr(language, `Правил: ${splitTunnelEnabledCount}`, `Rules: ${splitTunnelEnabledCount}`)}
                  </span>
                ) : null}
              </div>

              <div className="overview-actions tunnel-mode-actions compact-mode-actions">
                <button
                  type="button"
                  className={`ghost-button mode-toggle-button ${tunnelMode}`}
                  onClick={() => onTunnelModeChange(nextTunnelMode)}
                  disabled={isBusy}
                  title={nextModeHint}
                >
                  <span className={`mode-toggle-icon-shell ${tunnelMode}`}>
                    {tunnelMode === 'tun' ? <Waypoints size={17} /> : <Globe2 size={17} />}
                  </span>
                  <span className="mode-toggle-copy">
                    <span className="mode-toggle-kicker">{tr(language, 'Режим маршрутизации', 'Routing mode')}</span>
                    <strong>{currentModeLabel}</strong>
                    <span className="mode-toggle-meta">{nextModeHint}</span>
                  </span>
                  <span className="mode-toggle-switch-mark" aria-hidden="true">
                    <ArrowRightLeft size={15} />
                  </span>
                </button>

                {tunnelMode === 'tun' ? (
                  <button
                    type="button"
                    className={`ghost-button split-tunnel-launcher-button ${isSplitTunnelEditorOpen ? 'active' : ''}`}
                    onClick={() => setIsSplitTunnelEditorOpen((current) => !current)}
                    disabled={isBusy}
                    title={tr(language, 'Настроить список TUN', 'Configure TUN list')}
                    aria-label={tr(language, 'Настроить список TUN', 'Configure TUN list')}
                  >
                    <MonitorCog size={17} />
                    <span className={`mode-count-badge ${splitTunnelEnabledCount > 0 ? 'filled' : ''}`}>{splitTunnelEnabledCount}</span>
                  </button>
                ) : null}
              </div>
            </div>
          </article>
        </div>

        <article className="metrics-card compact-metrics-card">
          <div className="metrics-card-header">
            <strong>{tr(language, 'После подключения', 'After connection')}</strong>
          </div>

          <div className="metric-item">
            <div className="metric-label">
              <Clock3 size={16} /> {tr(language, 'Сессия', 'Session')}
            </div>
            <strong>{connectionState === 'connected' ? sessionDurationText : '00:00:00'}</strong>
          </div>
          <div className="metric-item">
            <div className="metric-label">
              <Globe2 size={16} /> {tr(language, 'Внешний IP', 'Public IP')}
            </div>
            <strong>{vpnExternalIpLabel}</strong>
          </div>
          <div className="metric-item">
            <div className="metric-label">
              <MapPin size={16} /> {tr(language, 'Текущий узел', 'Current node')}
            </div>
            <strong>{primaryServerLabel}</strong>
            {secondaryServerLabel ? <span className="metric-note">{secondaryServerLabel}</span> : null}
          </div>
        </article>
      </div>

      {tunnelMode === 'tun' && isSplitTunnelEditorOpen ? (
        <div className="split-tunnel-modal-backdrop" onClick={() => setIsSplitTunnelEditorOpen(false)}>
          <div className="split-tunnel-modal" onClick={(event) => event.stopPropagation()}>
            <div className="split-tunnel-modal-header">
              <div>
                <strong>{tr(language, 'Приложения и службы', 'Apps and services')}</strong>
                <span>{tr(language, 'Добавь только то, что должно идти через TUN', 'Add only what should use TUN')}</span>
              </div>
              <div className="split-tunnel-modal-actions">
                <span className={`mode-count-badge ${splitTunnelEnabledCount > 0 ? 'filled' : ''}`}>{splitTunnelEnabledCount}</span>
                <button type="button" className="ghost-button split-modal-close" onClick={() => setIsSplitTunnelEditorOpen(false)}>
                  <X size={16} />
                </button>
              </div>
            </div>

            <div className="split-tunnel-form-grid compact-split-tunnel-form-grid">
              <form className="split-tunnel-form compact-split-tunnel-form" onSubmit={handleProgramSubmit}>
                <label>
                  <strong><MonitorCog size={15} /> {tr(language, 'Программа', 'Program')}</strong>
                </label>
                <div className="split-tunnel-input-row key-input-row compact-key-input-row">
                  <input
                    value={programValue}
                    onChange={(event) => setProgramValue(event.target.value)}
                    placeholder={tr(language, 'chrome.exe или путь к .exe', 'chrome.exe or path to .exe')}
                  />
                  <button type="submit" className="ghost-button split-inline-button">
                    <Plus size={15} />
                  </button>
                </div>
              </form>

              <form className="split-tunnel-form compact-split-tunnel-form" onSubmit={handleServiceSubmit}>
                <label>
                  <strong><Cpu size={15} /> {tr(language, 'Служба', 'Service')}</strong>
                </label>
                <div className="split-tunnel-input-row key-input-row compact-key-input-row">
                  <input
                    value={serviceValue}
                    onChange={(event) => setServiceValue(event.target.value)}
                    placeholder={tr(language, 'Имя службы Windows', 'Windows service name')}
                  />
                  <button type="submit" className="ghost-button split-inline-button">
                    <Plus size={15} />
                  </button>
                </div>
              </form>

              <div className="split-tunnel-form compact-split-tunnel-form split-running-apps-form">
                <label>
                  <strong><MousePointer2 size={15} /> {tr(language, 'Запущенные', 'Running')}</strong>
                </label>
                <button
                  type="button"
                  className="ghost-button split-running-apps-button"
                  onClick={handleOpenRunningApps}
                  disabled={isLoadingRunningApps}
                >
                  {isLoadingRunningApps
                    ? tr(language, 'Загрузка…', 'Loading…')
                    : tr(language, 'Выбрать запущенное приложение', 'Choose running app')}
                </button>
              </div>
            </div>

            {isRunningAppsOpen ? (
              <div className="split-running-apps-panel">
                <div className="split-running-apps-panel-header">
                  <strong>{tr(language, 'Запущенные приложения', 'Running apps')}</strong>
                  <button type="button" className="ghost-button split-modal-close" onClick={() => setIsRunningAppsOpen(false)}>
                    <X size={14} />
                  </button>
                </div>
                <div className="split-running-apps-list">
                  {isLoadingRunningApps ? (
                    <div className="split-tunnel-empty compact">
                      <span>{tr(language, 'Получаю список процессов…', 'Loading process list…')}</span>
                    </div>
                  ) : runningApps.length ? runningApps.map((app: RunningAppInfo) => (
                    <button
                      type="button"
                      key={`${app.pid}-${app.path ?? app.name}`}
                      className="split-running-app-item"
                      onClick={() => handleSelectRunningApp(app)}
                    >
                      <strong>{app.name}</strong>
                      <span>{app.title || app.path || `PID ${app.pid}`}</span>
                    </button>
                  )) : (
                    <div className="split-tunnel-empty compact">
                      <strong>{tr(language, 'Ничего не найдено', 'Nothing found')}</strong>
                      <span>{tr(language, 'Можно ввести exe вручную.', 'You can enter the exe manually.')}</span>
                    </div>
                  )}
                </div>
              </div>
            ) : null}

            <div className="split-tunnel-list compact-split-tunnel-list">
              {splitTunnelEntries.length ? splitTunnelEntries.map((entry: SplitTunnelEntry) => (
                <div key={entry.id} className={`split-tunnel-entry ${entry.enabled ? 'enabled' : 'disabled'}`}>
                  <button
                    type="button"
                    className={`ghost-button split-entry-toggle ${entry.enabled ? 'active' : ''}`}
                    onClick={() => onToggleSplitTunnelEntry(entry.id)}
                  >
                    {entry.enabled ? 'TUN' : tr(language, 'Выкл', 'Off')}
                  </button>
                  <div className="split-entry-copy">
                    <strong>{entry.kind === 'app' ? tr(language, 'Программа', 'Program') : tr(language, 'Служба', 'Service')}</strong>
                    <span>{entry.value}</span>
                  </div>
                  <button type="button" className="ghost-button split-entry-remove" onClick={() => onRemoveSplitTunnelEntry(entry.id)}>
                    <Trash2 size={15} />
                  </button>
                </div>
              )) : (
                <div className="split-tunnel-empty">
                  <strong>{tr(language, 'Список пуст', 'List is empty')}</strong>
                  <span>{tr(language, 'Добавь программу или службу.', 'Add a program or service.')}</span>
                </div>
              )}
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
