import type { ChangeEvent } from 'react';
import {
  ClipboardList,
  Cpu,
  Download,
  FileText,
  FolderOpen,
  Languages,
  Radar,
  RefreshCcw,
  ShieldAlert,
  ShieldCheck,
  Waypoints
} from 'lucide-react';
import { tr, type UiLanguage } from '../i18n';
import type {
  AppSettings,
  ConnectivityProbe,
  DiagnosticsSnapshot,
  IntegrationMeta,
  ProfileSyncInfo,
  ProxyStatus,
  RemnawaveSession,
  RuntimeStatus,
  SessionRecord,
  UpdateInfo
} from '../types/vpn';

const sessionStatusLabel = (language: UiLanguage): Record<SessionRecord['status'], string> => ({
  current: tr(language, 'Текущая', 'Current'),
  completed: tr(language, 'Завершена', 'Completed'),
  interrupted: tr(language, 'Прервана', 'Interrupted')
});

function formatDisplayTime(language: UiLanguage, value?: string | null) {
  const normalized = value?.trim();
  if (!normalized) {
    return '—';
  }

  if (/^\d{10}$/.test(normalized)) {
    const parsed = new Date(Number(normalized) * 1000);
    return Number.isNaN(parsed.getTime()) ? normalized : parsed.toLocaleString(language === 'ru' ? 'ru-RU' : 'en-GB');
  }

  if (/^\d{13}$/.test(normalized)) {
    const parsed = new Date(Number(normalized));
    return Number.isNaN(parsed.getTime()) ? normalized : parsed.toLocaleString(language === 'ru' ? 'ru-RU' : 'en-GB');
  }

  return normalized;
}

function resolvePlanState(language: UiLanguage, expiresAt: string) {
  const normalized = expiresAt?.trim();
  if (!normalized || normalized === '—' || normalized === 'Не ограничен' || normalized === 'Неизвестно') {
    return {
      title: tr(language, 'Подписка активна', 'Subscription active'),
      hint: tr(language, 'Без ограничения по сроку', 'No expiry limit'),
      tone: 'good' as const
    };
  }

  const parts = normalized.match(/(\d{2})\.(\d{2})\.(\d{4})/);
  if (!parts) {
    return {
      title: tr(language, 'Подписка активна', 'Subscription active'),
      hint: `${tr(language, 'До', 'Until')} ${normalized}`,
      tone: 'good' as const
    };
  }

  const [, dd, mm, yyyy] = parts;
  const parsed = new Date(Number(yyyy), Number(mm) - 1, Number(dd), 23, 59, 59);
  const active = parsed.getTime() >= Date.now();

  return {
    title: active ? tr(language, 'Подписка активна', 'Subscription active') : tr(language, 'Подписка не активна', 'Subscription inactive'),
    hint: active ? `${tr(language, 'До', 'Until')} ${normalized}` : `${tr(language, 'Истекла', 'Expired')} ${normalized}`,
    tone: active ? ('good' as const) : ('bad' as const)
  };
}

function resolveHealthScore(diagnostics: DiagnosticsSnapshot, proxyStatus: ProxyStatus, runtimeStatus?: RuntimeStatus | null) {
  let score = 0;
  score += diagnostics.serviceStatus === 'ok' ? 35 : diagnostics.serviceStatus === 'warning' ? 18 : 0;
  score += diagnostics.tunnelStatus === 'ok' ? 35 : diagnostics.tunnelStatus === 'warning' ? 18 : 0;
  score += runtimeStatus?.coreInstalled ? 15 : 0;
  score += proxyStatus.enabled ? 15 : 7;
  return Math.min(score, 100);
}

interface DiagnosticsTabProps {
  diagnostics: DiagnosticsSnapshot | null;
  runtimeStatus?: RuntimeStatus | null;
  proxyStatus: ProxyStatus;
  connectivityProbe: ConnectivityProbe | null;
  profileSyncInfo: ProfileSyncInfo;
  session?: RemnawaveSession | null;
  integrationMeta: IntegrationMeta;
  sessionHistory: SessionRecord[];
  updateInfo: UpdateInfo;
  settings: AppSettings;
  language: UiLanguage;
  onEnableSystemProxy: () => void;
  onDisableSystemProxy: () => void;
  onRunConnectivityProbe: () => void;
  onSyncProfile: () => void;
  onCheckUpdates: () => void;
  onInstallUpdate?: () => void;
  onClearAccessKey: () => void;
  onReleaseChannelChange: (value: AppSettings['releaseChannel']) => void;
  onProtocolStrategyChange: (value: AppSettings['protocolStrategy']) => void;
  onTunnelModeChange: (value: AppSettings['tunnelMode']) => void;
  onLanguageChange: (value: AppSettings['language']) => void;
  isBusy?: boolean;
  isSyncingProfile?: boolean;
}

export function DiagnosticsTab({
  diagnostics,
  runtimeStatus,
  proxyStatus,
  connectivityProbe,
  profileSyncInfo,
  session,
  integrationMeta,
  sessionHistory,
  updateInfo,
  settings,
  language,
  onEnableSystemProxy,
  onDisableSystemProxy,
  onRunConnectivityProbe,
  onSyncProfile,
  onCheckUpdates,
  onInstallUpdate,
  onClearAccessKey,
  onReleaseChannelChange,
  onProtocolStrategyChange,
  onTunnelModeChange,
  onLanguageChange,
  isBusy = false,
  isSyncingProfile = false
}: DiagnosticsTabProps) {
  const safeSession = session ?? {
    accessKey: '',
    userId: 'local-session',
    displayName: 'VKarmani',
    loginHint: '',
    deviceLimit: 0,
    source: 'demo' as const,
    plan: {
      title: 'VKarmani',
      expiresAt: '—',
      trafficUsedGb: 0,
      trafficLimitGb: 0,
      devices: 0
    }
  };

  const safeSessionHistory = Array.isArray(sessionHistory) ? sessionHistory : [];

  if (!diagnostics) {
    return (
      <section className="panel">
        <div className="panel-header compact-header-row">
          <div>
            <span className="chip subdued">{tr(language, 'Диагностика', 'Diagnostics')}</span>
            <h3>{tr(language, 'Проверка клиента', 'Client diagnostics')}</h3>
          </div>
        </div>
        <p className="muted">{tr(language, 'Загружаем состояние клиента…', 'Loading client status…')}</p>
      </section>
    );
  }

  const serviceTone = diagnostics.serviceStatus === 'ok' ? 'good' : diagnostics.serviceStatus === 'warning' ? 'warn' : 'bad';
  const tunnelTone = diagnostics.tunnelStatus === 'ok' ? 'good' : diagnostics.tunnelStatus === 'warning' ? 'warn' : 'bad';
  const proxyTone = proxyStatus.enabled ? 'good' : 'warn';
  const runtimeActive = Boolean(runtimeStatus?.tunnelActive);
  const safeLogLines = Array.isArray(diagnostics.logLines) && diagnostics.logLines.length
    ? diagnostics.logLines
    : [tr(language, 'Логи пока не поступили.', 'No log lines received yet.')];
  const planState = resolvePlanState(language, safeSession.plan.expiresAt);
  const healthScore = resolveHealthScore(diagnostics, proxyStatus, runtimeStatus);
  const healthLabel = healthScore >= 80
    ? tr(language, 'Система выглядит стабильно', 'System looks stable')
    : healthScore >= 55
      ? tr(language, 'Есть несколько моментов для проверки', 'A few things need attention')
      : tr(language, 'Нужно проверить runtime и маршрут', 'Runtime and route should be checked');
  const probeTone = !connectivityProbe
    ? 'warn'
    : connectivityProbe.success
      ? 'good'
      : 'bad';
  const updateTone = updateInfo.available ? 'warn' : updateInfo.status === 'error' ? 'bad' : 'good';

  return (
    <div className="tab-stack compact-tab-stack diagnostics-screen">
      <section className="panel diagnostics-hero-panel">
        <div className="panel-header compact compact-header-row diagnostics-hero-header">
          <div>
            <span className="chip subdued">{tr(language, 'Диагностика', 'Diagnostics')}</span>
            <h3>{tr(language, 'Центр состояния клиента', 'Client status center')}</h3>
            <p className="muted diagnostics-hero-copy">{healthLabel}</p>
          </div>
          <div className="diagnostics-score-card">
            <span>{tr(language, 'Общее состояние', 'Overall health')}</span>
            <strong>{healthScore}%</strong>
            <small>{tr(language, 'Последняя синхронизация:', 'Last sync:')} {formatDisplayTime(language, diagnostics.lastConfigSync)}</small>
          </div>
        </div>

        <div className="diagnostics-grid compact-diagnostics-grid">
          <article className={`diag-card ${serviceTone}`}>
            <ShieldCheck size={18} />
            <div>
              <strong>{tr(language, 'Служба клиента', 'Client service')}</strong>
              <span>{diagnostics.serviceStatus === 'ok' ? tr(language, 'В норме', 'Healthy') : tr(language, 'Требует внимания', 'Needs attention')}</span>
            </div>
          </article>
          <article className={`diag-card ${tunnelTone}`}>
            <ShieldAlert size={18} />
            <div>
              <strong>{tr(language, 'Туннель', 'Tunnel')}</strong>
              <span>{diagnostics.tunnelStatus === 'ok' ? tr(language, 'Активен', 'Active') : tr(language, 'Готов к переподключению', 'Ready to reconnect')}</span>
            </div>
          </article>
          <article className="diag-card">
            <Cpu size={18} />
            <div>
              <strong>{tr(language, 'Маршрутизация', 'Routing')}</strong>
              <span>{diagnostics.routeMode}</span>
            </div>
          </article>
          <article className={`diag-card ${proxyTone}`}>
            <Waypoints size={18} />
            <div>
              <strong>{tr(language, 'Системный proxy', 'System proxy')}</strong>
              <span>{proxyStatus.enabled ? tr(language, 'Включён', 'Enabled') : tr(language, 'Выключен', 'Disabled')}</span>
            </div>
          </article>
        </div>
      </section>

      <section className="panel compact-panel">
        <div className="panel-header compact compact-header-row">
          <div>
            <span className="chip subdued">{tr(language, 'Быстрые действия', 'Quick actions')}</span>
            <h3>{tr(language, 'Профиль, proxy и probe', 'Profile, proxy, and probe')}</h3>
          </div>
        </div>

        <div className="diagnostics-actions-grid">
          <article className="action-card">
            <div className="action-card-head">
              <span className={`micro-pill ${profileSyncInfo.status === 'ready' ? 'active' : ''}`}>{profileSyncInfo.sourceLabel}</span>
              <strong>{tr(language, 'Профиль Remnawave', 'Remnawave profile')}</strong>
            </div>
            <p>{profileSyncInfo.message ?? tr(language, 'Синхронизация профиля готовит live-сервера и runtime-ready конфиги.', 'Profile sync prepares live servers and runtime-ready configs.')}</p>
            <button className="ghost-button" onClick={onSyncProfile} disabled={isSyncingProfile}>
              <RefreshCcw size={15} />
              {isSyncingProfile ? tr(language, 'Синхронизация…', 'Syncing…') : tr(language, 'Синхронизировать', 'Sync profile')}
            </button>
          </article>

          <article className="action-card">
            <div className="action-card-head">
              <span className={`micro-pill ${proxyStatus.enabled ? 'active' : ''}`}>{proxyStatus.enabled ? tr(language, 'Активен', 'Active') : tr(language, 'Отключён', 'Disabled')}</span>
              <strong>{tr(language, 'Windows proxy', 'Windows proxy')}</strong>
            </div>
            <p>{proxyStatus.enabled ? `${tr(language, 'Сервер:', 'Server:')} ${proxyStatus.server ?? '—'}` : tr(language, 'Используйте системный proxy, если нужен браузерный и системный трафик через туннель.', 'Use system proxy when browser and system traffic should go through the tunnel.')}</p>
            <div className="settings-actions compact-actions action-card-buttons">
              <button className="ghost-button" onClick={onEnableSystemProxy} disabled={isBusy || !runtimeActive}><Waypoints size={15} />{tr(language, 'Включить', 'Enable')}</button>
              <button className="ghost-button" onClick={onDisableSystemProxy} disabled={isBusy}><Waypoints size={15} />{tr(language, 'Отключить', 'Disable')}</button>
            </div>
          </article>

          <article className="action-card">
            <div className="action-card-head">
              <span className={`micro-pill ${connectivityProbe?.success ? 'active' : ''}`}>{connectivityProbe ? formatDisplayTime(language, connectivityProbe.checkedAt) : tr(language, 'Не запускалась', 'Not run yet')}</span>
              <strong>{tr(language, 'Проверка маршрута', 'Route probe')}</strong>
            </div>
            <p>{connectivityProbe?.message ?? tr(language, 'Probe проверяет HTTP/SOCKS порты, внешний IP и базовую доступность маршрута.', 'The probe checks HTTP/SOCKS ports, public IP, and basic route availability.')}</p>
            <button className="ghost-button" onClick={onRunConnectivityProbe} disabled={isBusy || !runtimeActive}><Radar size={15} />{tr(language, 'Запустить probe', 'Run probe')}</button>
          </article>
        </div>
      </section>

      <div className="three-panel-grid compact-three-grid diagnostics-detail-grid">
        <section className="panel compact-panel">
          <div className="panel-header compact compact-header-row">
            <div>
              <span className="chip subdued">{tr(language, 'Runtime', 'Runtime')}</span>
              <h3>{tr(language, 'Нативный слой', 'Native layer')}</h3>
            </div>
          </div>

          <div className="support-list compact-support-list">
            <div className="support-item"><strong>{tr(language, 'Core установлен', 'Core installed')}</strong><span>{runtimeStatus?.coreInstalled ? tr(language, 'Да', 'Yes') : tr(language, 'Пока нет', 'Not yet')}</span></div>
            <div className="support-item"><strong>{tr(language, 'Режим', 'Mode')}</strong><span>{runtimeStatus?.networkMode === 'tun' ? 'Xray TUN' : runtimeStatus?.launchMode === 'xray-sidecar' ? 'Xray sidecar' : tr(language, 'Mock / preview', 'Mock / preview')}</span></div>
            <div className="support-item"><strong>{tr(language, 'Туннель', 'Tunnel')}</strong><span>{runtimeStatus?.tunnelActive ? tr(language, 'Активен', 'Active') : tr(language, 'Не активен', 'Inactive')}</span></div>
            <div className="support-item"><strong>{tr(language, 'Порты', 'Ports')}</strong><span>{runtimeStatus?.socksPort ? `SOCKS ${runtimeStatus.socksPort}` : '—'} / {runtimeStatus?.httpPort ? `HTTP ${runtimeStatus.httpPort}` : '—'}</span></div>
            <div className="support-item"><strong>{tr(language, 'Активный сервер', 'Active server')}</strong><span>{runtimeStatus?.activeServerLabel ?? '—'}</span></div>
          </div>

          <div className="file-path-list">
            <div className="file-path-row">
              <FolderOpen size={16} />
              <div>
                <strong>Core path</strong>
                <span>{runtimeStatus?.corePath ?? tr(language, 'ещё не создан', 'not created yet')}</span>
              </div>
            </div>
            <div className="file-path-row">
              <FileText size={16} />
              <div>
                <strong>Log path</strong>
                <span>{runtimeStatus?.logPath ?? tr(language, 'ещё не создан', 'not created yet')}</span>
              </div>
            </div>
          </div>
        </section>

        <section className="panel compact-panel">
          <div className="panel-header compact compact-header-row">
            <div>
              <span className="chip subdued">Probe</span>
              <h3>{tr(language, 'Проверка маршрута', 'Route probe')}</h3>
            </div>
            <span className={`micro-pill ${probeTone === 'good' ? 'active' : ''}`}>{connectivityProbe?.success ? tr(language, 'Успешно', 'Passed') : connectivityProbe ? tr(language, 'Нужно проверить', 'Needs review') : tr(language, 'Ожидает запуска', 'Waiting to run')}</span>
          </div>

          <div className="probe-grid">
            <div className={`support-item probe-item ${connectivityProbe?.httpPortOpen ? 'probe-good' : ''}`}><strong>HTTP</strong><span>{connectivityProbe ? (connectivityProbe.httpPortOpen ? tr(language, 'Открыт', 'Open') : tr(language, 'Закрыт', 'Closed')) : '—'}</span></div>
            <div className={`support-item probe-item ${connectivityProbe?.socksPortOpen ? 'probe-good' : ''}`}><strong>SOCKS</strong><span>{connectivityProbe ? (connectivityProbe.socksPortOpen ? tr(language, 'Открыт', 'Open') : tr(language, 'Закрыт', 'Closed')) : '—'}</span></div>
            <div className="support-item probe-item"><strong>{tr(language, 'Внешний IP', 'Public IP')}</strong><span>{connectivityProbe?.publicIp ?? '—'}</span></div>
            <div className="support-item probe-item"><strong>Latency</strong><span>{connectivityProbe?.latencyMs ? `${connectivityProbe.latencyMs} ms` : '—'}</span></div>
          </div>

          <div className="support-list compact-support-list">
            <div className="support-item"><strong>{tr(language, 'Статус', 'Status')}</strong><span>{connectivityProbe?.message ?? tr(language, 'Проверка ещё не выполнялась.', 'The probe has not been run yet.')}</span></div>
            <div className="support-item"><strong>{tr(language, 'Время', 'Time')}</strong><span>{formatDisplayTime(language, connectivityProbe?.checkedAt)}</span></div>
            <div className="support-item"><strong>{tr(language, 'Последняя проверка proxy', 'Proxy check')}</strong><span>{formatDisplayTime(language, proxyStatus.checkedAt)}</span></div>
          </div>
        </section>

        <section className="panel compact-panel">
          <div className="panel-header compact compact-header-row">
            <div>
              <span className="chip subdued">{tr(language, 'Обновления', 'Updates')}</span>
              <h3>{updateInfo.available ? tr(language, 'Доступна новая версия', 'New version available') : tr(language, 'Релизная ветка', 'Release channel')}</h3>
            </div>
            <span className={`micro-pill ${updateTone === 'good' ? 'active' : ''}`}>{settings.releaseChannel}</span>
          </div>

          <div className="support-list compact-support-list">
            <div className="support-item"><strong>{tr(language, 'Текущая версия', 'Current version')}</strong><span>{updateInfo.currentVersion}</span></div>
            <div className="support-item"><strong>{tr(language, 'Источник', 'Source')}</strong><span>{updateInfo.source}</span></div>
            <div className="support-item"><strong>{tr(language, 'Статус', 'Status')}</strong><span>{updateInfo.message ?? '—'}</span></div>
            <div className="support-item"><strong>{tr(language, 'Интеграция', 'Integration')}</strong><span>{integrationMeta.modeLabel}</span></div>
          </div>

          <div className="settings-actions compact-actions">
            <button className="ghost-button" onClick={onCheckUpdates}><Download size={15} />{tr(language, 'Проверить', 'Check')}</button>
            {updateInfo.available && onInstallUpdate ? (
              <button className="ghost-button accent-action-button" onClick={onInstallUpdate}><Download size={15} />{tr(language, 'Обновить', 'Update')}</button>
            ) : null}
          </div>
        </section>
      </div>

      <div className="two-panel-grid compact-two-grid diagnostics-meta-grid">
        <section className="panel compact-panel">
          <div className="panel-header compact compact-header-row">
            <div>
              <span className="chip subdued">{tr(language, 'Подписка', 'Subscription')}</span>
              <h3>{safeSession.plan.title}</h3>
            </div>
          </div>

          <div className="support-list compact-support-list">
            <div className="support-item"><strong>{tr(language, 'Статус', 'Status')}</strong><span className={`status-value ${planState.tone}`}>{planState.title}</span></div>
            <div className="support-item"><strong>{tr(language, 'Срок', 'Expiry')}</strong><span>{planState.hint}</span></div>
            <div className="support-item"><strong>{tr(language, 'Трафик', 'Traffic')}</strong><span>{safeSession.plan.trafficUsedGb} / {safeSession.plan.trafficLimitGb} GB</span></div>
            <div className="support-item"><strong>{tr(language, 'Устройств', 'Devices')}</strong><span>{safeSession.plan.devices}</span></div>
            <div className="support-item"><strong>{tr(language, 'Panel URL', 'Panel URL')}</strong><span>{integrationMeta.panelUrl || tr(language, 'не указан', 'not set')}</span></div>
            <div className="support-item"><strong>{tr(language, 'Subscription URL', 'Subscription URL')}</strong><span>{integrationMeta.subscriptionUrl || tr(language, 'не указан', 'not set')}</span></div>
          </div>
        </section>

        <section className="panel compact-panel">
          <div className="panel-header compact compact-header-row">
            <div>
              <span className="chip subdued">{tr(language, 'История', 'History')}</span>
              <h3>{tr(language, 'Последние сессии', 'Recent sessions')}</h3>
            </div>
          </div>

          <div className="history-list compact-history-list">
            {safeSessionHistory.length ? safeSessionHistory.slice(0, 4).map((item) => (
              <article key={item.id} className="history-card">
                <div className="history-card-top">
                  <strong>{item.serverLabel}</strong>
                  <span>{item.durationLabel}</span>
                </div>
                <span>{formatDisplayTime(language, item.startedAt)}</span>
                <span className={`history-pill ${item.status}`}>{sessionStatusLabel(language)[item.status]}</span>
              </article>
            )) : (
              <div className="empty-state compact-empty-state">
                <strong>{tr(language, 'История сессий пока пуста', 'Session history is still empty')}</strong>
                <span>{tr(language, 'После первого подключения здесь появятся последние сессии.', 'Recent sessions will appear here after your first connection.')}</span>
              </div>
            )}
          </div>
        </section>
      </div>

      <section className="panel compact-panel">
        <div className="panel-header compact compact-header-row">
          <div>
            <span className="chip subdued">{tr(language, 'Параметры', 'Parameters')}</span>
            <h3>{tr(language, 'Язык, релизы и протокол', 'Language, releases and protocol')}</h3>
          </div>
        </div>

        <div className="settings-grid compact-settings-grid">
          <label className="select-field">
            <strong><Languages size={16} /> {tr(language, 'Язык интерфейса', 'Interface language')}</strong>
            <select value={settings.language} onChange={(event: ChangeEvent<HTMLSelectElement>) => onLanguageChange(event.target.value as AppSettings['language'])}>
              <option value="ru">Русский</option>
              <option value="en">English</option>
            </select>
          </label>

          <label className="select-field">
            <span>{tr(language, 'Канал обновлений', 'Release channel')}</span>
            <select value={settings.releaseChannel} onChange={(event: ChangeEvent<HTMLSelectElement>) => onReleaseChannelChange(event.target.value as AppSettings['releaseChannel'])}>
              <option value="stable">Stable</option>
              <option value="beta">Beta</option>
            </select>
          </label>

          <label className="select-field">
            <span>{tr(language, 'Предпочтение протокола', 'Protocol preference')}</span>
            <select value={settings.protocolStrategy} onChange={(event: ChangeEvent<HTMLSelectElement>) => onProtocolStrategyChange(event.target.value as AppSettings['protocolStrategy'])}>
              <option value="auto">{tr(language, 'Автоматически', 'Automatic')}</option>
              <option value="reality-first">{tr(language, 'Сначала Reality', 'Reality first')}</option>
              <option value="xray-only">{tr(language, 'Только Xray/VLESS', 'Xray/VLESS only')}</option>
            </select>
          </label>

          <label className="select-field">
            <span>{tr(language, 'Режим туннеля', 'Tunnel mode')}</span>
            <select value={settings.tunnelMode} onChange={(event: ChangeEvent<HTMLSelectElement>) => onTunnelModeChange(event.target.value as AppSettings['tunnelMode'])}>
              <option value="proxy">{tr(language, 'Proxy режим', 'Proxy mode')}</option>
              <option value="tun">{tr(language, 'TUN режим (экспериментальный)', 'TUN mode (experimental)')}</option>
            </select>
          </label>
        </div>

        <div className="settings-actions compact-actions">
          <button className="ghost-button danger-button" onClick={onClearAccessKey}>{tr(language, 'Удалить сохранённый ключ доступа', 'Remove stored access key')}</button>
        </div>
      </section>

      <section className="panel compact-panel">
        <div className="panel-header compact compact-header-row">
          <div>
            <span className="chip subdued">{tr(language, 'Журнал', 'Log')}</span>
            <h3>{tr(language, 'Последние строки', 'Recent log lines')}</h3>
          </div>
          <ClipboardList size={18} className="muted" />
        </div>

        <div className="log-list compact-log-list">
          {safeLogLines.map((line, index) => (
            <div key={`${index}-${line}`} className="log-line">{line}</div>
          ))}
        </div>
      </section>
    </div>
  );
}
