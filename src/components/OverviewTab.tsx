import {
  ArrowDown,
  ArrowUp,
  BarChart3,
  Check,
  Clock3,
  Globe2,
  Power,
  RefreshCw,
  SlidersHorizontal,
  Search,
  ShieldCheck,
  Signal,
  Star,
  Waypoints
} from 'lucide-react';
import { tr, type UiLanguage } from '../i18n';
import type { ConnectionState, TunnelMode, VpnServer } from '../types/vpn';
import { getServerPrimaryLabel, getServerSecondaryLabel, resolveServerFlag } from '../utils/serverDisplay';

interface OverviewTabProps {
  connectionState: ConnectionState;
  connectLabel: string;
  selectedServer: VpnServer | null;
  selectedServerId: string;
  servers: VpnServer[];
  allServerCount: number;
  searchValue: string;
  sessionDurationText: string;
  language: UiLanguage;
  showDiagnostics: boolean;
  tunnelMode: TunnelMode;
  onToggleConnection: () => void;
  onTunnelModeChange: (value: TunnelMode) => void;
  onSelectServer: (serverId: string) => void;
  onSearchChange: (value: string) => void;
  onRefreshServers: () => void;
  onRefreshPing: () => void;
  onToggleFavoriteServer: (serverId: string) => void;
  favoriteServerIds: string[];
  trafficReceivedText: string;
  trafficSentText: string;
  trafficChartBars: number[];
  vpnExternalIp: string;
  packetLossText: string;
  isCheckingPing?: boolean;
  pingProgressText?: string;
  checkingPingServerIds?: string[];
  canConnect: boolean;
  connectDisabledReason?: string;
  isSyncingProfile?: boolean;
  activeSplitTunnelCount: number;
  onOpenSplitTunnel: () => void;
}

function getProtocolLabel(server: VpnServer | null | undefined) {
  if (!server) {
    return 'VLESS | JSON';
  }

  const protocol = server.protocol === 'Xray' ? server.runtimeTemplate?.protocol?.toUpperCase() || 'XRAY' : server.protocol;
  const transport = server.transportLabel || server.runtimeTemplate?.transport?.toUpperCase() || 'JSON';
  return `${protocol} | ${transport}`;
}

function formatLatency(server: VpnServer | null | undefined, language: UiLanguage, isChecking = false) {
  if (isChecking || server?.latencyStatus === 'checking') {
    return tr(language, 'Проверяем…', 'Checking…');
  }

  if (server?.latencyStatus === 'failed') {
    return tr(language, 'Нет ответа', 'No response');
  }

  if (!server || server.latency === null || server.latency === undefined || !Number.isFinite(Number(server.latency))) {
    return tr(language, 'Не проверено', 'Not checked');
  }

  return `${Math.max(1, Math.round(Number(server.latency)))} мс`;
}

function latencyTone(server: VpnServer, isChecking = false) {
  if (isChecking || server.latencyStatus === 'checking') {
    return 'checking';
  }

  if (server.latencyStatus === 'failed') {
    return 'warn';
  }

  const latency = Number(server.latency);
  if (server.latency === null || server.latency === undefined || !Number.isFinite(latency)) {
    return 'muted';
  }

  if (latency >= 100) {
    return 'warn';
  }
  return 'good';
}

export function OverviewTab({
  connectionState,
  connectLabel,
  selectedServer,
  selectedServerId,
  servers,
  allServerCount,
  searchValue,
  sessionDurationText,
  language,
  showDiagnostics,
  tunnelMode,
  onToggleConnection,
  onTunnelModeChange,
  onSelectServer,
  onSearchChange,
  onRefreshServers,
  onRefreshPing,
  onToggleFavoriteServer,
  favoriteServerIds,
  trafficReceivedText,
  trafficSentText,
  trafficChartBars,
  vpnExternalIp,
  packetLossText,
  isCheckingPing = false,
  pingProgressText = '',
  checkingPingServerIds = [],
  canConnect,
  connectDisabledReason = '',
  isSyncingProfile,
  activeSplitTunnelCount,
  onOpenSplitTunnel
}: OverviewTabProps) {
  const isConnected = connectionState === 'connected';
  const flag = selectedServer ? resolveServerFlag(selectedServer) : '🌐';
  const selectedName = selectedServer ? getServerPrimaryLabel(selectedServer) : tr(language, 'Сервер не выбран', 'No server selected');
  const selectedMeta = selectedServer
    ? getServerSecondaryLabel(selectedServer, showDiagnostics)
    : tr(language, 'Выберите сервер из списка', 'Choose a server from the list');
  const selectedProtocol = getProtocolLabel(selectedServer);
  const filteredServerCount = servers.length;
  const favoriteServerIdSet = new Set(favoriteServerIds);
  const checkingPingServerIdSet = new Set(checkingPingServerIds);
  const selectedLatency = formatLatency(selectedServer, language, Boolean(selectedServer && checkingPingServerIdSet.has(selectedServer.id)));

  return (
    <div className="vk-dashboard">
      <section className={`vk-hero-card ${connectionState}`}>
        <div className="vk-hero-status">
          <div className="vk-shield-ring"><ShieldCheck size={44} /></div>
          <div>
            <h1>{isConnected ? tr(language, 'Подключен', 'Connected') : connectLabel}</h1>
            <p><span className={isConnected ? 'green-dot' : 'blue-dot'} />{isConnected ? tr(language, 'Стабильное соединение', 'Stable connection') : tr(language, 'Готов к безопасному подключению', 'Ready for secure connection')}</p>
          </div>
        </div>

        <div className="vk-world-lines" aria-hidden="true">
          <span />
          <i />
          <b />
        </div>

        <div className="vk-hero-server">
          <span className="vk-flag-large">{flag}</span>
          <div className="vk-hero-server-copy">
            <strong>{selectedName}</strong>
            <span>{selectedMeta} · {selectedProtocol}</span>
          </div>
          <div className="vk-hero-latency">
            <Signal size={26} />
            <strong>{selectedLatency}</strong>
          </div>
        </div>
      </section>

      <section className="vk-card vk-server-card">
        <div className="vk-card-header vk-card-header-row">
          <h2>{tr(language, 'Серверы', 'Servers')}</h2>
          <div className="vk-server-tools">
            <label className="vk-search-box">
              <Search size={18} />
              <input
                value={searchValue}
                onChange={(event) => onSearchChange(event.target.value)}
                placeholder={tr(language, 'Поиск серверов', 'Search servers')}
              />
            </label>
          </div>
        </div>

        <div className="vk-server-list">
          {servers.map((server) => {
            const active = server.id === selectedServerId;
            const isFavorite = favoriteServerIdSet.has(server.id);
            const serverPingChecking = checkingPingServerIdSet.has(server.id);
            return (
              <div
                key={server.id}
                className={`vk-server-row ${active ? 'active' : ''}`}
              >
                <button
                  type="button"
                  className="vk-server-select-button"
                  onClick={() => onSelectServer(server.id)}
                  aria-pressed={active}
                >
                  <span className="vk-server-flag">{resolveServerFlag(server)}</span>
                  <span className="vk-server-copy">
                    <strong>{getServerPrimaryLabel(server)}</strong>
                    <small>{getProtocolLabel(server)}</small>
                  </span>
                  <span className="vk-server-quality">
                    {active ? <span className="vk-check-badge"><Check size={13} /></span> : null}
                    <Signal size={20} />
                    <strong className={latencyTone(server, serverPingChecking)}>{formatLatency(server, language, serverPingChecking)}</strong>
                  </span>
                </button>
                <button
                  type="button"
                  className={`vk-favorite-star ${isFavorite ? 'active' : ''}`}
                  aria-label={isFavorite ? tr(language, 'Убрать из избранного', 'Remove from favorites') : tr(language, 'Добавить в избранное', 'Add to favorites')}
                  title={isFavorite ? tr(language, 'Убрать из избранного', 'Remove from favorites') : tr(language, 'Добавить в избранное', 'Add to favorites')}
                  onClick={() => onToggleFavoriteServer(server.id)}
                >
                  <Star size={21} fill={isFavorite ? 'currentColor' : 'none'} />
                </button>
              </div>
            );
          })}

          {!servers.length ? (
            <div className="vk-empty-list">
              <strong>{tr(language, 'Серверы не найдены', 'No servers found')}</strong>
              <span>{tr(language, 'Обновите профиль или измените поиск.', 'Refresh the profile or change the search.')}</span>
            </div>
          ) : null}
        </div>

        <div className="vk-server-footer">
          <span>{tr(language, `Всего серверов: ${allServerCount || filteredServerCount}`, `Total servers: ${allServerCount || filteredServerCount}`)}</span>
          <div className="vk-server-footer-actions">
            <button type="button" className="vk-secondary-action" onClick={onRefreshServers} disabled={Boolean(isSyncingProfile)}>
              <RefreshCw size={18} className={isSyncingProfile ? 'spin-icon' : ''} />
              {isSyncingProfile ? tr(language, 'Обновляем…', 'Refreshing…') : tr(language, 'Обновить серверы', 'Refresh servers')}
            </button>
            <button
              type="button"
              className={`vk-secondary-action vk-ping-action ${isCheckingPing ? 'background-running' : ''}`}
              onClick={onRefreshPing}
              aria-busy={isCheckingPing}
              title={isCheckingPing ? tr(language, 'Пинг проверяется в фоне. Остальные кнопки доступны.', 'Ping is checking in the background. Other buttons remain available.') : undefined}
            >
              <RefreshCw size={18} className={isCheckingPing ? 'spin-icon' : ''} />
              {isCheckingPing ? (pingProgressText || tr(language, 'Проверяем…', 'Checking…')) : tr(language, 'Проверить пинг', 'Check ping')}
            </button>
          </div>
        </div>
      </section>

      <aside className="vk-dashboard-side">
        <article className="vk-card vk-traffic-card">
          <div className="vk-card-header small">
            <h3><BarChart3 size={19} /> {tr(language, 'Трафик', 'Traffic')}</h3>
          </div>
          <div className="vk-traffic-chart" aria-hidden="true">
            {trafficChartBars.map((height, index) => (
              <span key={`${height}-${index}`} style={{ height: `${height}%` }} />
            ))}
          </div>
          <div className="vk-traffic-stats">
            <span><ArrowDown size={20} />{tr(language, 'Получено', 'Received')}<strong>{trafficReceivedText}</strong></span>
            <span><ArrowUp size={20} />{tr(language, 'Отправлено', 'Sent')}<strong>{trafficSentText}</strong></span>
          </div>
        </article>

        <article className="vk-card vk-session-card">
          <div className="vk-card-header small">
            <h3><Clock3 size={19} /> {tr(language, 'Сессия', 'Session')}</h3>
          </div>
          <strong className="vk-session-time">{isConnected ? sessionDurationText : '00:00:00'}</strong>
          <div className="vk-session-lines">
            <span>{tr(language, 'Протокол', 'Protocol')}<strong>{selectedProtocol}</strong></span>
            <span>{tr(language, 'IP-адрес', 'IP address')}<strong>{vpnExternalIp}</strong></span>
            <span>{tr(language, 'Потеря пакетов', 'Packet loss')}<strong>{packetLossText}</strong></span>
          </div>
        </article>

        <article className="vk-card vk-mode-card">
          <div className="vk-card-header small">
            <h3><Globe2 size={19} /> {tr(language, 'Режим подключения', 'Connection mode')}</h3>
          </div>
          <div className="vk-mode-options">
            <button type="button" className={`vk-mode-option ${tunnelMode === 'proxy' ? 'active' : ''}`} onClick={() => onTunnelModeChange('proxy')}>
              <Globe2 size={26} />
              <span>Proxy</span>
              <i />
            </button>
            <button type="button" className={`vk-mode-option ${tunnelMode === 'tun' ? 'active' : ''}`} onClick={() => onTunnelModeChange('tun')}>
              <Waypoints size={26} />
              <span>TUN</span>
              <i>{tunnelMode === 'tun' ? <Check size={14} /> : null}</i>
            </button>
          </div>
        </article>

        <div className={`vk-power-actions ${tunnelMode === 'tun' ? 'with-tun-tools' : ''}`}>
          <button
            type="button"
            className={`vk-primary-power ${connectionState}`}
            onClick={onToggleConnection}
            disabled={connectionState === 'disconnecting' || (!canConnect && connectionState === 'idle')}
            title={!canConnect && connectDisabledReason ? connectDisabledReason : undefined}
          >
            <Power size={34} />
            <span>{connectLabel}</span>
          </button>

          {tunnelMode === 'tun' ? (
            <button
              type="button"
              className="vk-tun-config-button"
              onClick={onOpenSplitTunnel}
              title={tr(language, 'Выбрать приложения и службы для TUN', 'Choose apps and services for TUN')}
            >
              <SlidersHorizontal size={22} />
              <span>{tr(language, 'Приложения', 'TUN apps')}</span>
              <strong>{activeSplitTunnelCount}</strong>
            </button>
          ) : null}
        </div>
      </aside>
    </div>
  );
}
