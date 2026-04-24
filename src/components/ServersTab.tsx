import { Search, Shield, Star, Zap } from 'lucide-react';
import { tr, type UiLanguage } from '../i18n';
import type { ConnectionState, VpnServer } from '../types/vpn';
import { getServerPrimaryLabel, getServerSecondaryLabel, resolveServerFlag } from '../utils/serverDisplay';

interface ServersTabProps {
  servers: VpnServer[];
  allServerCount: number;
  selectedServerId: string;
  searchValue: string;
  language: UiLanguage;
  syncMessage?: string;
  showDiagnostics: boolean;
  connectionState: ConnectionState;
  onSearchChange: (value: string) => void;
  onSelectServer: (serverId: string) => void;
}

export function ServersTab({
  servers,
  allServerCount,
  selectedServerId,
  searchValue,
  language,
  syncMessage,
  showDiagnostics,
  connectionState,
  onSearchChange,
  onSelectServer
}: ServersTabProps) {
  const hasSearch = Boolean(searchValue.trim());
  const hasAnyServers = allServerCount > 0;

  return (
    <section className="panel">
      <div className="panel-header compact-header-row">
        <div>
          <span className="chip subdued">{tr(language, 'Серверы', 'Servers')}</span>
          <h3>{tr(language, 'Доступные локации', 'Available locations')}</h3>
        </div>
      </div>



      <div className="search-row">
        <Search size={16} />
        <input
          value={searchValue}
          onChange={(event: React.ChangeEvent<HTMLInputElement>) => onSearchChange(event.target.value)}
          placeholder={tr(language, 'Поиск по стране, городу, протоколу…', 'Search by country, city, protocol…')}
        />
      </div>

      <div className="server-list compact-server-list">
        {!hasAnyServers ? (
          <div className="empty-state">
            <strong>{tr(language, 'Список серверов пока пуст', 'Server list is empty')}</strong>
            <span>{syncMessage ?? tr(language, 'Синхронизируйте live-профиль Remnawave, чтобы загрузить ваши узлы.', 'Sync your live Remnawave profile to load your nodes.')}</span>
          </div>
        ) : null}

        {hasAnyServers && hasSearch && servers.length === 0 ? (
          <div className="empty-state">
            <strong>{tr(language, 'Ничего не найдено', 'Nothing found')}</strong>
            <span>{tr(language, 'Попробуйте убрать часть запроса или искать по стране, городу, протоколу и тегам.', 'Try a shorter query or search by country, city, protocol, and tags.')}</span>
          </div>
        ) : null}

        {servers.map((server) => {
          const ready = Boolean(server.runtimeTemplate);
          const flag = resolveServerFlag(server);
          const primaryLabel = getServerPrimaryLabel({ ...server, flag });
          const secondaryLabel = getServerSecondaryLabel(server, false);
          const diagnosticsLabel = showDiagnostics ? getServerSecondaryLabel(server, true) : undefined;
          const isSelected = server.id === selectedServerId;

          return (
            <button
              key={server.id}
              className={`server-card ${isSelected ? 'active' : ''}`}
              onClick={() => onSelectServer(server.id)}
            >
              <div className="server-main">
                <div className="server-flag">{flag}</div>
                <div>
                  <strong>{primaryLabel}</strong>
                  {secondaryLabel ? <div className="server-location-note">{secondaryLabel}</div> : null}
                  <span>
                    {server.protocol}
                    {server.transportLabel ? ` / ${server.transportLabel}` : ''} · {tr(language, 'пинг', 'ping')} {server.latency} ms
                    {showDiagnostics && server.ipPool ? ` · ${tr(language, 'узел', 'node')} ${server.ipPool}` : ''}
                  </span>
                  {diagnosticsLabel ? <div className="server-location-note server-diagnostics-note">{diagnosticsLabel}</div> : null}
                  <div className="tag-row">
                    {(server.tags ?? []).map((tag) => (
                      <span key={tag} className="micro-pill">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="server-side">
                {isSelected ? (
                  <span className="recommend-pill">
                    <Star size={13} />
                    {connectionState === 'connected' ? tr(language, 'Выбран для переключения', 'Selected for switching') : tr(language, 'Текущий выбор', 'Current selection')}
                  </span>
                ) : null}
                {server.isRecommended ? (
                  <span className="recommend-pill">
                    <Star size={13} />
                    {tr(language, 'Рекомендуем', 'Recommended')}
                  </span>
                ) : null}
                <span className="metric-label">
                  <Shield size={13} /> {tr(language, 'Нагрузка', 'Load')} {server.load}%
                </span>
                <span className={`runtime-badge ${ready ? 'ready' : 'waiting'}`}>
                  <Zap size={13} /> {ready ? tr(language, 'Готов к подключению', 'Ready to connect') : tr(language, 'Нужен live import', 'Needs live import')}
                </span>
              </div>
            </button>
          );
        })}
      </div>
    </section>
  );
}
