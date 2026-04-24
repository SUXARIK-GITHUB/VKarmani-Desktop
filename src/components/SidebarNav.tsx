import { Activity, LayoutDashboard, MonitorSmartphone, Server, Settings2 } from 'lucide-react';
import { tr, type UiLanguage } from '../i18n';
import type { AppTab, ConnectionState, DeviceRecord, RemnawaveSession } from '../types/vpn';

function resolveSidebarSubscription(language: UiLanguage, expiresAt: string) {
  const normalized = expiresAt?.trim();
  if (!normalized || normalized === '—' || normalized === 'Не ограничен' || normalized === 'Неизвестно') {
    return {
      title: tr(language, 'Подписка активна', 'Subscription active'),
      hint: '',
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
    title: active
      ? tr(language, 'Подписка активна', 'Subscription active')
      : tr(language, 'Подписка не активна', 'Subscription inactive'),
    hint: `${tr(language, 'До', 'Until')} ${normalized}`,
    tone: active ? ('good' as const) : ('bad' as const)
  };
}

interface SidebarNavProps {
  activeTab: AppTab;
  onChange: (tab: AppTab) => void;
  connectionState: ConnectionState;
  session: RemnawaveSession;
  devices: DeviceRecord[];
  language: UiLanguage;
  showDiagnostics: boolean;
}

export function SidebarNav({ activeTab, onChange, connectionState, session, language, showDiagnostics }: SidebarNavProps) {
  const statusText = {
    idle: tr(language, 'Не подключено', 'Disconnected'),
    connecting: tr(language, 'Подключение…', 'Connecting…'),
    connected: tr(language, 'Защищено', 'Protected'),
    disconnecting: tr(language, 'Отключение…', 'Disconnecting…')
  }[connectionState];

  const subscriptionState = resolveSidebarSubscription(language, session.plan.expiresAt);

  const labels: Record<AppTab, string> = {
    overview: tr(language, 'Обзор', 'Overview'),
    servers: tr(language, 'Серверы', 'Servers'),
    devices: tr(language, 'Устройства', 'Devices'),
    diagnostics: tr(language, 'Диагностика', 'Diagnostics'),
    settings: tr(language, 'Настройки', 'Settings')
  };

  const tabs: Array<{ id: AppTab; icon: typeof LayoutDashboard }> = [
    { id: 'overview', icon: LayoutDashboard },
    { id: 'servers', icon: Server },
    { id: 'devices', icon: MonitorSmartphone },
    ...(showDiagnostics ? [{ id: 'diagnostics' as AppTab, icon: Activity }] : []),
    { id: 'settings', icon: Settings2 }
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-profile">
        <span className={`chip status-chip ${connectionState}`}>{statusText}</span>
        <strong>{session.plan.title}</strong>
        <span className={`sidebar-subscription ${subscriptionState.tone}`}>{subscriptionState.title}</span>
        {subscriptionState.hint ? <span className="sidebar-hint single-line-hint">{subscriptionState.hint}</span> : null}
      </div>

      <nav className="sidebar-nav">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              className={`nav-button ${tab.id === activeTab ? 'active' : ''}`}
              onClick={() => onChange(tab.id)}
            >
              <Icon size={18} />
              <span>{labels[tab.id]}</span>
            </button>
          );
        })}
      </nav>
    </aside>
  );
}
