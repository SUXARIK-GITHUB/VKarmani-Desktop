import { BarChart3, CircleAlert, Headphones, Home, LogOut, Settings } from 'lucide-react';
import { tr, type UiLanguage } from '../i18n';
import type { AppTab, ConnectionState, DeviceRecord, RemnawaveSession } from '../types/vpn';

interface SidebarNavProps {
  activeTab: AppTab;
  onChange: (tab: AppTab) => void;
  onExit?: () => void;
  onShowInfo?: () => void;
  connectionState: ConnectionState;
  session: RemnawaveSession;
  devices: DeviceRecord[];
  language: UiLanguage;
  showDiagnostics: boolean;
}

export function SidebarNav({ activeTab, onChange, onExit, onShowInfo, language, showDiagnostics }: SidebarNavProps) {
  const items: Array<{ id: AppTab; label: string; icon: typeof Home }> = [
    { id: 'overview', label: tr(language, 'Главная', 'Home'), icon: Home },
    ...(showDiagnostics ? [{ id: 'diagnostics' as AppTab, label: tr(language, 'Статистика', 'Statistics'), icon: BarChart3 }] : []),
    { id: 'settings', label: tr(language, 'Настройки', 'Settings'), icon: Settings },
    { id: 'support', label: tr(language, 'Поддержка', 'Support'), icon: Headphones }
  ];

  return (
    <aside className="vk-sidebar">
      <div className="vk-sidebar-brand" aria-label="VKarmani">
        <div className="vk-orb-logo" aria-hidden="true">
          <img src="/assets/logo-vkarmani.png" alt="" className="vk-orb-logo-image" />
        </div>
      </div>

      <nav className="vk-sidebar-menu" aria-label={tr(language, 'Навигация', 'Navigation')}>
        {items.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              type="button"
              className={`vk-nav-item ${activeTab === item.id ? 'active' : ''}`}
              onClick={() => onChange(item.id)}
              aria-label={item.label}
              title={item.label}
            >
              <Icon size={22} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="vk-sidebar-footer">
        <button
          type="button"
          className="vk-info-button"
          onClick={onShowInfo}
          aria-label={tr(language, 'Информация о программе', 'Application information')}
          title={tr(language, 'Информация о программе', 'Application information')}
        >
          <CircleAlert size={21} />
        </button>
        <button
          type="button"
          className="vk-exit-button"
          onClick={onExit}
          aria-label={tr(language, 'Выйти', 'Exit')}
          title={tr(language, 'Выйти', 'Exit')}
        >
          <LogOut size={22} />
          <span>{tr(language, 'Выйти', 'Exit')}</span>
        </button>
      </div>
    </aside>
  );
}
