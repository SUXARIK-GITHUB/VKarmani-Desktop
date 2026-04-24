import { Bell, Bolt, MonitorCog, Shield, Sparkles } from 'lucide-react';
import { tr, type UiLanguage } from '../i18n';
import type { AppSettings } from '../types/vpn';

interface SettingsTabProps {
  settings: AppSettings;
  language: UiLanguage;
  onToggleSetting: (key: keyof Omit<AppSettings, 'releaseChannel' | 'protocolStrategy' | 'language' | 'allowDemoFallback' | 'tunnelMode'>) => void;
  onTunnelModeChange: (value: AppSettings['tunnelMode']) => void;
}

type ToggleKey = keyof Omit<AppSettings, 'releaseChannel' | 'protocolStrategy' | 'language' | 'allowDemoFallback' | 'tunnelMode'>;

interface ToggleItem {
  key: ToggleKey;
  title: string;
  description: string;
}

export function SettingsTab({ settings, language, onToggleSetting, onTunnelModeChange }: SettingsTabProps) {
  const groups: Array<{ title: string; subtitle: string; icon: typeof Shield; items: ToggleItem[] }> = [
    {
      title: tr(language, 'Подключение и профиль', 'Connection and profile'),
      subtitle: tr(language, 'Настройки, которые влияют на вход, старт туннеля и обновление live-профиля.', 'Options that affect sign-in, tunnel startup, and live profile sync.'),
      icon: Shield,
      items: [
        {
          key: 'autoConnect',
          title: tr(language, 'Автоподключение', 'Auto-connect'),
          description: tr(language, 'Поднимать туннель после успешного входа по ключу', 'Start the tunnel after successful sign-in')
        },
        {
          key: 'profileSyncOnLogin',
          title: tr(language, 'Синхронизация профиля при входе', 'Sync profile on sign-in'),
          description: tr(language, 'Сразу подтягивать subscription-профиль Remnawave', 'Fetch the Remnawave subscription profile immediately')
        },
        {
          key: 'useSystemProxy',
          title: tr(language, 'Системный proxy после подключения', 'Enable system proxy after connect'),
          description: tr(language, 'Направлять HTTP/HTTPS трафик Windows в локальный HTTP inbound Xray', 'Route Windows HTTP/HTTPS traffic into the local Xray HTTP inbound')
        },
        {
          key: 'probeOnConnect',
          title: tr(language, 'Проверять маршрут после подключения', 'Run probe after connect'),
          description: tr(language, 'Сразу проверять локальные порты и внешний IP', 'Check local ports and public IP immediately after connect')
        }
      ]
    },
    {
      title: tr(language, 'Система и фоновые действия', 'System and background behavior'),
      subtitle: tr(language, 'То, как приложение ведёт себя при запуске Windows и при закрытии окна.', 'How the app behaves on Windows startup and when the window is closed.'),
      icon: MonitorCog,
      items: [
        {
          key: 'launchOnStartup',
          title: tr(language, 'Автозапуск', 'Launch on startup'),
          description: tr(language, 'Запускать VKarmani вместе с системой', 'Start VKarmani with the operating system')
        },
        {
          key: 'runAsAdmin',
          title: tr(language, 'Запуск с правами администратора', 'Run with administrator rights'),
          description: tr(language, 'В собранной версии VKarmani запросит права администратора при старте, если они нужны системным действиям', 'In the packaged build VKarmani will request administrator rights on start when system actions require them')
        },
        {
          key: 'minimizeToTray',
          title: tr(language, 'Сворачивать в трей', 'Minimize to tray'),
          description: tr(language, 'При закрытии окна оставлять приложение в фоне', 'Keep the app running in the background when the window is closed')
        },
        {
          key: 'showDiagnostics',
          title: tr(language, 'Диагностика', 'Diagnostics'),
          description: tr(language, 'Показывать вкладку для продвинутой диагностики и служебной информации', 'Show the advanced diagnostics and service information tab')
        }
      ]
    },
    {
      title: tr(language, 'Обновления и интерфейс', 'Updates and interface'),
      subtitle: tr(language, 'Косметика и то, как клиент сообщает о событиях и релизах.', 'Visual polish and how the client reports events and releases.'),
      icon: Sparkles,
      items: [
        {
          key: 'autoUpdate',
          title: tr(language, 'Автообновления', 'Auto-updates'),
          description: tr(language, 'Проверять релизы и предлагать установку новой версии', 'Check releases and offer a new version when available')
        },
        {
          key: 'notifications',
          title: tr(language, 'Уведомления', 'Notifications'),
          description: tr(language, 'Показывать статус подключения и обновлений', 'Show connection and update status')
        },
        {
          key: 'themeGlow',
          title: tr(language, 'Световой акцент', 'Glow accent'),
          description: tr(language, 'Подсвечивать активные состояния в фирменном стиле', 'Highlight active states using the VKarmani visual accent')
        }
      ]
    }
  ];

  return (
    <div className="tab-stack compact-tab-stack">
      <section className="panel compact-panel">
        <div className="panel-header compact compact-header-row">
          <div>
            <span className="chip subdued">{tr(language, 'Быстрые рекомендации', 'Quick recommendations')}</span>
            <h3>{tr(language, 'Что обычно включают', 'What is usually enabled')}</h3>
          </div>
        </div>

        <div className="settings-tip-grid">
          <article className="support-item compact-support-item">
            <Bolt size={18} />
            <div>
              <strong>{tr(language, 'Для повседневного использования', 'For daily use')}</strong>
              <span>{tr(language, 'Автоподключение + sync профиля + уведомления.', 'Auto-connect + profile sync + notifications.')}</span>
            </div>
          </article>
          <article className="support-item compact-support-item">
            <MonitorCog size={18} />
            <div>
              <strong>{tr(language, 'Для фоновой работы', 'For background use')}</strong>
              <span>{tr(language, 'Автозапуск и сворачивание в трей делают клиент менее навязчивым.', 'Launch on startup and minimize to tray make the client less intrusive.')}</span>
            </div>
          </article>
          <article className="support-item compact-support-item">
            <Bell size={18} />
            <div>
              <strong>{tr(language, 'Для контроля соединения', 'For connection awareness')}</strong>
              <span>{tr(language, 'Probe после подключения помогает быстро понять, жив ли маршрут.', 'Probe after connect helps confirm the route is actually alive.')}</span>
            </div>
          </article>
        </div>
      </section>

      <section className="panel compact-panel">
        <div className="panel-header compact compact-header-row">
          <div>
            <span className="chip subdued">{tr(language, 'Маршрутизация', 'Routing mode')}</span>
            <h3>{tr(language, 'Режим туннеля', 'Tunnel mode')}</h3>
          </div>
        </div>

        <div className="settings-tip-grid">
          <button className={`setting-row button-row ${settings.tunnelMode === 'proxy' ? 'setting-row-active' : ''}`} onClick={() => onTunnelModeChange('proxy')}>
            <div className="setting-copy">
              <strong>{tr(language, 'Proxy режим', 'Proxy mode')}</strong>
              <span>{tr(language, 'Классический режим: Xray поднимает локальные SOCKS/HTTP порты, а Windows-трафик можно отправлять через system proxy.', 'Classic mode: Xray exposes local SOCKS/HTTP ports and Windows traffic can be routed through the system proxy.')}</span>
            </div>
            <div className="setting-side">
              <span className={`micro-pill ${settings.tunnelMode === 'proxy' ? 'active' : ''}`}>{settings.tunnelMode === 'proxy' ? tr(language, 'Выбран', 'Selected') : tr(language, 'Доступен', 'Available')}</span>
            </div>
          </button>

          <button className={`setting-row button-row ${settings.tunnelMode === 'tun' ? 'setting-row-active' : ''}`} onClick={() => onTunnelModeChange('tun')}>
            <div className="setting-copy">
              <strong>{tr(language, 'TUN режим', 'TUN mode')}</strong>
              <span>{tr(language, 'Экспериментальный полный маршрут: Xray создаёт TUN-интерфейс и клиент добавляет Windows-маршруты. Для него обычно нужны права администратора.', 'Experimental full-route mode: Xray creates a TUN interface and the client adds Windows routes. This usually requires administrator rights.')}</span>
            </div>
            <div className="setting-side">
              <span className={`micro-pill ${settings.tunnelMode === 'tun' ? 'active' : ''}`}>{settings.tunnelMode === 'tun' ? tr(language, 'Выбран', 'Selected') : tr(language, 'Экспериментальный', 'Experimental')}</span>
            </div>
          </button>
        </div>
      </section>

      <div className="settings-group-grid">
        {groups.map((group) => {
          const Icon = group.icon;
          return (
            <section key={group.title} className="panel compact-panel settings-group-panel">
              <div className="panel-header compact compact-header-row settings-group-header">
                <div>
                  <span className="chip subdued">{group.title}</span>
                  <h3>{group.title}</h3>
                  <p className="muted settings-group-note">{group.subtitle}</p>
                </div>
                <div className="settings-group-icon">
                  <Icon size={18} />
                </div>
              </div>

              <div className="quick-settings compact-quick-settings settings-group-list">
                {group.items.map((item) => (
                  <button key={item.key} className="setting-row button-row" onClick={() => onToggleSetting(item.key)}>
                    <div className="setting-copy">
                      <strong>{item.title}</strong>
                      <span>{item.description}</span>
                    </div>
                    <div className="setting-side">
                      <span className={`micro-pill ${settings[item.key] ? 'active' : ''}`}>
                        {settings[item.key] ? tr(language, 'Вкл', 'On') : tr(language, 'Выкл', 'Off')}
                      </span>
                      <div className={`toggle ${settings[item.key] ? 'on' : ''}`} />
                    </div>
                  </button>
                ))}
              </div>
            </section>
          );
        })}
      </div>

    </div>
  );
}
