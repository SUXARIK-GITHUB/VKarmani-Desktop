import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Bell, Download, Globe2, Languages, MonitorCog, Palette, RefreshCw, Route, Shield, SlidersHorizontal, Split, Star, Wifi, Zap } from 'lucide-react';
import { tr, type UiLanguage } from '../i18n';
import type { AppSettings } from '../types/vpn';

interface SettingsTabProps {
  settings: AppSettings;
  language: UiLanguage;
  onToggleSetting: (key: keyof Omit<AppSettings, 'releaseChannel' | 'protocolStrategy' | 'language' | 'allowDemoFallback' | 'tunnelMode'>) => void;
  onTunnelModeChange: (value: AppSettings['tunnelMode']) => void;
  onLanguageChange: (value: UiLanguage) => void;
}

type ToggleKey = keyof Omit<AppSettings, 'releaseChannel' | 'protocolStrategy' | 'language' | 'allowDemoFallback' | 'tunnelMode'>;
type SectionId = 'general' | 'network' | 'tunnel' | 'split' | 'proxy' | 'startup' | 'notifications' | 'diagnostics';

interface ToggleItem {
  key: ToggleKey;
  title: string;
  description: string;
  icon: typeof Shield;
}

function scrollToSettingsSection(id: SectionId) {
  const target = document.getElementById(`settings-${id}`);
  if (!target) {
    return;
  }

  const container = target.closest('.settings-screen-redesign') as HTMLElement | null;
  if (container) {
    container.scrollTo({
      top: Math.max(0, target.offsetTop - container.offsetTop - 12),
      behavior: 'smooth'
    });
    return;
  }

  target.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function ToggleRow({ item, enabled, onClick, language }: { item: ToggleItem; enabled: boolean; onClick: () => void; language: UiLanguage }) {
  const Icon = item.icon;
  return (
    <button className={`setting-row button-row ${enabled ? 'setting-row-active' : ''}`} onClick={onClick} type="button">
      <div className="setting-row-icon"><Icon size={18} /></div>
      <div className="setting-copy">
        <strong>{item.title}</strong>
        <span>{item.description}</span>
      </div>
      <div className="setting-side">
        <span className={`micro-pill ${enabled ? 'active' : ''}`}>{enabled ? tr(language, 'Вкл', 'On') : tr(language, 'Выкл', 'Off')}</span>
        <div className={`toggle ${enabled ? 'on' : ''}`} />
      </div>
    </button>
  );
}

function SettingsSection({ id, kicker, title, icon: Icon, children }: { id: SectionId; kicker: string; title: string; icon: typeof Shield; children: ReactNode }) {
  return (
    <section id={`settings-${id}`} className="settings-wide-panel panel settings-anchor-section">
      <div className="panel-header compact compact-header-row">
        <div>
          <span className="section-kicker">{kicker}</span>
          <h3>{title}</h3>
        </div>
        <Icon size={19} />
      </div>
      {children}
    </section>
  );
}

export function SettingsTab({ settings, language, onToggleSetting, onTunnelModeChange, onLanguageChange }: SettingsTabProps) {
  const [activeSection, setActiveSection] = useState<SectionId>('general');
  const scrollSpyFrameRef = useRef<number | null>(null);
  const nextLanguage: UiLanguage = language === 'ru' ? 'en' : 'ru';

  const tabs: Array<{ id: SectionId; label: string }> = [
    { id: 'general', label: tr(language, 'Общие', 'General') },
    { id: 'network', label: tr(language, 'Сеть', 'Network') },
    { id: 'tunnel', label: tr(language, 'Режим туннеля', 'Tunnel mode') },
    { id: 'split', label: tr(language, 'Раздельное туннелирование', 'Split tunneling') },
    { id: 'proxy', label: tr(language, 'Системный прокси', 'System proxy') },
    { id: 'startup', label: tr(language, 'Автозапуск', 'Startup') },
    { id: 'notifications', label: tr(language, 'Уведомления', 'Notifications') },
    { id: 'diagnostics', label: tr(language, 'Диагностика', 'Diagnostics') }
  ];

  const sections: Record<SectionId, ToggleItem[]> = {
    general: [
      {
        key: 'minimizeToTray',
        title: tr(language, 'Минимизировать в трей', 'Minimize to tray'),
        description: tr(language, 'Сворачивать приложение в системный трей при закрытии', 'Keep the app in the system tray when closing the window'),
        icon: SlidersHorizontal
      },
      {
        key: 'themeGlow',
        title: tr(language, 'Световой акцент', 'Glow accent'),
        description: tr(language, 'Подсвечивать активные состояния фирменным синим цветом', 'Highlight active states with the branded blue accent'),
        icon: Palette
      }
    ],
    network: [
      {
        key: 'autoConnect',
        title: tr(language, 'Автоподключение', 'Auto-connect'),
        description: tr(language, 'Поднимать туннель после успешного входа по ключу', 'Start the tunnel after successful sign-in'),
        icon: Zap
      },
      {
        key: 'autoConnectFavorite',
        title: tr(language, 'После запуска подключаться к избранному серверу', 'Connect to a favorite server after launch'),
        description: tr(language, 'При запуске с сохранённым ключом VKarmani автоматически выберет первый доступный избранный сервер.', 'With a saved key, VKarmani will automatically choose the first available favorite server on launch.'),
        icon: Star
      },
      {
        key: 'profileSyncOnLogin',
        title: tr(language, 'Синхронизация профиля при входе', 'Sync profile on sign-in'),
        description: tr(language, 'Сразу подтягивать subscription-профиль Remnawave', 'Fetch the Remnawave subscription profile immediately'),
        icon: RefreshCw
      },
      {
        key: 'probeOnConnect',
        title: tr(language, 'Проверять маршрут после подключения', 'Run probe after connect'),
        description: tr(language, 'Сразу проверять локальные порты и внешний IP', 'Check local ports and public IP immediately after connect'),
        icon: Shield
      }
    ],
    tunnel: [],
    split: [],
    proxy: [
      {
        key: 'useSystemProxy',
        title: tr(language, 'Системный прокси', 'System proxy'),
        description: tr(language, 'Направлять HTTP/HTTPS трафик Windows в локальный HTTP inbound Xray', 'Route Windows HTTP/HTTPS traffic into the local Xray HTTP inbound'),
        icon: Wifi
      }
    ],
    startup: [
      {
        key: 'launchOnStartup',
        title: tr(language, 'Запускать при старте Windows', 'Launch on Windows startup'),
        description: tr(language, 'Автоматически запускать приложение при включении компьютера', 'Start the app automatically when the computer turns on'),
        icon: MonitorCog
      },
      {
        key: 'runAsAdmin',
        title: tr(language, 'Запуск с правами администратора', 'Run with administrator rights'),
        description: tr(language, 'Нужно для системных действий и TUN-режима', 'Needed for system actions and TUN mode'),
        icon: Shield
      }
    ],
    notifications: [
      {
        key: 'notifications',
        title: tr(language, 'Уведомления', 'Notifications'),
        description: tr(language, 'Показывать статус подключения и обновлений', 'Show connection and update status'),
        icon: Bell
      },
      {
        key: 'autoUpdate',
        title: tr(language, 'Автопроверка обновлений', 'Auto-check updates'),
        description: tr(language, 'Проверять релизы в фоне', 'Check releases in the background'),
        icon: RefreshCw
      },
      {
        key: 'autoInstallUpdates',
        title: tr(language, 'Автоустановка обновлений', 'Auto-install updates'),
        description: tr(language, 'Устанавливать найденные обновления автоматически', 'Install found updates automatically'),
        icon: Download
      }
    ],
    diagnostics: [
      {
        key: 'showDiagnostics',
        title: tr(language, 'Расширенная диагностика', 'Advanced diagnostics'),
        description: tr(language, 'Показывать вкладку диагностики и служебной информации', 'Show diagnostics and service information tab'),
        icon: Shield
      }
    ]
  };

  const handleTabClick = (id: SectionId) => {
    setActiveSection(id);
    window.requestAnimationFrame(() => scrollToSettingsSection(id));
  };

  useEffect(() => {
    const container = document.querySelector('.settings-screen-redesign') as HTMLElement | null;
    if (!container) {
      return;
    }

    const sectionIds = tabs.map((tab) => tab.id);

    const updateActiveSection = () => {
      if (scrollSpyFrameRef.current !== null) {
        window.cancelAnimationFrame(scrollSpyFrameRef.current);
      }

      scrollSpyFrameRef.current = window.requestAnimationFrame(() => {
        const scrollMarker = container.scrollTop + 180;
        let nextActive = sectionIds[0];

        for (const id of sectionIds) {
          const section = document.getElementById(`settings-${id}`);
          if (!section) {
            continue;
          }

          if (section.offsetTop <= scrollMarker) {
            nextActive = id;
          }
        }

        setActiveSection((current) => (current === nextActive ? current : nextActive));
        scrollSpyFrameRef.current = null;
      });
    };

    updateActiveSection();
    container.addEventListener('scroll', updateActiveSection, { passive: true });
    window.addEventListener('resize', updateActiveSection);

    return () => {
      if (scrollSpyFrameRef.current !== null) {
        window.cancelAnimationFrame(scrollSpyFrameRef.current);
        scrollSpyFrameRef.current = null;
      }
      container.removeEventListener('scroll', updateActiveSection);
      window.removeEventListener('resize', updateActiveSection);
    };
  }, [language]);

  return (
    <div className="settings-screen-redesign">
      <section className="settings-hero-line">
        <div>
          <span className="section-kicker">VKarmani</span>
          <h1>{tr(language, 'Настройки', 'Settings')}</h1>
          <p>{tr(language, 'Управляйте параметрами приложения, подключения и системной интеграции.', 'Manage application, connection, and system integration settings.')}</p>
        </div>
        <div className="settings-health-card">
          <span className="system-status-dot" />
          <div>
            <strong>{tr(language, 'Все системы работают', 'All systems operational')}</strong>
            <small>{tr(language, 'Параметры применяются сразу', 'Settings apply instantly')}</small>
          </div>
        </div>
      </section>

      <div className="settings-tab-strip" role="tablist" aria-label={tr(language, 'Разделы настроек', 'Settings sections')}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={activeSection === tab.id}
            className={activeSection === tab.id ? 'active' : ''}
            onClick={() => handleTabClick(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="settings-redesign-grid">
        <SettingsSection id="general" kicker={tr(language, 'Общие', 'General')} title={tr(language, 'Основные параметры', 'Core preferences')} icon={Globe2}>
          <div className="settings-list-modern">
            <button className="setting-row button-row" type="button" onClick={() => onLanguageChange(nextLanguage)}>
              <div className="setting-row-icon"><Languages size={18} /></div>
              <div className="setting-copy">
                <strong>{tr(language, 'Язык интерфейса', 'Interface language')}</strong>
                <span>{tr(language, 'Нажмите, чтобы переключить русский / английский интерфейс', 'Click to switch Russian / English interface')}</span>
              </div>
              <div className="select-field">{language === 'ru' ? 'Русский' : 'English'}</div>
            </button>
            {sections.general.map((item) => (
              <ToggleRow key={item.key} item={item} enabled={Boolean(settings[item.key])} onClick={() => onToggleSetting(item.key)} language={language} />
            ))}
          </div>
        </SettingsSection>

        <SettingsSection id="network" kicker={tr(language, 'Сеть', 'Network')} title={tr(language, 'Поведение подключения', 'Connection behavior')} icon={Wifi}>
          <div className="settings-two-columns">
            {sections.network.map((item) => (
              <ToggleRow key={item.key} item={item} enabled={Boolean(settings[item.key])} onClick={() => onToggleSetting(item.key)} language={language} />
            ))}
          </div>
        </SettingsSection>

        <SettingsSection id="tunnel" kicker={tr(language, 'Режим туннеля', 'Tunnel mode')} title={tr(language, 'Proxy или TUN', 'Proxy or TUN')} icon={Route}>
          <div className="settings-mode-card-inline">
            <div>
              <h4>{settings.tunnelMode === 'tun' ? 'TUN' : 'Proxy'}</h4>
              <p>{settings.tunnelMode === 'tun'
                ? tr(language, 'TUN-режим шифрует выбранный системный трафик через VPN.', 'TUN mode routes selected system traffic through VPN.')
                : tr(language, 'Proxy-режим использует локальные SOCKS/HTTP порты.', 'Proxy mode uses local SOCKS/HTTP ports.')}</p>
            </div>
            <div className="settings-mode-switch">
              <button className={settings.tunnelMode === 'proxy' ? 'active' : ''} type="button" onClick={() => onTunnelModeChange('proxy')}>Proxy</button>
              <button className={settings.tunnelMode === 'tun' ? 'active' : ''} type="button" onClick={() => onTunnelModeChange('tun')}>TUN</button>
            </div>
          </div>
        </SettingsSection>

        <SettingsSection id="split" kicker={tr(language, 'Раздельное туннелирование', 'Split tunneling')} title={tr(language, 'Маршрутизация приложений', 'App routing')} icon={Split}>
          <div className="settings-note-card">
            <strong>{tr(language, 'Раздельное туннелирование управляется на главном экране TUN-режима', 'Split tunneling is managed from the main TUN-mode screen')}</strong>
            <span>{tr(language, 'Здесь можно быстро переключить режим туннеля. Списки приложений и служб применяются при переподключении.', 'Here you can quickly switch tunnel mode. App and service lists apply on reconnect.')}</span>
          </div>
        </SettingsSection>

        <SettingsSection id="proxy" kicker={tr(language, 'Системный прокси', 'System proxy')} title={tr(language, 'Интеграция Windows', 'Windows integration')} icon={Globe2}>
          <div className="settings-list-modern">
            {sections.proxy.map((item) => (
              <ToggleRow key={item.key} item={item} enabled={Boolean(settings[item.key])} onClick={() => onToggleSetting(item.key)} language={language} />
            ))}
          </div>
        </SettingsSection>

        <SettingsSection id="startup" kicker={tr(language, 'Автозапуск', 'Startup')} title={tr(language, 'Запуск приложения', 'Application startup')} icon={MonitorCog}>
          <div className="settings-two-columns">
            {sections.startup.map((item) => (
              <ToggleRow key={item.key} item={item} enabled={Boolean(settings[item.key])} onClick={() => onToggleSetting(item.key)} language={language} />
            ))}
          </div>
        </SettingsSection>

        <SettingsSection id="notifications" kicker={tr(language, 'Уведомления', 'Notifications')} title={tr(language, 'Обновления и события', 'Updates and events')} icon={Bell}>
          <div className="settings-two-columns">
            {sections.notifications.map((item) => (
              <ToggleRow key={item.key} item={item} enabled={Boolean(settings[item.key])} onClick={() => onToggleSetting(item.key)} language={language} />
            ))}
          </div>
        </SettingsSection>

        <SettingsSection id="diagnostics" kicker={tr(language, 'Диагностика', 'Diagnostics')} title={tr(language, 'Служебная информация', 'Service information')} icon={Shield}>
          <div className="settings-list-modern">
            {sections.diagnostics.map((item) => (
              <ToggleRow key={item.key} item={item} enabled={Boolean(settings[item.key])} onClick={() => onToggleSetting(item.key)} language={language} />
            ))}
          </div>
        </SettingsSection>
      </div>
    </div>
  );
}
