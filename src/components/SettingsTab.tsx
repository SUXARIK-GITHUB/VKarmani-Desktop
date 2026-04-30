import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Bell, Download, Globe2, Languages, MonitorCog, Palette, Plus, RefreshCw, Route, Shield, SlidersHorizontal, Split, Star, Trash2, Wifi, Zap } from 'lucide-react';
import { tr, type UiLanguage } from '../i18n';
import type { AppSettings, RoutingExclusionSettings } from '../types/vpn';
import { countActiveRoutingExclusions, normalizeRoutingDomainInput, normalizeRoutingIpInput, sanitizeRoutingExclusions } from '../utils/routingExclusions';

interface SettingsTabProps {
  settings: AppSettings;
  language: UiLanguage;
  onToggleSetting: (key: keyof Omit<AppSettings, 'releaseChannel' | 'protocolStrategy' | 'language' | 'allowDemoFallback' | 'tunnelMode' | 'ipStack' | 'routingExclusions'>) => void;
  onTunnelModeChange: (value: AppSettings['tunnelMode']) => void;
  onIpStackChange: (value: AppSettings['ipStack']) => void;
  onLanguageChange: (value: UiLanguage) => void;
  onRoutingExclusionsChange: (value: RoutingExclusionSettings) => void;
}

type ToggleKey = keyof Omit<AppSettings, 'releaseChannel' | 'protocolStrategy' | 'language' | 'allowDemoFallback' | 'tunnelMode' | 'ipStack' | 'routingExclusions'>;
type SectionId = 'general' | 'network' | 'routes' | 'tunnel' | 'split' | 'proxy' | 'startup' | 'notifications' | 'diagnostics';

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


function SimpleToggleRow({ title, description, icon: Icon, enabled, onClick, language }: { title: string; description: string; icon: typeof Shield; enabled: boolean; onClick: () => void; language: UiLanguage }) {
  return (
    <button className={`setting-row button-row ${enabled ? 'setting-row-active' : ''}`} onClick={onClick} type="button">
      <div className="setting-row-icon"><Icon size={18} /></div>
      <div className="setting-copy">
        <strong>{title}</strong>
        <span>{description}</span>
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

export function SettingsTab({ settings, language, onToggleSetting, onTunnelModeChange, onIpStackChange, onLanguageChange, onRoutingExclusionsChange }: SettingsTabProps) {
  const [activeSection, setActiveSection] = useState<SectionId>('general');
  const scrollSpyFrameRef = useRef<number | null>(null);
  const nextLanguage: UiLanguage = language === 'ru' ? 'en' : 'ru';
  const [routingDomainInput, setRoutingDomainInput] = useState('');
  const [routingIpInput, setRoutingIpInput] = useState('');
  const [routingInputError, setRoutingInputError] = useState('');
  const routingExclusions = sanitizeRoutingExclusions(settings.routingExclusions);
  const activeRoutingExclusionCount = countActiveRoutingExclusions(routingExclusions);

  const updateRoutingExclusions = (patch: Partial<RoutingExclusionSettings>) => {
    setRoutingInputError('');
    onRoutingExclusionsChange(sanitizeRoutingExclusions({ ...routingExclusions, ...patch }));
  };

  const addRoutingDomain = () => {
    const normalized = normalizeRoutingDomainInput(routingDomainInput);
    if (!normalized) {
      setRoutingInputError(tr(language, 'Укажите домен в формате example.ru, *.example.ru или .ru.', 'Enter a domain like example.ru, *.example.ru, or .ru.'));
      return;
    }

    updateRoutingExclusions({ domains: [...routingExclusions.domains, normalized] });
    setRoutingDomainInput('');
  };

  const addRoutingIp = () => {
    const normalized = normalizeRoutingIpInput(routingIpInput);
    if (!normalized) {
      setRoutingInputError(tr(language, 'Укажите IPv4 или CIDR в формате 1.2.3.4 или 1.2.3.0/24.', 'Enter IPv4 or CIDR like 1.2.3.4 or 1.2.3.0/24.'));
      return;
    }

    updateRoutingExclusions({ ips: [...routingExclusions.ips, normalized] });
    setRoutingIpInput('');
  };

  const tabs: Array<{ id: SectionId; label: string }> = [
    { id: 'general', label: tr(language, 'Общие', 'General') },
    { id: 'network', label: tr(language, 'Сеть', 'Network') },
    { id: 'routes', label: tr(language, 'Исключения', 'Exclusions') },
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
    routes: [],
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
          <div className="settings-mode-card-inline">
            <div>
              <h4>{settings.ipStack === 'ipv6' ? 'IPv6' : 'IPv4'}</h4>
              <p>{settings.ipStack === 'ipv6'
                ? tr(language, 'Xray будет отдавать приоритет IPv6 DNS/endpoint. Для TUN пока используйте IPv4; IPv6 включайте только для Proxy и если сервер/провайдер поддерживают IPv6.', 'Xray will prefer IPv6 DNS/endpoints. Keep TUN on IPv4 for now; enable IPv6 only for Proxy when the server/ISP support it.')
                : tr(language, 'Стандартный и самый совместимый режим. Xray отдаёт приоритет IPv4 DNS/endpoint.', 'Default and most compatible mode. Xray prefers IPv4 DNS/endpoints.')}</p>
            </div>
            <div className="settings-mode-switch">
              <button className={settings.ipStack === 'ipv4' ? 'active' : ''} type="button" onClick={() => onIpStackChange('ipv4')}>IPv4</button>
              <button className={settings.ipStack === 'ipv6' ? 'active' : ''} type="button" onClick={() => onIpStackChange('ipv6')}>IPv6</button>
            </div>
          </div>
        </SettingsSection>



        <SettingsSection id="routes" kicker={tr(language, 'Исключения маршрутизации', 'Routing exclusions')} title={tr(language, 'Домены и IP напрямую', 'Domains and IPs direct')} icon={Route}>
          <div className="settings-list-modern">
            <SimpleToggleRow
              title={tr(language, 'Включить исключения маршрутизации', 'Enable routing exclusions')}
              description={tr(language, 'Выбранные домены и IPv4/CIDR будут идти напрямую мимо VPN в Proxy и TUN режимах.', 'Selected domains and IPv4/CIDR will go direct outside VPN in Proxy and TUN modes.')}
              icon={Shield}
              enabled={routingExclusions.enabled}
              onClick={() => updateRoutingExclusions({ enabled: !routingExclusions.enabled })}
              language={language}
            />
          </div>

          <div className="settings-note-card">
            <strong>{tr(language, 'Быстрые правила', 'Quick rules')}</strong>
            <span>{tr(language, 'Можно включить обход для популярных зон и дополнить список своими доменами или IPv4-сетями.', 'Enable bypass for common zones and add custom domains or IPv4 networks.')}</span>
            <div className="settings-two-columns">
              <SimpleToggleRow
                title=".ru"
                description={tr(language, 'Домены российской зоны идут напрямую.', 'Russian .ru domains go direct.')}
                icon={Globe2}
                enabled={routingExclusions.bypassRuDomains}
                onClick={() => updateRoutingExclusions({ bypassRuDomains: !routingExclusions.bypassRuDomains })}
                language={language}
              />
              <SimpleToggleRow
                title=".su"
                description={tr(language, 'Домены зоны .su идут напрямую.', '.su domains go direct.')}
                icon={Globe2}
                enabled={routingExclusions.bypassSuDomains}
                onClick={() => updateRoutingExclusions({ bypassSuDomains: !routingExclusions.bypassSuDomains })}
                language={language}
              />
              <SimpleToggleRow
                title=".рф"
                description={tr(language, 'Кириллическая зона .рф идёт напрямую.', 'Cyrillic .рф domains go direct.')}
                icon={Globe2}
                enabled={routingExclusions.bypassRfDomains}
                onClick={() => updateRoutingExclusions({ bypassRfDomains: !routingExclusions.bypassRfDomains })}
                language={language}
              />
              <div className="setting-row">
                <div className="setting-row-icon"><Route size={18} /></div>
                <div className="setting-copy">
                  <strong>{activeRoutingExclusionCount}</strong>
                  <span>{tr(language, 'активных direct-правил будет применено при следующем подключении или переподключении', 'active direct rules will apply on next connect or reconnect')}</span>
                </div>
                <span className={`micro-pill ${activeRoutingExclusionCount ? 'active' : ''}`}>DIRECT</span>
              </div>
            </div>

            <div className="split-section">
              <div className="split-section-title">
                <strong>{tr(language, 'Свои домены', 'Custom domains')}</strong>
                <span>{routingExclusions.domains.length}</span>
              </div>
              <form className="split-tunnel-add-grid service" onSubmit={(event) => { event.preventDefault(); addRoutingDomain(); }}>
                <label className="split-field">
                  <span>{tr(language, 'Домен или маска', 'Domain or wildcard')}</span>
                  <input value={routingDomainInput} onChange={(event) => setRoutingDomainInput(event.target.value)} placeholder="example.ru / *.example.ru / .ru" />
                </label>
                <button className="vk-secondary-action compact" type="submit"><Plus size={15} />{tr(language, 'Добавить', 'Add')}</button>
              </form>
              <div className="split-entry-list">
                {routingExclusions.domains.map((domain) => (
                  <div className="split-entry enabled" key={domain}>
                    <span className="micro-pill active">DOMAIN</span>
                    <div>
                      <strong>{domain}</strong>
                      <small>{tr(language, 'Будет направлен напрямую без VPN', 'Will be routed direct outside VPN')}</small>
                    </div>
                    <button className="split-entry-delete" type="button" onClick={() => updateRoutingExclusions({ domains: routingExclusions.domains.filter((item) => item !== domain) })} aria-label={tr(language, 'Удалить домен', 'Remove domain')}>
                      <Trash2 size={15} />
                    </button>
                  </div>
                ))}
                {routingExclusions.domains.length === 0 ? <div className="split-empty">{tr(language, 'Пользовательских доменов пока нет.', 'No custom domains yet.')}</div> : null}
              </div>
            </div>

            <div className="split-section">
              <div className="split-section-title">
                <strong>{tr(language, 'Свои IPv4 / CIDR', 'Custom IPv4 / CIDR')}</strong>
                <span>{routingExclusions.ips.length}</span>
              </div>
              <form className="split-tunnel-add-grid service" onSubmit={(event) => { event.preventDefault(); addRoutingIp(); }}>
                <label className="split-field">
                  <span>{tr(language, 'IP или подсеть', 'IP or network')}</span>
                  <input value={routingIpInput} onChange={(event) => setRoutingIpInput(event.target.value)} placeholder="1.2.3.4 / 1.2.3.0/24" />
                </label>
                <button className="vk-secondary-action compact" type="submit"><Plus size={15} />{tr(language, 'Добавить', 'Add')}</button>
              </form>
              {routingInputError ? <div className="split-empty">{routingInputError}</div> : null}
              <div className="split-entry-list">
                {routingExclusions.ips.map((ip) => (
                  <div className="split-entry enabled" key={ip}>
                    <span className="micro-pill active">IP</span>
                    <div>
                      <strong>{ip}</strong>
                      <small>{tr(language, 'Будет направлен напрямую без VPN', 'Will be routed direct outside VPN')}</small>
                    </div>
                    <button className="split-entry-delete" type="button" onClick={() => updateRoutingExclusions({ ips: routingExclusions.ips.filter((item) => item !== ip) })} aria-label={tr(language, 'Удалить IP', 'Remove IP')}>
                      <Trash2 size={15} />
                    </button>
                  </div>
                ))}
                {routingExclusions.ips.length === 0 ? <div className="split-empty">{tr(language, 'Пользовательских IP/CIDR пока нет.', 'No custom IP/CIDR yet.')}</div> : null}
              </div>
            </div>
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
