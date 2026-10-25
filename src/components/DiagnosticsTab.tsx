import {useState} from 'react';
import {tr,type UiLanguage} from '../i18n';
import type {AppSettings,ConnectivityProbe,DiagnosticsSnapshot,IntegrationMeta,ProfileSyncInfo,ProxyStatus,RemnawaveSession,RuntimeStatus,SessionRecord,UpdateInfo} from '../types/vpn';
import {supportRedactor} from '../utils/diagnosticsExport';
import '../styles/diagnostics.css';
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
  onRepairRuntimeEnvironment?: () => void;
  onSyncProfile: () => void;
  onCheckUpdates: () => void;
  onInstallUpdate?: () => void;
  onExportDiagnostics?: () => void;
  onClearAccessKey: () => void;
  onReleaseChannelChange: (value: AppSettings['releaseChannel']) => void;
  onProtocolStrategyChange: (value: AppSettings['protocolStrategy']) => void;
  onTunnelModeChange: (value: AppSettings['tunnelMode']) => void;
  onLanguageChange: (value: AppSettings['language']) => void;
  isProxyBusy?: boolean;
  isProbeBusy?: boolean;
  isRepairBusy?: boolean;
  isLogoutBusy?: boolean;
  isSyncingProfile?: boolean;
  isExportingDiagnostics?: boolean;
}

export function DiagnosticsTab(props: DiagnosticsTabProps) {
  const [section,setSection]=useState('overview');
  const {language,runtimeStatus:r,proxyStatus:p,connectivityProbe:probe,profileSyncInfo:sync,updateInfo:update,settings}=props;
  const safe=supportRedactor(props.session ?? null);
  const label=(ru:string,en:string)=>tr(language,ru,en);
  const unknown=label('Не проверено','Not verified');
  const sections=[['overview','Обзор','Overview'],['network','Сеть','Network'],['xray','Xray','Xray'],['subscription','Подписка','Subscription'],['components','Компоненты','Components'],['logs','Логи','Logs'],['checks','Проверки','Checks']];
  const row=(name:string,value:unknown)=><div className="support-item" key={name}><strong>{name}</strong><span>{value===undefined||value===null||value===''?'—':safe(String(value))}</span></div>;
  const busy=Boolean(r?.operation);
  const active=Boolean(r?.tunnelActive);
  const action=(title:string,callback:(()=>void)|undefined,disabled=false)=><button type="button" className="ghost-button" onClick={callback} disabled={!callback||disabled||busy}>{title}</button>;
  const subscriptionLabels:Record<string,string>={verified:label('Подтверждена','Verified'),expired:label('Истекла','Expired'),'needs-refresh':label('Требуется обновление','Needs refresh'),unconfirmed:label('Не подтверждена','Unconfirmed')};
  return <div className="tab-stack compact-tab-stack diagnostics-screen diagnostics-v2">
    <section className="panel compact-panel"><div className="panel-header"><div><span className="chip subdued">{label('Диагностика','Diagnostics')}</span><h3>{label('Состояние клиента','Client status')}</h3><p className="muted">{r?label('Нативное состояние; доступность сети проверяется отдельно.','Native state; network reachability is checked separately.'):label('Ожидаем нативное состояние.','Waiting for native state.')}</p></div>{action(props.isExportingDiagnostics?label('Подготовка…','Preparing…'):label('Support bundle','Support bundle'),props.onExportDiagnostics,props.isExportingDiagnostics)}</div>
      <nav className="diagnostics-tabs" aria-label={label('Разделы диагностики','Diagnostic sections')}>{sections.map(([id,ru,en])=><button type="button" key={id} aria-pressed={section===id} onClick={()=>setSection(id)}>{label(ru,en)}</button>)}</nav>
    </section>
    <section className="panel compact-panel diagnostics-section"><h3>{label(sections.find(s=>s[0]===section)![1],sections.find(s=>s[0]===section)![2])}</h3>
      {section==='overview'&&<><div className="support-list">{row(label('Runtime','Runtime'),r?(active?label('Процесс активен','Process active'):label('Отключён','Disconnected')):unknown)}{row(label('Режим','Mode'),r?.networkMode)}{row(label('Операция','Operation'),r?.operation?`${r.operation.kind} · ${r.operation.stage} · #${r.operation.id}`:label('Нет','None'))}{row(label('Последний результат','Last outcome'),r?.lastOperation?.outcome)}{row(label('Subscription','Subscription'),subscriptionLabels[r?.subscriptionState ?? 'unconfirmed'])}{row(label('Probe','Probe'),probe?(probe.success?label('Успешно','Passed'):label('Ошибка','Failed')):label('Не запускалась','Not run'))}</div><p className="muted">{safe(r?.message)}</p></>}
      {section==='network'&&<><div className="support-list">{row('WinINet proxy',p.enabled?label('Включён','Enabled'):label('Выключен','Disabled'))}{row(label('Владение proxy','Proxy ownership'),r?.proxyOwnership)}{row('PAC',p.autoConfigUrl?label('Настроен (URL скрыт)','Configured (URL hidden)'):label('Нет','None'))}{row('Autodetect',p.autoDetect?label('Да','Yes'):label('Нет','No'))}{row('TUN interface',r?.tunInterfaceName)}{row(label('Владение routes','Route ownership'),r?.routeOwnership)}{row(label('Учтённые routes','Recorded routes'),r?.ownedRoutes?.length)}{row('HTTP / SOCKS',probe?`${probe.httpPortOpen} / ${probe.socksPortOpen}`:unknown)}</div><p className="muted">{label('TUN process rules не являются firewall-изоляцией. Proxy не гарантирует DIRECT для программ с ручным SOCKS/HTTP.','TUN process rules are not firewall isolation. Proxy does not guarantee DIRECT for apps with manual SOCKS/HTTP.')}</p><div className="settings-actions">{action(label('Включить proxy','Enable proxy'),props.onEnableSystemProxy,props.isProxyBusy||!active||r?.networkMode==='tun')}{action(label('Восстановить proxy','Restore proxy'),props.onDisableSystemProxy,props.isProxyBusy)}{action(label('Проверить маршрут','Run probe'),props.onRunConnectivityProbe,props.isProbeBusy||!active)}</div></>}
      {section==='xray'&&<div className="support-list">{row(label('Core найден','Core found'),r?.coreInstalled?label('Да; это не проверка integrity','Yes; not an integrity check'):unknown)}{row('PID',r?.xrayPid)}{row('Config SHA-256',r?.runtimeConfigHash)}{row(label('Logical profile','Logical profile'),r?.lastPreparedServerId)}{row(label('Revision','Revision'),r?.runtimeRevision)}{row(label('Reconnect attempts','Reconnect attempts'),r?.reconnectAttempt)}{row(label('Последний exit code','Last exit code'),r?.lastExitCode)}</div>}
      {section==='subscription'&&<><div className="support-list">{row(label('Нативная авторизация','Native authorization'),subscriptionLabels[r?.subscriptionState ?? 'unconfirmed'])}{row(label('Следующее обновление (UTC Unix)','Refresh after (UTC Unix)'),r?.subscriptionRefreshAfter)}{row(label('Синхронизация','Sync'),sync.status)}{row(label('Конфигурации','Configurations'),`${sync.readyCount ?? 0} / ${sync.configCount}`)}</div><p className="muted">{safe(sync.message)}</p><div className="settings-actions">{action(label('Синхронизировать','Sync profile'),props.onSyncProfile,props.isSyncingProfile)}{action(label('Выйти','Sign out'),props.onClearAccessKey,props.isLogoutBusy)}</div></>}
      {section==='components'&&<><div className="support-list">{row(label('Клиент','Client'),update.currentVersion)}{row('Update',update.status)}{row(label('Версия update','Update version'),update.version)}{row(label('Xray/Wintun integrity','Xray/Wintun integrity'),label('Проверяется native перед запуском','Checked by native before launch'))}{row(label('Подпись update','Update signature'),label('Обязательна при установке; здесь не проверена','Required at installation; not verified here'))}</div><div className="settings-actions">{action(label('Проверить update','Check update'),props.onCheckUpdates,['checking','downloading','installing'].includes(update.status))}{update.available&&action(label('Установить update','Install update'),props.onInstallUpdate,['downloading','installing'].includes(update.status))}</div><div className="settings-grid"><label className="select-field">{label('Язык','Language')}<select value={settings.language} onChange={e=>props.onLanguageChange(e.target.value as AppSettings['language'])}><option value="ru">Русский</option><option value="en">English</option></select></label><label className="select-field">{label('Режим','Mode')}<select value={settings.tunnelMode} onChange={e=>props.onTunnelModeChange(e.target.value as AppSettings['tunnelMode'])}><option value="proxy">Proxy</option><option value="tun">TUN</option></select></label><label className="select-field">{label('Протокол','Protocol')}<select value={settings.protocolStrategy} onChange={e=>props.onProtocolStrategyChange(e.target.value as AppSettings['protocolStrategy'])}><option value="auto">Auto</option><option value="reality-first">Reality first</option><option value="xray-only">Xray only</option></select></label></div></>}
      {section==='logs'&&<><p className="muted">{label('Последние 160 строк; credentials и URLs скрыты.','Last160 lines; credentials and URLs hidden.')}</p><div className="log-list">{props.diagnostics?.logLines?.length?props.diagnostics.logLines.slice(-160).map((line,i)=><div className="log-line" key={i}>{safe(line)}</div>):<p>{label('Логи недоступны.','Logs unavailable.')}</p>}</div></>}
      {section==='checks'&&<><div className="support-list">{row(label('Проверка сети','Network check'),probe?`${probe.success?'PASS':'FAIL'} · ${safe(probe.checkedAt)}`:'NOT_RUN')}{row(label('Результат','Result'),probe?.message)}{row(label('Реальные packet/soak tests','Actual packet/soak tests'),label('Не измеряется клиентом','Not measured by client'))}</div><div className="settings-actions">{action(label('Проверить маршрут','Run probe'),props.onRunConnectivityProbe,props.isProbeBusy||!active)}{action(label('Восстановить owned state','Repair owned state'),props.onRepairRuntimeEnvironment,props.isRepairBusy||active)}</div><p className="muted">{label('Repair восстанавливает только подтверждённое собственное состояние. При другом владельце операция завершается ошибкой.','Repair restores only confirmed owned state. Another owner causes an error.')}</p></>}
    </section>
  </div>;
}
