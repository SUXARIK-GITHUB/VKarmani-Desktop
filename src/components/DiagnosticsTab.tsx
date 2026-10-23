import {useEffect,useRef,useState} from 'react';
import {tr,type UiLanguage} from '../i18n';
import type {AppSettings,ConnectivityProbe,DiagnosticsSnapshot,IntegrationMeta,ProfileSyncInfo,ProxyStatus,RemnawaveSession,RuntimeStatus,SessionRecord,UpdateInfo} from '../types/vpn';
import {safePublicDigest,supportRedactor} from '../utils/diagnosticsExport';
import {getNativeDiagnosticsSnapshot,prepareNativeRuntimeRepair,normalizeNativeError} from '../services/runtime';
import {confirmRepairPlan} from '../utils/repairPlan';
import {diagnosticCategories,diagnosticChecks,formatUnixTimestamp,mayRepairOwnedState} from '../utils/diagnosticChecks';
import {publicDiagnosticFacts} from '../utils/diagnosticFacts';
import {nativeMutations} from '../services/nativeTransport';
import {copyInformation} from '../utils/clipboard';
import '../styles/diagnostics.css';
interface DiagnosticsTabProps {
  diagnostics: DiagnosticsSnapshot | null;
  runtimeStatus?: RuntimeStatus | null;
  proxyStatus: ProxyStatus;
  connectivityProbe: ConnectivityProbe | null;
  connectionError?: string;
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
  onRepairRuntimeEnvironment?: (planId:string) => Promise<boolean>;
  onSyncProfile: () => void;
  onCheckUpdates: () => void;
  onInstallUpdate?: () => void;
  onExportDiagnostics?: () => void;
  onExportLegacyState?: () => void;
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
  isExportingLegacyState?: boolean;
}

export function DiagnosticsTab(props: DiagnosticsTabProps) {
  const [section,setSection]=useState('overview');
  const [observed,setObserved]=useState<RuntimeStatus|null>(null);
  const [checkedAt,setCheckedAt]=useState('');
  const [readBusy,setReadBusy]=useState(false);
  const [category,setCategory]=useState('all'),[status,setStatus]=useState('all'),[query,setQuery]=useState(''),[logQuery,setLogQuery]=useState('');
  const [readError,setReadError]=useState('');
  const [copyFeedback,setCopyFeedback]=useState('');
  const [repairPreviewBusy,setRepairPreviewBusy]=useState(false);
  const [repairResult,setRepairResult]=useState('');
  const repairInFlight=useRef(false);
  const repairGeneration=useRef(0);
  const readGeneration=useRef(0),readInFlight=useRef(false);
  useEffect(()=>()=>{readGeneration.current++;repairGeneration.current++;},[]);
  const {language,runtimeStatus:r,proxyStatus:p,connectivityProbe:probe,profileSyncInfo:sync,updateInfo:update,settings}=props;
  const safe=supportRedactor(props.session ?? null);
  const label=(ru:string,en:string)=>tr(language,ru,en);
  const unknown=label('Не проверено','Not verified');
  const sections=[['overview','Обзор','Overview'],['network','Сеть','Network'],['xray','Xray','Xray'],['subscription','Подписка','Subscription'],['history','Подключения','Connections'],['components','Компоненты','Components'],['logs','Логи','Logs'],['checks','Проверки','Checks']];
  const row=(name:string,value:unknown,digest=false)=><div className="support-item" key={name}><strong>{name}</strong><span>{value===undefined||value===null||value===''?'—':digest?safePublicDigest(value,props.session??null):safe(String(value))}</span></div>;
  const busy=Boolean(r?.operation)||nativeMutations.pending();
  const active=Boolean(r?.tunnelActive);
  const action=(title:string,callback:(()=>void)|undefined,disabled=false)=><button type="button" className="ghost-button" onClick={callback} disabled={!callback||disabled||busy}>{title}</button>;
  const subscriptionLabels:Record<string,string>={verified:label('Подтверждена','Verified'),expired:label('Истекла','Expired'),'needs-refresh':label('Требуется обновление','Needs refresh'),unconfirmed:label('Не подтверждена','Unconfirmed')};
  const plan=props.session?.plan;
  const noData=label('Нет данных','No data');
  const bytes=(value:string|null|undefined)=>value===null||value===undefined?noData:`${value} B`;
  const quota=plan?.totalBytes==='0'?label('Без ограничений','Unlimited'):plan?.totalBytes?bytes(plan.totalBytes):plan?.trafficLimitGb!==null&&plan?.trafficLimitGb!==undefined?`${plan.trafficLimitGb} GB`:noData;
  const expiry=plan?.expiresAtUnix==='0'?label('Без срока','No expiry'):plan?.expiresAt&&plan.expiresAt!=='—'?plan.expiresAt:noData;
  const network=observed??r;
  const facts=publicDiagnosticFacts(network?.diagnosticFacts);
  const checks=observed?diagnosticChecks(observed,language,checkedAt,probe):[];
  const listener=(port:number)=>{const state=facts?.ports?.find(p=>p.port===port)?.state;return !state?'NOT_TESTED':state==='owned'?label('Доступен, собственный','Available, owned'):state==='foreign'?label('Доступен, другой владелец','Available, foreign owner'):state==='free'?label('Не слушает','Not listening'):label('Не подтверждён','Unconfirmed');};
  const probeType=probe?.kind==='xray-http'?'XRAY_HTTP':probe?.kind==='server-direct'?'SERVER_DIRECT':'NOT_TESTED';
  const httpProbe=probe?.kind==='xray-http'?`${probe.success?'PASS':'FAIL'} · ${safe(probe.checkedAt)}`:'NOT_TESTED';
  const filteredChecks=checks.filter(check=>(category==='all'||check.category===category)&&(status==='all'||check.status===status)&&`${check.id} ${check.summary} ${check.evidence}`.toLowerCase().includes(query.slice(0,160).toLowerCase()));
  const logLines=(props.diagnostics?.logLines??[]).slice(-160).map(line=>safe(line));
  const filteredLogs=logLines.filter(line=>line.toLowerCase().includes(logQuery.slice(0,160).toLowerCase()));
  const runReadOnly=async()=>{
    if(readInFlight.current||repairInFlight.current)return;
    readInFlight.current=true;const generation=++readGeneration.current;setReadBusy(true);setReadError('');
    try{const snapshot=await getNativeDiagnosticsSnapshot();if(generation===readGeneration.current){setObserved(snapshot);setCheckedAt(new Date().toISOString());}}
    catch(error){if(generation===readGeneration.current)setReadError(normalizeNativeError(error,label('Проверка не завершена.','Diagnostics did not complete.')).message);}
    finally{readInFlight.current=false;if(generation===readGeneration.current)setReadBusy(false);}
  };
  const repairOwned=async()=>{
    if(repairInFlight.current||readInFlight.current||!mayRepairOwnedState(observed)||!props.onRepairRuntimeEnvironment)return;
    repairInFlight.current=true;setRepairPreviewBusy(true);setRepairResult('');const generation=++repairGeneration.current;
    try{
      const result=await confirmRepairPlan(prepareNativeRuntimeRepair,plan=>window.confirm(label(
        `План: восстановить proxy/PAC — ${plan.restoreProxy?'да':'нет'}; удалить подтверждённые owned routes — ${plan.removeRouteCount}. Чужие настройки не изменяются. План действует 30 секунд; изменения владения отменят выполнение. При частичной ошибке завершённое восстановление не отменяется. Продолжить?`,
        `Plan: restore proxy/PAC — ${plan.restoreProxy?'yes':'no'}; remove confirmed owned routes — ${plan.removeRouteCount}. Other owners are not changed. Plan expires in 30 seconds; ownership drift cancels execution. A partial failure does not undo completed restoration. Continue?`
      )),props.onRepairRuntimeEnvironment,()=>generation===repairGeneration.current);
      if(generation===repairGeneration.current){setRepairResult(result==='completed'?label('Восстановление подтверждено.','Restoration confirmed.'):result==='cancelled'?label('Выполнение отменено; repair не запускался.','Cancelled; repair was not executed.'):label('Выполнение не подтверждено; проверьте код ошибки и запустите диагностику снова.','Execution not confirmed; review the error code and run diagnostics again.'));setObserved(null);}
    }catch(error){if(generation===repairGeneration.current)setRepairResult(normalizeNativeError(error,label('План восстановления недоступен.','Repair plan unavailable.')).message);}
    finally{repairInFlight.current=false;if(generation===repairGeneration.current)setRepairPreviewBusy(false);}
  };
  return <div className="tab-stack compact-tab-stack diagnostics-screen diagnostics-v2">
    <section className="panel compact-panel"><div className="panel-header"><div><span className="chip subdued">{label('Диагностика','Diagnostics')}</span><h3>{label('Состояние клиента','Client status')}</h3><p className="muted">{r?label('Нативное состояние; доступность сети проверяется отдельно.','Native state; network reachability is checked separately.'):label('Ожидаем нативное состояние.','Waiting for native state.')}</p></div><div className="settings-actions"><button type="button" className="ghost-button" disabled={readBusy} onClick={()=>void runReadOnly()}>{readBusy?label('Проверяем…','Checking…'):label('Запустить диагностику','Run diagnostics')}</button>{action(props.isExportingDiagnostics?label('Подготовка…','Preparing…'):label('Support bundle','Support bundle'),props.onExportDiagnostics,props.isExportingDiagnostics)}</div></div>
      {readError&&<p role="alert">{label('Диагностика недоступна: ','Diagnostics unavailable: ')}{readError}</p>}
      {copyFeedback&&<p role="status">{copyFeedback}</p>}
      {checks.length>0&&<section aria-label={label('Результаты диагностики','Diagnostic results')}><p>{new Date(checkedAt).toLocaleString(language==='ru'?'ru-RU':'en-US')}</p><div className="settings-grid diagnostics-filters"><label className="select-field">{label('Категория','Category')}<select value={category} onChange={e=>setCategory(e.target.value)}><option value="all">{label('Все','All')}</option>{diagnosticCategories.map(item=><option key={item} value={item}>{item}</option>)}</select></label><label className="select-field">{label('Статус','Status')}<select value={status} onChange={e=>setStatus(e.target.value)}>{['all','PASS','WARN','FAIL','NOT_RUN'].map(item=><option key={item} value={item}>{item==='all'?label('Все','All'):item}</option>)}</select></label><label className="input-field">{label('Поиск проверок','Search checks')}<input maxLength={160} value={query} onChange={e=>setQuery(e.target.value)}/></label></div><p role="status">{filteredChecks.length} / {checks.length}</p><div className="support-list">{filteredChecks.map(check=>row(`${check.category} · ${check.id} · ${check.status}`,`${check.summary} · ${check.evidence}`))}</div><button type="button" className="ghost-button" onClick={()=>void copyInformation(JSON.stringify(filteredChecks,null,2),navigator.clipboard).then(ok=>setCopyFeedback(ok?label('Скопировано','Copied'):label('Копирование недоступно','Copy unavailable')))}>{label('Копировать результаты','Copy results')}</button></section>}
      {props.onExportLegacyState&&<div className="settings-actions">{action(label('Подготовить откат на 0.13.76','Prepare rollback to 0.13.76'),props.onExportLegacyState,props.isExportingLegacyState||active)}</div>}
      <nav className="diagnostics-tabs" aria-label={label('Разделы диагностики','Diagnostic sections')}>{sections.map(([id,ru,en])=><button type="button" key={id} aria-pressed={section===id} onClick={()=>setSection(id)}>{label(ru,en)}</button>)}</nav>
    </section>
    <section className="panel compact-panel diagnostics-section"><h3>{label(sections.find(s=>s[0]===section)![1],sections.find(s=>s[0]===section)![2])}</h3>
      {section==='overview'&&<><div className="support-list">{row(label('Runtime','Runtime'),r?(active?label('Процесс активен','Process active'):label('Отключён','Disconnected')):unknown)}{row(label('Режим','Mode'),r?.networkMode)}{row(label('Операция','Operation'),r?.operation?`${r.operation.kind} · ${r.operation.stage} · #${r.operation.id}`:label('Нет','None'))}{row(label('Последний результат','Last outcome'),r?.lastOperation?.outcome)}{row(label('Subscription','Subscription'),subscriptionLabels[r?.subscriptionState ?? 'unconfirmed'])}{row(label('Probe','Probe'),probe?(probe.success?label('Успешно','Passed'):label('Ошибка','Failed')):label('Не запускалась','Not run'))}</div><p className="muted">{safe(r?.message)}</p></>}
      {section==='network'&&<><div className="support-list">
        {row(label('Фактический режим','Actual mode'),network?.networkMode)}
        {row('Xray process',network?.tunnelActive&&network?.xrayPid?label('Собственный процесс работает','Owned process running'):unknown)}
        {row('HTTP listener 10809',listener(10809))}{row('SOCKS listener 10808',listener(10808))}
        {row('WinINet proxy',(network?.systemProxyEnabled??p.enabled)?label('Включён','Enabled'):label('Выключен','Disabled'))}
        {row(label('Владение proxy','Proxy ownership'),network?.proxyOwnership)}
        {row('PAC',(network?.proxyAutoConfigUrl??p.autoConfigUrl)?label('Настроен (URL скрыт)','Configured (URL hidden)'):label('Нет','None'))}
        {row('Autodetect',(network?.proxyAutoDetect??p.autoDetect)?label('Да','Yes'):label('Нет','No'))}
        {row('TUN interface',facts?.tunInterface==='ready'?label('Создан, IP-адреса готовы','Created, IP addresses ready'):facts?.tunInterface??'NOT_TESTED')}
        {row(label('Владение routes','Route ownership'),network?.routeOwnership)}{row(label('Учтённые routes','Recorded routes'),network?.ownedRoutes?.length)}
        {row(label('Тип последней проверки','Last probe type'),probeType)}{row('Xray HTTP egress',httpProbe)}
        {row('VPN / TUN egress','NOT_TESTED')}{row('DNS leak status','NOT_TESTED')}
        {row(label('Причина отказа подключения','Connection refusal reason'),props.connectionError||label('Отказ не зафиксирован','No refusal recorded'))}
      </div><p className="muted">{label('WinINet HTTP/HTTPS proxy охватывает только поддерживающие его приложения, не весь TCP/UDP и не голос Discord. Для полного туннелирования нужен full TUN. Прямой TCP ping и HTTP proxy probe не доказывают TUN, UDP или отсутствие DNS leak.','WinINet HTTP/HTTPS proxy covers supporting apps, not all TCP/UDP or Discord voice. Full tunneling requires full TUN. Direct TCP ping and HTTP proxy probes do not prove TUN, UDP or DNS leak protection.')}</p><div className="settings-actions">{action(label('Обновить факты','Refresh facts'),()=>void runReadOnly(),readBusy)}{action(label('Включить proxy','Enable proxy'),props.onEnableSystemProxy,props.isProxyBusy||!active||r?.networkMode==='tun')}{action(label('Восстановить proxy','Restore proxy'),props.onDisableSystemProxy,props.isProxyBusy)}{action(label('Проверить HTTP egress','Check HTTP egress'),props.onRunConnectivityProbe,props.isProbeBusy||!active)}</div></>}
      {section==='xray'&&<div className="support-list">{row(label('Core найден','Core found'),r?.coreInstalled?label('Да; это не проверка integrity','Yes; not an integrity check'):unknown)}{row('PID',r?.xrayPid)}{row('Config SHA-256',r?.runtimeConfigHash,true)}{row(label('Logical profile','Logical profile'),r?.lastPreparedServerId)}{row(label('Revision','Revision'),r?.runtimeRevision)}{row(label('Reconnect attempts','Reconnect attempts'),r?.reconnectAttempt)}{row(label('Последний exit code','Last exit code'),r?.lastExitCode)}</div>}
      {section==='subscription'&&<><div className="support-list">{row(label('Нативная авторизация','Native authorization'),subscriptionLabels[r?.subscriptionState ?? 'unconfirmed'])}{row(label('Следующее обновление','Refresh after'),formatUnixTimestamp(r?.subscriptionRefreshAfter,language))}{row(label('Синхронизация','Sync'),sync.status)}{row(label('Конфигурации','Configurations'),`${sync.readyCount ?? 0} / ${sync.configCount}`)}{row(label('Срок действия','Expires'),expiry)}{row(label('Отправлено по данным подписки','Subscription upload'),bytes(plan?.uploadBytes))}{row(label('Получено по данным подписки','Subscription download'),bytes(plan?.downloadBytes))}{row(label('Лимит трафика','Traffic quota'),quota)}{row(label('Лимит устройств','Device limit'),props.session?.deviceLimit??noData)}{row(label('Устройств по данным панели','Panel device count'),plan?.devices??noData)}</div><p className="muted">{safe(sync.message)}</p><div className="settings-actions">{action(label('Синхронизировать','Sync profile'),props.onSyncProfile,props.isSyncingProfile)}{action(label('Выйти','Sign out'),props.onClearAccessKey,props.isLogoutBusy)}</div></>}
      {section==='components'&&<><div className="support-list">{row(label('Клиент','Client'),update.currentVersion)}{row('Update',update.status)}{row(label('Версия update','Update version'),update.version)}{row(label('Xray/Wintun integrity','Xray/Wintun integrity'),label('Проверяется native перед запуском','Checked by native before launch'))}{row(label('Подпись update','Update signature'),label('Обязательна при установке; здесь не проверена','Required at installation; not verified here'))}</div><div className="settings-actions">{action(label('Проверить update','Check update'),props.onCheckUpdates,['checking','downloading','installing'].includes(update.status))}{update.available&&action(label('Установить update','Install update'),props.onInstallUpdate,['downloading','installing'].includes(update.status))}</div><div className="settings-grid"><label className="select-field">{label('Язык','Language')}<select value={settings.language} onChange={e=>props.onLanguageChange(e.target.value as AppSettings['language'])}><option value="ru">Русский</option><option value="en">English</option></select></label><label className="select-field">{label('Режим','Mode')}<select value={settings.tunnelMode} onChange={e=>props.onTunnelModeChange(e.target.value as AppSettings['tunnelMode'])}><option value="proxy">Proxy</option><option value="tun">TUN</option></select></label><label className="select-field">{label('Протокол','Protocol')}<select value={settings.protocolStrategy} onChange={e=>props.onProtocolStrategyChange(e.target.value as AppSettings['protocolStrategy'])}><option value="auto">Auto</option><option value="reality-first">Reality first</option><option value="xray-only">Xray only</option></select></label></div></>}
      {section==='history'&&<><p className="muted">{label('Локальный журнал: до 128 подключений, без ключей, адресов и названий серверов. Длительность незавершённой записи — последнее сохранённое значение.','Local history: up to 128 connections, without keys, addresses or server names. An unfinished entry shows its last saved duration.')}</p><div className="support-list">{props.sessionHistory.length?props.sessionHistory.map(entry=>row(`${new Date(entry.startedAt).toLocaleString(language==='ru'?'ru-RU':'en-US')} · ${entry.serverLabel} · ${entry.id.slice(0,6)}`,`${entry.durationLabel} · ${entry.status==='current'?label('Текущее','Current'):entry.status==='completed'?label('Завершено','Completed'):label('Завершение не подтверждено','End not confirmed')}`)):row(label('Подключения','Connections'),label('Записей пока нет','No entries yet'))}</div></>}
      {section==='logs'&&<><label className="input-field diagnostics-search">{label('Поиск в безопасных логах','Search safe logs')}<input maxLength={160} value={logQuery} onChange={e=>setLogQuery(e.target.value)}/></label><button type="button" className="ghost-button" onClick={()=>void copyInformation(filteredLogs.join('\n'),navigator.clipboard).then(ok=>setCopyFeedback(ok?label('Скопировано','Copied'):label('Копирование недоступно','Copy unavailable')))}>{label('Копировать видимые логи','Copy visible logs')}</button><p className="muted">{label('Последние 160 строк; credentials и URLs скрыты.','Last 160 lines; credentials and URLs hidden.')}</p><div className="log-list">{filteredLogs.length?filteredLogs.map((line,i)=><div className="log-line" key={i}>{safe(line)}</div>):<p>{label('Логи недоступны.','Logs unavailable.')}</p>}</div></>}
      {section==='checks'&&<><h4>{label('Журнал восстановления','Repair history')}</h4><p className="muted">{label('До 32 событий. Незавершённый STARTED — неизвестный исход, не успех. Автоматического undo нет.','Up to 32 events. An unfinished STARTED is an unknown outcome, not success. There is no automatic undo.')}</p><div className="support-list">{facts?.repairHistory.length?facts.repairHistory.map((receipt,index)=>row(`${new Date(receipt.atUnixMs).toLocaleString(language==='ru'?'ru-RU':'en-US')} · ${index+1}`,`${receipt.code} · proxy=${receipt.restoreProxy} · routes=${receipt.routeCount}`)):row(label('Receipts','Receipts'),facts?.repairHistoryStatus==='available'?label('Событий нет','No events'):unknown)}</div><div className="support-list">{row(label('Тип проверки','Probe type'),probeType)}{row('Xray HTTP egress',httpProbe)}{row('VPN / TUN egress','NOT_TESTED')}{row('DNS leak status','NOT_TESTED')}{row(label('Результат','Result'),probe?.message)}{row(label('Реальные packet/soak tests','Actual packet/soak tests'),label('Не измеряется клиентом','Not measured by client'))}</div><div className="settings-actions">{action(label('Проверить маршрут','Run probe'),props.onRunConnectivityProbe,props.isProbeBusy||!active)}{action(label('Восстановить owned state','Repair owned state'),()=>void repairOwned(),repairPreviewBusy||props.isRepairBusy||active||!mayRepairOwnedState(observed))}</div>{repairResult&&<p role="status">{safe(repairResult)}</p>}<p className="muted">{label('Repair восстанавливает только подтверждённое собственное состояние. При другом владельце операция завершается ошибкой.','Repair restores only confirmed owned state. Another owner causes an error.')}</p></>}
    </section>
  </div>;
}
