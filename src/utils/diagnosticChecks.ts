import type {RuntimeStatus} from '../types/vpn';
import {tr,type UiLanguage} from '../i18n';
import {publicDiagnosticFacts} from './diagnosticFacts';
export const diagnosticCategories=['runtime','ports','tun','wfp','routes','dns','proxy','subscription','resources','storage','logs','permissions','repair'] as const;
const categories:Record<string,typeof diagnosticCategories[number]>={NATIVE_BRIDGE:'runtime',RUNTIME_PROCESS:'runtime',RUNTIME_OPERATION:'runtime',CORE_PRESENCE:'resources',PROXY_OWNERSHIP:'proxy',ROUTE_OWNERSHIP:'routes',SUBSCRIPTION:'subscription',DNS_LEAK:'dns',WFP_ISOLATION:'wfp',RESOURCE_INTEGRITY:'resources',PORT_OWNERSHIP:'ports',TUN_EGRESS:'tun',STORAGE_METADATA:'storage',LOGS_METADATA:'logs',ELEVATION:'permissions',REPAIR_HISTORY:'repair'};
export interface DiagnosticCheck {
  id:string;
  category:typeof diagnosticCategories[number];
  status:'PASS'|'WARN'|'FAIL'|'NOT_RUN';
  summary:string;
  evidence:string;
  checkedAt:string;
  action:'none'|'review-owned-state'|'native-acceptance';
}
export function diagnosticChecks(runtime:RuntimeStatus,language:UiLanguage,at=new Date().toISOString()):DiagnosticCheck[]{
  const label=(ru:string,en:string)=>tr(language,ru,en);
  const row=(id:string,status:DiagnosticCheck['status'],summary:string,evidence:string,action:DiagnosticCheck['action']='none'):DiagnosticCheck=>({id,category:categories[id]??'runtime',status,summary,evidence,checkedAt:at,action});
  if(runtime.bridge!=='tauri')return [row('NATIVE_BRIDGE','NOT_RUN',label('Нужна нативная сборка','Native build required'),'bridge=unavailable','native-acceptance')];
  const validProxy=['none','owned','prepared','restored-pending-journal','changed','unavailable','corrupt'].includes(runtime.proxyOwnership??'');
  const proxy=validProxy?runtime.proxyOwnership!:'unknown';
  const validRoute=['none','confirmed','changed','missing','unconfirmed','unavailable','unsupported'].includes(runtime.routeOwnership??'');
  const route=validRoute?runtime.routeOwnership!:'unknown';
  const pid=Number.isInteger(runtime.xrayPid)&&runtime.xrayPid!>0;
  const active=runtime.tunnelActive===true&&pid;
  const facts=publicDiagnosticFacts(runtime.diagnosticFacts);
  const ports=facts?.ports;
  const portStatus:DiagnosticCheck['status']=!ports?'NOT_RUN':ports.some(p=>p.state==='foreign')?'FAIL':ports.some(p=>p.state==='unavailable'||p.state==='unconfirmed')?'WARN':runtime.operation?'WARN':ports.every(p=>p.state===(active?'owned':'free'))?'PASS':'WARN';
  return [
    row('NATIVE_BRIDGE','PASS',label('Получен read-only snapshot','Read-only snapshot received'),'bridge=tauri'),
    row('RUNTIME_PROCESS',active?'PASS':runtime.tunnelActive?'WARN':'NOT_RUN',label('Состояние owned процесса; это не тест egress','Owned process state; not an egress test'),`active=${runtime.tunnelActive===true}; pidPresent=${pid}`),
    row('RUNTIME_OPERATION',runtime.operation?'WARN':'PASS',label('Нативная операция','Native operation'),runtime.operation?'operation=in-progress':'operation=none'),
    row('CORE_PRESENCE',runtime.coreInstalled===true?'PASS':'WARN',label('Наличие core; подпись и содержимое отдельно','Core presence; signature and contents checked separately'),`corePresent=${runtime.coreInstalled===true}`),
    row('PROXY_OWNERSHIP',proxy==='changed'||proxy==='corrupt'?'FAIL':['owned','none'].includes(proxy)?'PASS':'WARN',label('Владение proxy по journal и текущему состоянию','Proxy ownership from journal and current state'),`ownership=${proxy}`,'review-owned-state'),
    row('ROUTE_OWNERSHIP',['changed','missing'].includes(route)?'FAIL':['confirmed','none'].includes(route)?'PASS':'WARN',label('Сравнение owned routes; без изменения маршрутов','Owned route comparison; no route mutation'),`ownership=${route}`,'review-owned-state'),
    row('SUBSCRIPTION',runtime.subscriptionState==='verified'?'PASS':runtime.subscriptionState==='expired'?'FAIL':'WARN',label('Нативное подтверждение подписки','Native subscription confirmation'),`state=${['verified','expired','needs-refresh','unconfirmed'].includes(runtime.subscriptionState??'')?runtime.subscriptionState:'unknown'}`),
    row('DNS_LEAK','NOT_RUN',label('DNS leak требует отдельного packet-теста','DNS leak requires a separate packet test'),'packetCapture=not-run','native-acceptance'),
    row('WFP_ISOLATION','NOT_RUN',label('Firewall-изоляция здесь не проверяется','Firewall isolation is not verified here'),'WFP=not-verified','native-acceptance'),
    row('RESOURCE_INTEGRITY',facts?.resourceIntegrity==='verified'?'PASS':facts?.resourceIntegrity==='mismatch'?'FAIL':'NOT_RUN',label('SHA-256 четырёх файлов по compiled pins; это не Authenticode или launch acceptance','Four file SHA-256 hashes against compiled pins; not Authenticode or launch acceptance'),`source=bounded-file-read; integrity=${facts?.resourceIntegrity??'not-run'}; observedAt=${facts?.checkedAtUnixMs??'unknown'}`,'native-acceptance'),
    row('PORT_OWNERSHIP',portStatus,label('Read-only TCP listeners 127.0.0.1 и возможный IPv6 wildcard; это не резервирование порта или проверка egress','Read-only 127.0.0.1 TCP listeners and possible IPv6 wildcard; not a port reservation or egress test'),ports?`source=GetExtendedTcpTable; ${ports.map(p=>`${p.port}=${p.state}`).join('; ')}; observedAt=${facts?.checkedAtUnixMs}`:'portOwner=not-queried'),
    row('TUN_EGRESS','NOT_RUN',label('TUN egress требует packet-теста','TUN egress requires a packet test'),'packetCapture=not-run','native-acceptance'),
    row('STORAGE_METADATA',facts?.storageMetadata==='present'?'PASS':'WARN',label('Только metadata v2; DPAPI, migration, запись и восстановление не запускались','V2 metadata only; no DPAPI, migration, write or recovery'),`source=guarded-metadata; state=${facts?.storageMetadata??'unknown'}`),
    row('LOGS_METADATA',facts?.logsMetadata==='present'?'PASS':'WARN',label('Только существующий logs directory; запись/ротация не проверены','Existing log directory only; write/rotation not verified'),`source=guarded-directory-metadata; state=${facts?.logsMetadata??'unknown'}`),
    row('ELEVATION',facts?.elevation&&facts.elevation!=='unavailable'?'PASS':'NOT_RUN',label('Текущий token, без запроса elevation','Current token, without requesting elevation'),`source=token-query; elevation=${facts?.elevation??'unknown'}`),
    row('REPAIR_HISTORY',facts?.repairHistoryStatus==='available'?'PASS':'WARN',label('Публичные ограниченные receipts; STARTED без результата означает неизвестный исход','Bounded public receipts; STARTED without a result means unknown outcome'),`source=guarded-file-read; history=${facts?.repairHistoryStatus??'unknown'}; entries=${facts?.repairHistory.length??0}`)
  ];
}

export function mayRepairOwnedState(runtime:RuntimeStatus|null|undefined):boolean {
  if(!runtime||runtime.bridge!=='tauri'||runtime.tunnelActive!==false||runtime.xrayPid||runtime.operation)return false;
  return ['none','owned','prepared','restored-pending-journal'].includes(runtime.proxyOwnership??'')
    && ['none','confirmed'].includes(runtime.routeOwnership??'')
    && (runtime.proxyOwnership!=='none'||runtime.routeOwnership!=='none');
}

export function formatUnixTimestamp(value:unknown,language:UiLanguage):string {
  if(typeof value!=='number'||!Number.isSafeInteger(value)||value<0||value>8640000000000)return tr(language,'Нет данных','No data');
  return new Date(value*1000).toLocaleString(language==='ru'?'ru-RU':'en-US');
}
