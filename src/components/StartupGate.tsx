import {useEffect,useRef,useState,type ReactNode} from 'react';
import {tr,type UiLanguage} from '../i18n';
import {copyInformation} from '../utils/clipboard';
import {nativeStartupAvailable,safeStartupStatus,startupClient,startupErrorCode,type StartupCode,type StartupStatus} from '../services/startup';

export function StartupRecoveryPanel({status,language,onLanguage,onRetry,onExit,busy=false,retryPrepared=false,operationError}: {
  status:StartupStatus;language:UiLanguage;onLanguage:(language:UiLanguage)=>void;onRetry:()=>void;onExit:()=>void;busy?:boolean;retryPrepared?:boolean;operationError?:StartupCode|null;
}){
  const [copied,setCopied]=useState<boolean|null>(null);
  const label=(ru:string,en:string)=>tr(language,ru,en);
  const nativeStatusUnknown=status.code==='STARTUP_STATUS_UNAVAILABLE';
  return <main className="shell app-shell startup-recovery" aria-labelledby="startup-title">
    <section className="panel compact-panel" role="alert">
      <h1 id="startup-title">{nativeStatusUnknown?label('Статус запуска VKarmani не подтверждён','VKarmani startup status unavailable'):label('Безопасный запуск VKarmani','VKarmani Safe Mode')}</h1>
      <p>{nativeStatusUnknown?label('Этот экран не загружает, не сбрасывает и не мигрирует настройки и ключи. Действия нативного запуска до получения статуса неизвестны.','This screen does not load, reset or migrate settings and keys. Earlier native startup actions are unknown.'):label('Обычный запуск не подтверждён. Настройки и ключи не сбрасывались и не мигрировались.','Normal startup was not confirmed. Settings and keys were not reset or migrated.')}</p>
      <p>{nativeStatusUnknown?label('Этот экран не запрашивает подключение, обновление, elevation или восстановление сети. Не запускайте второй экземпляр.','This screen does not request connection, update, elevation or network recovery. Do not start a second instance.'):label('Автоподключение, обновления, elevation и восстановление сети не запускались в этом режиме.','Auto-connect, updates, elevation and network recovery were not started in this mode.')}</p>
      <p><code>{status.code}</code> · {status.appVersion} · {label(`Незавершённых запусков: ${status.failures}`,`Unconfirmed startups: ${status.failures}`)}</p>
      <p>{label('Этот режим не устанавливает причину Windows AV/heap crash. Для анализа нужны сведения о точной упавшей сборке.','This mode does not identify a Windows AV/heap crash cause. Analysis needs evidence from the exact failed build.')}</p>
      <div className="settings-actions">
        <button type="button" className="ghost-button" onClick={()=>onLanguage(language==='ru'?'en':'ru')} aria-label={label('Язык безопасного режима','Safe Mode language')}>{language==='ru'?'English':'Русский'}</button>
        <button type="button" className="ghost-button" onClick={()=>{void copyInformation(JSON.stringify({schemaVersion:1,appVersion:status.appVersion,code:status.code,unconfirmedStartups:status.failures},null,2),navigator.clipboard).then(setCopied);}}>{label('Копировать сведения','Copy details')}</button>
        <button type="button" className="ghost-button" disabled={busy||!status.retryAllowed||retryPrepared} onClick={onRetry}>{label('Разрешить обычный запуск в следующий раз','Allow normal startup next time')}</button>
        <button type="button" className="ghost-button" disabled={busy} onClick={onExit}>{label('Закрыть программу','Close application')}</button>
      </div>
      {copied!==null&&<p role="status">{copied?label('Скопировано','Copied'):label('Копирование недоступно','Copy unavailable')}</p>}
      {!status.retryAllowed&&<p>{label('Startup journal недоступен или не прошёл проверку. Исходный файл сохранён; автоматическая перезапись запрещена.','The startup journal is unavailable or invalid. Its original is preserved; automatic overwrite is blocked.')}</p>}
      {retryPrepared&&<p role="status">{label('Следующий запуск разрешён. Сейчас приложение остаётся в Safe Mode. Закройте его и откройте заново, когда это безопасно.','The next normal startup is allowed. This process remains in Safe Mode. Close and reopen it when safe.')}</p>}
      {operationError&&<p role="alert"><code>{operationError}</code> · {label('Действие не подтверждено. Пользовательские данные не очищались.','Action not confirmed. User data was not cleared.')}</p>}
    </section>
  </main>;
}

export function StartupGate({children}:{children:ReactNode}){
  const [status,setStatus]=useState<StartupStatus|null>(null);
  const [language,setLanguage]=useState<UiLanguage>(()=>typeof document!=='undefined'&&document.documentElement.lang==='en'?'en':'ru');
  const [error,setError]=useState<StartupCode|null>(null);
  const [busy,setBusy]=useState(false);const [retryPrepared,setRetryPrepared]=useState(false);
  const actionBusy=useRef(false);
  useEffect(()=>{
    if(!nativeStartupAvailable())return;
    let cancelled=false;let readyTimer:ReturnType<typeof setTimeout>|null=null;let active:StartupStatus|null=null;let readySeen=false;
    const onReady=()=>{
      if(readySeen||!active||active.mode!=='normal')return;readySeen=true;
      readyTimer=setTimeout(()=>{if(!cancelled)void startupClient.ready(active!.attemptId).catch(failure=>{if(!cancelled)setError(startupErrorCode(failure));});},active.readyAfterMs);
    };
    window.addEventListener('vkarmani:frontend-ready',onReady);
    void startupClient.read().then(async value=>{
      if(cancelled)return;
      if(value.mode==='normal')await startupClient.admit(value.attemptId);
      if(cancelled)return;active=value;setStatus(value);
    }).catch(()=>{if(!cancelled)setStatus(safeStartupStatus());});
    return()=>{cancelled=true;window.removeEventListener('vkarmani:frontend-ready',onReady);if(readyTimer!==null)clearTimeout(readyTimer);};
  },[]);
  if(!nativeStartupAvailable())return children;
  if(!status)return <main className="app-shell startup-recovery" role="status">{tr(language,'Проверка безопасного запуска…','Checking safe startup…')}</main>;
  if(status.mode==='normal')return <>{children}{error&&<aside role="alert" className="startup-warning"><code>{error}</code> · {tr(language,'Готовность startup journal не записана; работа приложения не прерывалась.','Startup readiness was not recorded; the app was not interrupted.')} <button type="button" onClick={()=>setError(null)}>{tr(language,'Закрыть','Dismiss')}</button></aside>}</>;
  const run=async(action:()=>Promise<void>)=>{
    if(actionBusy.current)return;actionBusy.current=true;setBusy(true);setError(null);
    try{await action();}catch(failure){setError(startupErrorCode(failure));}finally{actionBusy.current=false;setBusy(false);}
  };
  return <StartupRecoveryPanel status={status} language={language} onLanguage={setLanguage} busy={busy} retryPrepared={retryPrepared} operationError={error}
    onRetry={()=>{if(!window.confirm(tr(language,'Разрешить обычный запуск при следующем открытии? Он загрузит сохранённые настройки и может выполнить обычное восстановление owned сети. Настройки не сбрасываются.','Allow normal startup next time? It will load saved settings and may perform normal owned-network recovery. Settings are not reset.')))return;void run(async()=>{await startupClient.retry(status.attemptId);setRetryPrepared(true);});}}
    onExit={()=>{void run(()=>startupClient.exit());}}/>;
}
