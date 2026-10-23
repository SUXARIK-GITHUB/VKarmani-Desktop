import {tr,type UiLanguage} from '../i18n';
const messages:Record<string,[string,string]>={
  CORE_FRAGMENT_SCHEMA_UNSUPPORTED:['Профиль содержит несколько или конфликтующие диапазоны fragmentation, которые Xray 26.4.25 не поддерживает. Профиль не упрощался; обратитесь к провайдеру.','The profile contains multiple or conflicting fragmentation ranges unsupported by Xray 26.4.25. The profile was not simplified; contact the provider.'],
  CORE_CONFIG_REJECTED:['Xray отклонил конфигурацию до запуска runtime.','Xray rejected the configuration before runtime launch.'],
  CORE_SPAWN_ACCESS_DENIED:['Windows запретил запуск Xray (код 5). Проверьте защиту Windows и права доступа.','Windows denied Xray launch (code 5). Check Windows security and access permissions.'],
  CORE_SPAWN_INVALID_IMAGE:['Windows отклонил формат Xray (код 193). Проверьте целостность установленного core.','Windows rejected the Xray image (code 193). Check installed core integrity.'],
  CORE_SPAWN_CORRUPT_FILE:['Windows сообщил о повреждении файла Xray (код 1392).','Windows reported a corrupted Xray file (code 1392).'],
  CORE_SPAWN_FAILED:['Не удалось запустить Xray.','Xray could not be started.'],
  TUN_ADDRESS_NOT_READY:['Xray не подтвердил IP-адреса TUN-адаптера. Подключение не подтверждено; проверьте права администратора, журнал Xray и состояние собственных маршрутов.','Xray did not confirm the TUN adapter IP addresses. Connection is unconfirmed; check elevation, the Xray log and owned-route state.'],
  PROBE_RUNTIME_UNAVAILABLE:['Нет стабильного собственного Xray для проверки. Проверьте состояние подключения и владельца локальных портов.','No stable owned Xray is available for this check. Review the connection state and local port ownership.'],
  PROBE_RUNTIME_CHANGED:['Runtime изменился во время проверки; устаревший результат отброшен. Повторите проверку после завершения переключения.','The runtime changed during the check; the stale result was discarded. Retry after switching completes.'],
  RUNTIME_CLEANUP_INCOMPLETE:['Очистка сетевого состояния не подтверждена. Новое подключение не запущено; требуется проверка состояния.','Network cleanup is unconfirmed. No replacement connection was started; state verification is required.'],
  ROUTE_JOURNAL_UNAVAILABLE:['Журнал владения маршрутами недоступен или его путь небезопасен. Операция остановлена без удаления чужих маршрутов.','The route ownership journal is unavailable or its path is unsafe. The operation stopped without deleting foreign routes.'],
  TUN_PROCESS_ENFORCEMENT_UNAVAILABLE:['TUN для выбранных приложений недоступен: при ошибке определения процесса Xray может отправить их трафик напрямую. Подключение не запускалось.','Selected-app TUN is unavailable: an Xray process lookup failure can send selected traffic directly. Connection was not started.'],
  STATE_CLOSING:['Приложение завершает работу.','The application is closing.'],
  PROCESS_STOP_UNCONFIRMED:['Остановка собственного Xray не подтверждена. Новый процесс не запускается.','Stopping the owned Xray was not confirmed. No replacement is started.'],
  SESSION_CHANGED:['Авторизация изменилась во время операции.','Authorization changed during the operation.'],
  SUBSCRIPTION_UNAVAILABLE:['Подписка временно недоступна. Сохранённый runtime не отключается этим отказом.','The subscription is temporarily unavailable. This rejection does not stop a preserved runtime.'],
  SUBSCRIPTION_REJECTED:['Подписка не подтверждена сервисом.','The service did not confirm the subscription.'],
  CORE_NOT_FOUND:['Xray не найден или не прошёл проверку.','Xray was not found or failed validation.'],
  REQUEST_IDENTITY:['Идентичность выбранного профиля не подтверждена.','The selected profile identity was not confirmed.'],
  CONNECT_PREFLIGHT:['Подготовка подключения не прошла проверку.','Connection preparation did not pass validation.'],
  PROXY_OWNER_CHANGED:['Владелец proxy изменился. Чужие настройки сохранены.','Proxy ownership changed. Foreign settings were preserved.'],
  ROUTE_OWNER_CHANGED:['Владелец routes изменился. Чужие маршруты сохранены.','Route ownership changed. Foreign routes were preserved.'],
  CONFIG_PROVENANCE_MISSING:['Происхождение конфигурации не подтверждено.','Configuration provenance was not confirmed.'],
  REPAIR_HISTORY_INVALID:['Журнал repair повреждён и сохранён. Восстановление не запускалось.','The repair history is invalid and was preserved. Repair was not started.'],
  REPAIR_HISTORY_UNAVAILABLE:['Не удалось сохранить намерение repair; восстановление не запускалось.','Repair intent could not be saved; repair was not started.'],
  REPAIR_RECEIPT_UNCONFIRMED:['Итог repair не удалось записать. Возможны частичные изменения; запустите диагностику. Автоматического undo нет.','The repair outcome could not be recorded. Partial changes are possible; run diagnostics. There is no automatic undo.'],
  NATIVE_COMMAND_TIMEOUT:['Ответ native не получен вовремя. Исход операции неизвестен; завершение или отмена не подтверждены.','The native response deadline elapsed. The outcome is unknown; completion or cancellation was not confirmed.'],
  RUNTIME_CONNECT_FAILED:['Подключение не подтверждено. Проверьте диагностику и журналы.','Connection was not confirmed. Review diagnostics and logs.'],
  RUNTIME_DISCONNECT_FAILED:['Отключение не подтверждено. Состояние VPN сохранено до проверки.','Disconnect was not confirmed. VPN state is retained until checked.'],
  RUNTIME_PROXY_FAILED:['Изменение proxy не подтверждено. Проверьте его владение в диагностике.','Proxy change was not confirmed. Review its ownership in diagnostics.'],
  RUNTIME_ROLLBACK_FAILED:['Откат runtime не подтверждён. Повторный запуск не выполнялся.','Runtime rollback was not confirmed. No retry was performed.'],
  RUNTIME_COMMAND_TASK_FAILED:['Native-операция завершилась без подтверждённого результата.','The native operation ended without a confirmed result.'],
  RUNTIME_BUSY:['Другая native-операция ещё выполняется.','Another native operation is still running.'],
  RUNTIME_SUPERSEDED:['Результат относится к другому runtime и не применён.','The result belongs to another runtime and was not applied.'],
  RUNTIME_IDENTITY_UNCONFIRMED:['Native runtime не подтвердил выбранный сервер и конфигурацию.','The native runtime did not confirm the selected server and configuration.'],
  RUNTIME_SNAPSHOT_INVALID:['Нативное состояние не прошло проверку. Состояние VPN неизвестно.','Native state did not pass validation. VPN state is unknown.'],
  OPERATION_CANCELLED:['Операция отменена; итоговое состояние проверяется отдельно.','Operation cancelled; the final state is checked separately.'],
  OPERATION_DEADLINE:['Native-операция превысила срок; требуется проверка состояния.','The native operation exceeded its deadline; state verification is required.'],
  CORE_PORT_CONFLICT:['Локальные порты заняты. Чужой процесс не завершался.','Local ports are occupied. No foreign process was terminated.'],
  CORE_PORT_TIMEOUT:['Порты Xray не подтвердили готовность.','Xray ports did not confirm readiness.'],
  CORE_EXITED_EARLY:['Xray завершился до подтверждения готовности.','Xray exited before readiness was confirmed.'],
  TUN_ELEVATION_REQUIRED:['Для TUN нужны права администратора.','TUN requires administrator privileges.'],
  TUN_IPV6_UNSUPPORTED:['TUN IPv6 пока не поддерживается. Используйте IPv4 или Proxy.','TUN IPv6 is not supported yet. Use IPv4 or Proxy.'],
  SESSION_UNAUTHORIZED:['Native-сессия не авторизована. Подтвердите подписку.','The native session is not authorized. Verify the subscription.'],
  PROFILE_SERVER_MISSING:['Сервер отсутствует в профиле. Синхронизируйте профиль.','The server is missing from the profile. Sync the profile.'],
  NETWORK_MODE_INVALID:['Недопустимый режим сети.','Invalid network mode.'],
  NETWORK_IP_STACK_INVALID:['Недопустимый IP-стек.','Invalid IP stack.'],
  NETWORK_BINDING_CHANGED:['Физическая сеть изменилась во время подключения. Подключение не подтверждено.','The physical network changed during connection. Connection was not confirmed.'],
  NETWORK_BINDING_UNCONFIRMED:['Физический интерфейс не удалось подтвердить. Подключение не подтверждено.','The physical interface could not be verified. Connection was not confirmed.'],
  ROUTE_INTERFACE_CHANGED:['Идентичность адаптера изменилась. Маршруты сохранены для проверки.','The adapter identity changed. Routes were preserved for verification.'],
  ROUTE_INTERFACE_UNAVAILABLE:['Идентичность адаптера не удалось проверить. Маршруты сохранены.','The adapter identity could not be verified. Routes were preserved.'],
  TUN_INTERFACE_NOT_READY:['Адаптер TUN не подтвердил готовность. Подключение не подтверждено.','The TUN adapter did not confirm readiness. Connection was not confirmed.'],
  TUN_ROUTES_UNCONFIRMED:['Маршруты TUN не подтверждены полностью. Подключение не подтверждено.','The TUN route set was not fully confirmed. Connection was not confirmed.'],
  REPAIR_PLAN_STALE:['План восстановления истёк или состояние изменилось. Запустите диагностику снова.','The repair plan expired or state changed. Run diagnostics again.'],
  REPAIR_PARTIAL_ROUTES_UNCONFIRMED:['Восстановление proxy завершено, но очистка routes не подтверждена. Завершённое восстановление не отменялось.','Proxy restoration completed, but route cleanup was not confirmed. Completed restoration was not undone.'],
  REPAIR_PROXY_UNCONFIRMED:['Восстановление proxy не подтверждено; очистка routes не запускалась.','Proxy restoration was not confirmed; route cleanup was not started.'],
  REPAIR_OWNERSHIP_UNCONFIRMED:['Владение состоянием не подтверждено. Чужие настройки не изменялись.','State ownership was not confirmed. Foreign settings were not changed.'],
  REPAIR_RUNTIME_PRESENT:['Обнаружен собственный активный или незавершённый runtime. Repair отменён.','An owned active or pending runtime is present. Repair was rejected.'],
  REPAIR_NOT_NEEDED:['Подтверждённого состояния для восстановления нет.','There is no confirmed owned state to restore.'],
  REPAIR_BUSY:['Другая операция ещё выполняется. План не применён.','Another operation is still running. The plan was not applied.'],
  AUTOSTART_OWNER_CHANGED:['Запись автозапуска изменена другим владельцем. Она сохранена без изменений.','The startup entry belongs to another value. It was preserved.'],
  AUTOSTART_REQUEST_STALE:['Устаревший запрос автозапуска отменён.','An obsolete startup request was rejected.'],
  AUTOSTART_STATE_UNAVAILABLE:['Настройки автозапуска не подтверждены в хранилище.','Startup settings could not be confirmed in storage.'],
  AUTOSTART_BUILD_UNSUPPORTED:['Эта сборка не изменяет автозапуск Windows.','This build does not modify Windows startup.'],
  AUTOSTART_DELETE_FAILED:['Windows не подтвердил отключение автозапуска.','Windows did not confirm disabling startup.'],
  AUTOSTART_VERIFY_FAILED:['Итоговое состояние автозапуска не подтверждено.','The resulting startup state was not confirmed.'],
  AUTOSTART_READ_FAILED:['Запись автозапуска недоступна для чтения.','The startup entry could not be read.'],
  AUTOSTART_WRITE_FAILED:['Windows не подтвердил запись автозапуска.','Windows did not confirm writing the startup entry.'],
  AUTOSTART_ACCESS_FAILED:['Нет доступа к записи автозапуска текущего пользователя.','The current-user startup entry could not be accessed.'],
  AUTOSTART_VALUE_INVALID:['Запись автозапуска имеет неподдерживаемый формат и сохранена.','The startup entry has an unsupported format and was preserved.'],
  AUTOSTART_TARGET_INVALID:['Не удалось подтвердить путь приложения для автозапуска.','The application path for startup could not be confirmed.'],
  AUTOSTART_TASK_FAILED:['Изменение автозапуска не завершено.','Changing startup did not complete.'],
};
export class NativeOperationError extends Error {
  constructor(readonly code:string,readonly category:string,readonly retryable:boolean,message:string,readonly operationPending=false,readonly stage?:string,readonly causeCode?:string,readonly win32Code?:number){super(`${code}: ${message}`);this.name='NativeOperationError';}
}
const stages=['preflight','port-release','config-validation','spawn','listeners','routes','publish'];
const causes:Record<string,[string,string]>={CORE_FRAGMENT_LENGTH_INVALID:['Недопустимая длина fragmentation.','Invalid fragmentation length.'],CORE_VALIDATION_TIMEOUT:['Проверка конфигурации превысила срок.','Configuration validation timed out.'],CORE_CONFIG_INVALID:['Конфигурация несовместима с установленным Xray.','The configuration is incompatible with the installed Xray.']};
export function publicFailureDetails(record:Record<string,unknown>){
  const stage=typeof record.stage==='string'&&stages.includes(record.stage)?record.stage:undefined;
  const cause=record.code==='CORE_CONFIG_REJECTED'&&typeof record.cause==='string'&&Object.prototype.hasOwnProperty.call(causes,record.cause)?record.cause:undefined;
  const expected:Record<string,number>={CORE_SPAWN_ACCESS_DENIED:5,CORE_SPAWN_INVALID_IMAGE:193,CORE_SPAWN_CORRUPT_FILE:1392};
  const win32Code=typeof record.code==='string'&&Object.prototype.hasOwnProperty.call(expected,record.code)&&record.win32Code===expected[record.code]?expected[record.code]:undefined;
  return {stage,cause,win32Code};
}
export function isPublicNativeCode(value:unknown):value is string{return typeof value==='string'&&Object.prototype.hasOwnProperty.call(messages,value);}
export function nativeErrorCode(value:unknown):string|undefined {
  try{
    if(value&&typeof value==='object'&&typeof (value as {code?:unknown}).code==='string'){
      const code=(value as {code:string}).code;return /^[A-Z][A-Z0-9_]{2,63}$/.test(code)?code:undefined;
    }
    const text=typeof value==='string'?value:value instanceof Error?value.message:'';
    return /^([A-Z][A-Z0-9_]{2,63})(?=:|$)/.exec(text)?.[1];
  }catch{return undefined;}
}
/** Only fixed public catalog entries may bypass free-text token redaction. */
export function publicNativeErrorCode(title:string):string|undefined {
  const separator=title.indexOf(': ');if(separator<0||separator>64)return undefined;
  const code=title.slice(0,separator);return Object.prototype.hasOwnProperty.call(messages,code)?code:undefined;
}
export function structuredNativeError(value:unknown,fallback:string,language:UiLanguage):NativeOperationError|null{
  try{
    if(!value||typeof value!=='object')return null;
    const record=value as Record<string,unknown>;
    if(typeof record.code!=='string'||!/^(STATE|AUTOSTART|STARTUP|ELEVATION|RUNTIME|NETWORK|RULE|REPAIR|NATIVE|OPERATION|CORE|TUN|SESSION|SUBSCRIPTION|PROFILE|PROCESS|PROXY|ROUTE|CONFIG|REQUEST|CONNECT)_[A-Z0-9_]{1,54}$/.test(record.code))return null;
    const pair=messages[record.code];
    const category=['storage','startup','network','lifecycle','bridge','permission'].includes(String(record.category))?String(record.category):'native';
    const {stage,cause,win32Code}=publicFailureDetails(record);
    const detail=[stage,cause?`${cause}: ${tr(language,...causes[cause])}`:undefined].filter(Boolean).join(' · ');
    return new NativeOperationError(record.code,category,record.retryable===true||record.recoverable===true,`${pair?tr(language,...pair):fallback}${detail?` [${detail}]`:''}`,record.operationPending===true,stage,cause,win32Code);
  }catch{return null;}
}
export type AutostartStatus='unknown'|'pending'|'enabled'|'disabled'|'not-managed'|'unconfirmed';
export function autostartStatusLabel(status:AutostartStatus,language:UiLanguage){
  const labels:Record<AutostartStatus,[string,string]>={unknown:['Состояние Windows неизвестно','Windows state unknown'],pending:['Проверка записи Windows…','Checking Windows entry…'],enabled:['В Windows включён','Enabled in Windows'],disabled:['В Windows отключён','Disabled in Windows'],'not-managed':['В этой сборке не изменяется','Not managed by this build'],unconfirmed:['Состояние Windows не подтверждено','Windows state not confirmed']};
  return tr(language,...labels[status]);
}
