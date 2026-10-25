import { tr, type UiLanguage } from '../i18n';

interface Props {
  language: UiLanguage;
  code?: string;
  busy: boolean;
  safeStart: boolean;
  confirmBackup: boolean;
  onInspect: () => void;
  onConfirm: () => void;
  onCancel: () => void;
}
export function StorageRecoveryNotice(props: Props) {
  const { language, code, busy, safeStart, confirmBackup } = props;
  if (!code && !safeStart) return null;
  const safeCode = code && /^STATE_[A-Z0-9_]{1,64}$/.test(code) ? code : 'STATE_UNAVAILABLE';
  return <section className="panel compact-panel" role={code ? 'alert' : 'status'}
    style={{ position: 'fixed', zIndex: 60, bottom: 18, left: 18, right: 18, maxHeight: 'calc(100vh - 90px)', overflow: 'auto', background: 'var(--bg-2)' }}>
    <h3>{tr(language, code ? 'Хранилище требует внимания' : 'Режим восстановления', code ? 'Storage needs attention' : 'Recovery mode')}</h3>
    <p>{tr(language, 'Автоподключение, повышение прав и автоматическая установка обновлений остановлены для этого сеанса. Текущее соединение не отключается.', 'Automatic connection, elevation and update installation are stopped for this session. The current connection is not disconnected.')}</p>
    {code && <><p>{tr(language, 'Ошибка хранилища не означает неверный ключ. Оригиналы не сбрасываются; неподтверждённое сохранение не считается успешным.', 'A storage error does not mean an invalid key. Originals are not reset; an unconfirmed save is not a successful save.')}</p><code>{safeCode}</code>
      <p>{tr(language, confirmBackup ? 'Восстановить просмотренную проверенную резервную копию? Повреждённый оригинал будет сохранён отдельно.' : 'Повторное чтение заменит неподтверждённые изменения в интерфейсе. Восстановление резервной копии требует отдельного подтверждения.', confirmBackup ? 'Restore the reviewed verified backup? The corrupt original will be preserved separately.' : 'Reloading replaces unconfirmed interface edits. Restoring a backup requires separate confirmation.')}</p>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>{confirmBackup ? <><button type="button" className="ghost-button" disabled={busy} onClick={props.onConfirm}>{tr(language, 'Восстановить эту копию', 'Restore this backup')}</button><button type="button" className="ghost-button" disabled={busy} onClick={props.onCancel}>{tr(language, 'Отмена', 'Cancel')}</button></> : <button type="button" className="ghost-button" disabled={busy} onClick={props.onInspect}>{tr(language, busy ? 'Читаем хранилище…' : 'Повторить чтение', busy ? 'Reading storage…' : 'Reload storage')}</button>}</div></>}
  </section>;
}
