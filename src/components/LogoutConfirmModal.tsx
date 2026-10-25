import { useEffect, useRef } from 'react';
import { tr, type UiLanguage } from '../i18n';

interface Props { open: boolean; language: UiLanguage; busy: boolean; onCancel: () => void; onConfirm: () => void }
export function LogoutConfirmModal({ open, language, busy, onCancel, onConfirm }: Props) {
  const dialog = useRef<HTMLElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement;
    cancel.current?.focus();
    return () => { if (previous instanceof HTMLElement && previous.isConnected) previous.focus(); };
  }, [open]);
  if (!open) return null;
  return <div className="vk-modal-backdrop" role="presentation" onMouseDown={onCancel}>
    <section ref={dialog} className="vk-modal-card vk-info-modal" role="dialog" aria-modal="true"
      aria-labelledby="logout-confirm-title" aria-describedby="logout-confirm-description" onMouseDown={event => event.stopPropagation()}
      onKeyDown={event => {
        if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); onCancel(); }
        if (event.key === 'Tab') {
          const buttons = Array.from(dialog.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? []);
          const first = buttons[0]; const last = buttons[buttons.length - 1];
          if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
          else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
        }
      }}>
      <header className="vk-modal-header"><h2 id="logout-confirm-title">{tr(language, 'Выйти из VKarmani?', 'Sign out of VKarmani?')}</h2></header>
      <div className="vk-modal-scroll"><p id="logout-confirm-description">{tr(language,
        'После сохранения данных VKarmani остановит своё соединение и удалит сохранённый ключ и кэш профиля. Настройки и правила приложений останутся.',
        'After saving, VKarmani will stop its own connection and remove the saved key and profile cache. Settings and app rules will remain.')}</p>
        {busy && <p role="status">{tr(language, 'Сначала дождитесь завершения текущего действия.', 'Wait for the current operation to finish first.')}</p>}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button ref={cancel} type="button" className="ghost-button" onClick={onCancel}>{tr(language, 'Отмена', 'Cancel')}</button>
          <button type="button" className="danger-button" disabled={busy} onClick={onConfirm}>{tr(language, 'Отключиться и выйти', 'Disconnect and sign out')}</button>
        </div>
      </div>
    </section>
  </div>;
}
