import type { ToastItem } from '../types/vpn';
import { useState } from 'react';
import { tr, type UiLanguage } from '../i18n';
import { copyInformation } from '../utils/clipboard';
import { toastDetails } from '../utils/toast';

interface ToastViewportProps {
  items: ToastItem[];
  language?: UiLanguage;
  onDismiss?: (id: string) => void;
  criticalMessage?: string;
  dismissLabel?: string;
  onDismissCritical?: () => void;
  actionLabel?: string;
  onCriticalAction?: () => void;
}

export function ToastViewport({ items, criticalMessage, dismissLabel, onDismissCritical, actionLabel, onCriticalAction, language='ru', onDismiss }: ToastViewportProps) {
  const [copyResult,setCopyResult]=useState<{id:string;ok:boolean}|null>(null);
  const label=(ru:string,en:string)=>tr(language,ru,en);
  return (
    <div className="toast-viewport" aria-live="polite" aria-atomic="true">
      {criticalMessage && (
        <article className="toast toast-card error" role="alert">
          <strong>{criticalMessage}</strong>
          {onCriticalAction && <button type="button" onClick={onCriticalAction}>{actionLabel}</button>}
          <button type="button" className="icon-button" aria-label={dismissLabel} onClick={onDismissCritical}>×</button>
        </article>
      )}
      {items.map((item) => (
        <article key={item.id} className={`toast toast-card ${item.tone}`} role={item.tone==='error'?'alert':'status'}>
          <strong>{item.overflowCount?label(`Другие ошибки: ${item.overflowCount}. Достигнут лимит истории уведомлений.`,`${item.overflowCount} more errors. Notification history limit reached.`):item.title}</strong>
          {item.tone==='error'&&<>
            <small>{item.code}{item.createdAt ? ` · ${new Date(item.createdAt).toLocaleString(language==='ru'?'ru-RU':'en-US')}` : ''}</small>
            <button type="button" onClick={()=>void copyInformation(toastDetails(item),navigator.clipboard).then(ok=>setCopyResult({id:item.id,ok}))}>{label('Копировать подробности','Copy details')}</button>
            {copyResult?.id===item.id&&<span role="status">{copyResult.ok?label('Скопировано','Copied'):label('Копирование недоступно','Copy unavailable')}</span>}
            {onDismiss&&<button type="button" onClick={()=>{setCopyResult(null);onDismiss(item.id);}}>{label('Закрыть','Dismiss')}</button>}
          </>}
        </article>
      ))}
    </div>
  );
}
