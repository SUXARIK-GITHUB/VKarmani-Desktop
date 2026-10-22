import type { ToastItem } from '../types/vpn';
import { redactSensitiveText } from './redaction';
import {publicNativeErrorCode} from './nativeErrors';

export function redactToastTitle(title:string):string {
  const code=publicNativeErrorCode(title);
  return (code?`${code}: ${redactSensitiveText(title.slice(code.length+2))}`:redactSensitiveText(title)).slice(0,2048);
}

export function createToast(title: string, tone: ToastItem['tone']): ToastItem {
  const safeTitle = redactToastTitle(title);
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    title: safeTitle,
    tone,
    ...(tone === 'error' ? {code: /^([A-Z][A-Z0-9_]{2,63})(?=[:;\s]|$)/.exec(safeTitle)?.[1] ?? 'OPERATION_FAILED', createdAt: new Date().toISOString()} : {})
  };
}

export function mergeToastItems(items: ToastItem[], next: ToastItem): ToastItem[] {
  const different = items.filter(item => item.id !== next.id && !(item.tone === 'error' && next.tone === 'error' && item.title === next.title));
  const errors = different.filter(item=>item.tone==='error');
  const transient = different.filter(item=>item.tone!=='error');
  // Routine feedback cannot evict an unresolved error. Distinct failures have
  // a bounded history; the UI exposes the count and manual dismissal.
  if (next.tone !== 'error') return [...errors,...transient.slice(-3),next];
  const overflow = errors.find(item=>item.id==='error-overflow');
  const failures = [...errors.filter(item=>item.id!=='error-overflow'),next];
  if (failures.length <= 16 && !overflow) return [...failures,...transient.slice(-3)];
  return [...failures.slice(0,15), {id:'error-overflow',tone:'error',code:'ERROR_HISTORY_LIMIT',title:'ERROR_HISTORY_LIMIT',
    overflowCount:(overflow?.overflowCount??0)+failures.length-15}, ...transient.slice(-3)];
}

export function toastDetails(item: ToastItem): string {
  return JSON.stringify({code:item.code??'OPERATION_FAILED',timestamp:item.createdAt??null,message:redactToastTitle(item.title),...(item.overflowCount?{omittedCount:item.overflowCount}:{})},null,2);
}
