import { useCallback, useEffect, useRef, useState } from 'react';
import { createToast, mergeToastItems,redactToastTitle } from '../utils/toast';
import type { ToastItem } from '../types/vpn';

export function useToastManager(notificationsEnabled: boolean) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const lastToastSignatureRef = useRef<{ title: string; tone: ToastItem['tone']; at: number } | null>(null);
  const timers = useRef(new Map<string, number>());
  useEffect(() => () => { timers.current.forEach(timer => clearTimeout(timer)); timers.current.clear(); }, []);

  const pushToast = useCallback((title: string, tone: ToastItem['tone'], options?: { key?: string; force?: boolean }) => {
    if (!notificationsEnabled && !options?.force && tone !== 'error') {
      return;
    }

    const now = Date.now();
    const safeTitle = redactToastTitle(title);
    const lastToast = lastToastSignatureRef.current;
    if (!options?.key && lastToast && lastToast.title === safeTitle && lastToast.tone === tone && now - lastToast.at < 1600) {
      return;
    }

    lastToastSignatureRef.current = { title: safeTitle, tone, at: now };
    const toast = createToast(safeTitle, tone);
    if (options?.key) toast.id = `feedback:${options.key}`;
    const previousTimer = timers.current.get(toast.id);
    if (previousTimer !== undefined) clearTimeout(previousTimer);
    timers.current.delete(toast.id);
    setToasts((items: ToastItem[]) => mergeToastItems(items, toast));
    if (tone === 'error') return;

    timers.current.set(toast.id, window.setTimeout(() => {
      setToasts((items: ToastItem[]) => items.filter((item: ToastItem) => item.id !== toast.id));
      timers.current.delete(toast.id);
    }, 2800));
  }, [notificationsEnabled]);

  const dismissToast = useCallback((id: string) => {
    const timer = timers.current.get(id); if (timer !== undefined) clearTimeout(timer);
    timers.current.delete(id); setToasts(items=>items.filter(item=>item.id!==id));
  }, []);
  return { toasts, pushToast, dismissToast };
}
