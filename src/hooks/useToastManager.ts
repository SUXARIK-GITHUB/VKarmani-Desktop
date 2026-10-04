import { useCallback, useEffect, useRef, useState } from 'react';
import { createToast } from '../utils/toast';
import { redactSensitiveText } from '../utils/redaction';
import type { ToastItem } from '../types/vpn';

export function useToastManager(notificationsEnabled: boolean) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const lastToastSignatureRef = useRef<{ title: string; tone: ToastItem['tone']; at: number } | null>(null);
  const timers = useRef(new Map<string, number>());
  useEffect(() => () => { timers.current.forEach(timer => clearTimeout(timer)); timers.current.clear(); }, []);

  const pushToast = useCallback((title: string, tone: ToastItem['tone'], options?: { key?: string; force?: boolean }) => {
    if (!notificationsEnabled && !options?.force) {
      return;
    }

    const now = Date.now();
    const safeTitle = redactSensitiveText(title);
    const lastToast = lastToastSignatureRef.current;
    if (!options?.key && lastToast && lastToast.title === safeTitle && lastToast.tone === tone && now - lastToast.at < 1600) {
      return;
    }

    lastToastSignatureRef.current = { title: safeTitle, tone, at: now };
    const toast = createToast(safeTitle, tone);
    if (options?.key) toast.id = `feedback:${options.key}`;
    const previousTimer = timers.current.get(toast.id);
    if (previousTimer !== undefined) clearTimeout(previousTimer);
    setToasts((items: ToastItem[]) => [...items.filter(item => item.id !== toast.id).slice(-3), toast]);

    timers.current.set(toast.id, window.setTimeout(() => {
      setToasts((items: ToastItem[]) => items.filter((item: ToastItem) => item.id !== toast.id));
      timers.current.delete(toast.id);
    }, 2800));
  }, [notificationsEnabled]);

  return { toasts, pushToast };
}
