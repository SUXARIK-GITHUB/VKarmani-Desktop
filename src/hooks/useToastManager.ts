import { useCallback, useRef, useState } from 'react';
import { createToast } from '../utils/toast';
import { redactSensitiveText } from '../utils/redaction';
import type { ToastItem } from '../types/vpn';

export function useToastManager(notificationsEnabled: boolean) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const lastToastSignatureRef = useRef<{ title: string; tone: ToastItem['tone']; at: number } | null>(null);

  const pushToast = useCallback((title: string, tone: ToastItem['tone']) => {
    if (!notificationsEnabled) {
      return;
    }

    const now = Date.now();
    const safeTitle = redactSensitiveText(title);
    const lastToast = lastToastSignatureRef.current;
    if (lastToast && lastToast.title === safeTitle && lastToast.tone === tone && now - lastToast.at < 1600) {
      return;
    }

    lastToastSignatureRef.current = { title: safeTitle, tone, at: now };
    const toast = createToast(safeTitle, tone);
    setToasts((items: ToastItem[]) => [...items.slice(-3), toast]);

    window.setTimeout(() => {
      setToasts((items: ToastItem[]) => items.filter((item: ToastItem) => item.id !== toast.id));
    }, 2800);
  }, [notificationsEnabled]);

  return { toasts, pushToast };
}
