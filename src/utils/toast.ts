import type { ToastItem } from '../types/vpn';
import { redactSensitiveText } from './redaction';

export function createToast(title: string, tone: ToastItem['tone']): ToastItem {
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    title: redactSensitiveText(title),
    tone
  };
}
