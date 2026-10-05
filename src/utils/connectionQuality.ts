import type { VpnServer } from '../types/vpn';
import { tr } from '../i18n';

export function connectionQuality(server: Pick<VpnServer, 'latency' | 'latencyStatus'>, checking = false) {
  if (checking || server.latencyStatus === 'checking') return { level: 0, state: 'checking', tone: 'checking' } as const;
  if (server.latencyStatus === 'failed') return { level: 0, state: 'failed', tone: 'warn' } as const;
  const ms = server.latency;
  if (server.latencyStatus !== 'ok' || typeof ms !== 'number' || !Number.isFinite(ms) || ms <= 0) return { level: 0, state: 'unchecked', tone: 'muted' } as const;
  if (ms <= 50) return { level: 4, state: 'excellent', tone: 'good' } as const;
  if (ms <= 100) return { level: 3, state: 'good', tone: 'good' } as const;
  if (ms <= 180) return { level: 2, state: 'fair', tone: 'warn' } as const;
  if (ms <= 300) return { level: 1, state: 'poor', tone: 'error' } as const;
  return { level: 1, state: 'very-poor', tone: 'error' } as const;
}

export function qualityLabel(server: Pick<VpnServer, 'latency' | 'latencyStatus'>, language: 'ru' | 'en', checking = false) {
  const quality = connectionQuality(server, checking);
  const labels = {
    unchecked: ['Не проверено', 'Not checked'], checking: ['Проверяем…', 'Checking…'], failed: ['Сервер недоступен', 'Server unreachable'],
    excellent: ['Отличное', 'Excellent'], good: ['Хорошее', 'Good'], fair: ['Среднее', 'Fair'], poor: ['Слабое', 'Poor'], 'very-poor': ['Очень слабое', 'Very poor']
  } as const;
  const [ru, en] = labels[quality.state];
  const label = tr(language, ru, en);
  return quality.level ? `${label} · ${server.latency! < 1 ? '<1' : Math.round(server.latency!)} ${tr(language, 'мс', 'ms')}` : label;
}
