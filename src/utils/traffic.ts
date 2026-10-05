import type { TrafficSnapshot } from '../types/vpn';

export const TRAFFIC_HISTORY_LIMIT = 60;
export interface TrafficSample { at: number; receivedBytes: number; sentBytes: number; bytesPerSecond: number | null; source: TrafficSnapshot['source']; runtimeId?: string }
export function validTrafficSnapshot(snapshot: TrafficSnapshot | null): snapshot is TrafficSnapshot {
  return Boolean(snapshot && ['xray-stats','windows-tun-adapter'].includes(snapshot.source)
    && [snapshot.receivedBytes,snapshot.sentBytes].every(n => Number.isSafeInteger(n) && n >= 0));
}
export function appendTrafficSample(history: TrafficSample[], snapshot: TrafficSnapshot, at: number): TrafficSample[] {
  if (!validTrafficSnapshot(snapshot) || !Number.isFinite(at)) return history;
  const last = history[history.length-1], seconds = last ? (at-last.at)/1000 : 0;
  const delta = last ? snapshot.receivedBytes-last.receivedBytes + snapshot.sentBytes-last.sentBytes : -1;
  // Gaps, stale timestamps and resets must not invent transfer rates.
  const rate = last && !snapshot.baselineChanged && last.source === snapshot.source && last.runtimeId === snapshot.runtimeId && seconds > 0 && seconds <= 65 && snapshot.receivedBytes >= last.receivedBytes
    && snapshot.sentBytes >= last.sentBytes && delta >= 0 ? delta/seconds : null;
  if (last && at <= last.at) return history;
  return [...history, {at, receivedBytes:snapshot.receivedBytes, sentBytes:snapshot.sentBytes, bytesPerSecond:rate,source:snapshot.source,runtimeId:snapshot.runtimeId}].slice(-TRAFFIC_HISTORY_LIMIT);
}
export function formatTrafficBytes(value: number | null | undefined, language: 'ru' | 'en' = 'ru') {
  if (value === null || value === undefined || !Number.isSafeInteger(value) || value < 0) return '—';
  const units = language === 'ru' ? ['Б','КБ','МБ','ГБ','ТБ'] : ['B','KB','MB','GB','TB'];
  let current = value;
  let unit = 0;
  while (current >= 1024 && unit < units.length - 1) {
    current /= 1024;
    unit += 1;
  }

  return `${current >= 10 || unit === 0 ? current.toFixed(0) : current.toFixed(2)} ${units[unit]}`;
}

export function buildTrafficBars(history: TrafficSample[]) {
  const rates = history.slice(-30).map(s => s.bytesPerSecond);
  const maximum = Math.max(0, ...rates.filter((r): r is number => r !== null));
  return rates.map(rate => rate === null || maximum === 0 ? 0 : Math.min(100, rate/maximum*100));
}
