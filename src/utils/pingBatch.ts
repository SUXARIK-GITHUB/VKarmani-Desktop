import type { ConnectivityProbe, VpnServer } from '../types/vpn';

// Four matches the existing helper budget and the native ping admission limit.
// A connected VPN no longer forces a serial worker: ping never mutates routing.
export const PING_CONCURRENCY = 4;
export const PING_ITEM_TIMEOUT_MS = 9000; // Existing server_ping IPC deadline.
export const PING_BATCH_TIMEOUT_MS = 60000;
export type PingResult = { id: string; status: 'ok' | 'timeout' | 'unreachable' | 'cancelled'; probe?: ConnectivityProbe };
export interface PingBatchResult { results: PingResult[]; durationMs: number; success: number; timeout: number; unreachable: number; cancelled: number }

export async function runPingBatch(targets: VpnServer[], probe: (server: VpnServer) => Promise<ConnectivityProbe>, signal: AbortSignal, progress: (completed: number) => void = () => {}): Promise<PingBatchResult> {
  const started = performance.now();
  const results: PingResult[] = new Array(targets.length);
  let cursor = 0, completed = 0;
  const worker = async () => {
    while (!signal.aborted && performance.now() - started < PING_BATCH_TIMEOUT_MS) {
      const index = cursor++;
      if (index >= targets.length) return;
      const target = targets[index];
      const remaining = PING_BATCH_TIMEOUT_MS - (performance.now() - started);
      const outcome = await new Promise<PingResult>(resolve => {
        let settled = false;
        const finish = (result: PingResult) => { if (settled) return; settled = true; clearTimeout(timer); signal.removeEventListener('abort', abort); resolve(result); };
        const abort = () => finish({ id: target.id, status: 'cancelled' });
        const timer = setTimeout(() => finish({ id: target.id, status: 'timeout' }), Math.min(PING_ITEM_TIMEOUT_MS, remaining));
        signal.addEventListener('abort', abort, { once: true });
        if (signal.aborted) { abort(); return; }
        Promise.resolve().then(() => probe(target)).then(value => {
          const valid = value.success && typeof value.latencyMs === 'number' && Number.isFinite(value.latencyMs) && value.latencyMs > 0;
          finish({ id: target.id, status: valid ? 'ok' : 'unreachable', probe: value });
        }, error => finish({ id: target.id, status: /timeout|timed out|превысил|не завершилась/i.test(String(error)) ? 'timeout' : 'unreachable' }));
      });
      results[index] = outcome;
      progress(++completed);
    }
  };
  await Promise.all(Array.from({ length: Math.min(PING_CONCURRENCY, targets.length) }, worker));
  for (let i = 0; i < targets.length; i++) results[i] ??= { id: targets[i].id, status: signal.aborted ? 'cancelled' : 'timeout' };
  return { results, durationMs: performance.now() - started, success: results.filter(r => r.status === 'ok').length, timeout: results.filter(r => r.status === 'timeout').length, unreachable: results.filter(r => r.status === 'unreachable').length, cancelled: results.filter(r => r.status === 'cancelled').length };
}
export function applyPingBatch(current: VpnServer[], snapshot: VpnServer[], batch: PingBatchResult): VpnServer[] {
  // Pointer identity covers replacement even when IDs/endpoint labels are equal.
  if (current !== snapshot) return current;
  const results = new Map(batch.results.map(result => [result.id, result]));
  const checkedAt = new Date().toLocaleString('ru-RU');
  return current.map(server => {
    const result = results.get(server.id);
    if (!result || result.status === 'cancelled') return server;
    return { ...server, latency: result.status === 'ok' ? Math.max(1, Math.round(result.probe!.latencyMs!)) : null, latencyStatus: result.status === 'ok' ? 'ok' as const : 'failed' as const, latencyCheckedAt: checkedAt };
  });
}
