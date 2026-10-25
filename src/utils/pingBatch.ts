import type { ConnectivityProbe, VpnServer } from '../types/vpn';
import { getServerPingTargets } from './serverPing';
import { serverMeasurementIdentity } from './serverMeasurements';

// Four matches the existing helper budget and the native ping admission limit.
// A connected VPN no longer forces a serial worker: ping never mutates routing.
export const PING_CONCURRENCY = 4;
export const PING_ITEM_TIMEOUT_MS = 9000; // Existing server_ping IPC deadline.
export const PING_BATCH_TIMEOUT_MS = 60000;
export type PingResult = { id: string; status: 'ok' | 'timeout' | 'unreachable' | 'cancelled'; probe?: ConnectivityProbe };
export interface PingBatchResult { results: PingResult[]; durationMs: number; success: number; timeout: number; unreachable: number; cancelled: number }

export async function runPingBatch(targets: VpnServer[], probe: (server: VpnServer) => Promise<ConnectivityProbe>, signal: AbortSignal, progress: (completed: number) => void = () => {}): Promise<PingBatchResult> {
  const started = performance.now();
  // Flatten into the same shared queue: no per-Auto pool and no nested budget.
  const groups = targets.map(getServerPingTargets);
  const jobs = groups.flatMap((members, logical) => members.map(target => ({ target, logical })));
  const outcomes: PingResult[][] = groups.map(() => []);
  let cursor = 0, completed = groups.filter(group => !group.length).length;
  if (completed) progress(completed);
  const worker = async () => {
    while (!signal.aborted && performance.now() - started < PING_BATCH_TIMEOUT_MS) {
      const index = cursor++;
      if (index >= jobs.length) return;
      const { target, logical } = jobs[index];
      const remaining = PING_BATCH_TIMEOUT_MS - (performance.now() - started);
      const outcome = await new Promise<PingResult>(resolve => {
        let settled = false;
        const finish = (result: PingResult) => { if (settled) return; settled = true; clearTimeout(timer); resolve(signal.aborted ? { id: target.id, status: 'cancelled' } : result); };
        const timer = setTimeout(() => finish({ id: target.id, status: 'timeout' }), Math.min(PING_ITEM_TIMEOUT_MS, remaining));
        // IPC has its own deadline and cannot be cancelled by AbortSignal.
        // Drain started probes within the same item deadline before releasing
        // the pool; stop queued work and discard every cancelled result.
        if (signal.aborted) { finish({ id: target.id, status: 'cancelled' }); return; }
        Promise.resolve().then(() => signal.aborted ? undefined : probe(target)).then(value => {
          const valid = value?.success === true && typeof value.latencyMs === 'number' && Number.isFinite(value.latencyMs) && value.latencyMs > 0;
          finish({ id: target.id, status: valid ? 'ok' : 'unreachable', probe: value });
        }, error => finish({ id: target.id, status: /timeout|timed out|превысил|не завершилась/i.test(String(error)) ? 'timeout' : 'unreachable' }));
      });
      outcomes[logical].push(outcome);
      if (outcomes[logical].length === groups[logical].length) progress(++completed);
    }
  };
  await Promise.all(Array.from({ length: Math.min(PING_CONCURRENCY, jobs.length) }, worker));
  const results: PingResult[] = targets.map((target, logical) => {
    if (signal.aborted) return { id: target.id, status: 'cancelled' };
    const values = outcomes[logical];
    // Preserve ordinary-node failure diagnostics exactly; only Auto aggregates.
    if (target.runtimeTemplate?.profileKind !== 'auto' && values[0]) return values[0];
    const best = values.filter(result => result.status === 'ok').reduce<PingResult | undefined>((current, result) =>
      !current || result.probe!.latencyMs! < current.probe!.latencyMs! ? result : current, undefined);
    if (best) return { ...best, id: target.id };
    return { id: target.id, status: values.length < groups[logical].length || values.some(result => result.status === 'timeout') ? 'timeout' : 'unreachable' };
  });
  return { results, durationMs: performance.now() - started, success: results.filter(r => r.status === 'ok').length, timeout: results.filter(r => r.status === 'timeout').length, unreachable: results.filter(r => r.status === 'unreachable').length, cancelled: results.filter(r => r.status === 'cancelled').length };
}
export function applyPingBatch(current: VpnServer[], snapshot: VpnServer[], batch: PingBatchResult): VpnServer[] {
  // Pointer identity covers replacement even when IDs/endpoint labels are equal.
  if (current !== snapshot) return current;
  const results = new Map(batch.results.map(result => [result.id, result]));
  const checkedAt = new Date().toISOString();
  return current.map(server => {
    const result = results.get(server.id);
    if (!result || result.status === 'cancelled') return server;
    return { ...server, latency: result.status === 'ok' ? result.probe!.latencyMs! : null, latencyStatus: result.status === 'ok' ? 'ok' as const : 'failed' as const, latencyCheckedAt: checkedAt,
      latencyIdentity: serverMeasurementIdentity(server), latencySource: server.runtimeTemplate?.profileKind === 'auto' ? 'auto-members-physical-tcp' as const : 'physical-tcp' as const };
  });
}
