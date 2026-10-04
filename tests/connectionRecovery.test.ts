import { describe, expect, it } from 'vitest';
import type { RuntimeStatus } from '../src/types/vpn';
import { connectionFailureState, acceptRuntimeSnapshot } from '../src/utils/runtimeSnapshot';

const runtime = (server: string, active = true): RuntimeStatus => ({ bridge: 'tauri', coreInstalled: true,
  tunnelActive: active, nativeInstanceId: 'native', runtimeRevision: 4, message: '',
  lastPreparedServerId: server, lastPreparedServerFingerprint: `fp-${server}`, launchMode: 'sidecar' });
describe('switch recovery follows authoritative native ownership', () => {
  it.each(['A → B success', 'A → B prepare failure', 'A → Auto prepare failure', 'Auto → normal prepare failure'])('%s preserves an active runtime and its proxy journal', () => {
    expect(connectionFailureState(runtime('A'), 1, 1)).toBe('active');
  });
  it('new Xray failure permits recovery only from authoritative idle', () => {
    expect(connectionFailureState(runtime('B', false), 1, 1)).toBe('idle');
    expect(connectionFailureState({ ...runtime('B', false), launchMode: 'mock' }, 1, 1)).toBe('idle');
    expect(connectionFailureState(null, 1, 1)).toBe('unknown');
    expect(connectionFailureState({ ...runtime('B', false), nativeInstanceId: undefined }, 1, 1)).toBe('unknown');
  });
  it('disconnect during switch and a running native operation never authorize rollback', () => {
    expect(connectionFailureState(runtime('A'), 1, 1, true)).toBe('active');
    expect(connectionFailureState({ ...runtime('A', false), launchMode: 'mock' }, 1, 1, true)).toBe('idle');
    expect(connectionFailureState({ ...runtime('A', false), operation: { id: 4, kind: 'connect', stage: 'starting', startedAt: 0, deadlineAt: 1 } }, 1, 1)).toBe('pending');
  });
  it('rapid A → B → C and watchdog retirement prevent late B from completing C', () => {
    expect(connectionFailureState(runtime('C'), 2, 3)).toBe('stale');
    expect(connectionFailureState(runtime('B'), 2, 4)).toBe('stale');
  });
  it('rejects stale snapshot side effects and synthetic native idle', () => {
    const latest = runtime('C');
    expect(acceptRuntimeSnapshot(latest, { ...runtime('A', false), runtimeRevision: 3 })).toBe(latest);
    expect(acceptRuntimeSnapshot(latest, { ...runtime('A', false), nativeInstanceId: undefined, launchMode: 'mock' })).toBe(latest);
  });
});
