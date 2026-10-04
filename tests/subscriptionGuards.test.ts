import { describe, expect, it } from 'vitest';
import { nativeConnectFailurePreservesRuntime, assertNativeRuntimeServerMatches, runtimeConfirmsTargetServer } from '../src/services/connectionGuards';

describe('subscription and runtime failure separation', () => {
  it.each(['CONNECT_PREFLIGHT: SERVICE_SHARED_OR_UNSUPPORTED', 'SUBSCRIPTION_UNAVAILABLE: retry', 'SUBSCRIPTION_REJECTED: revoked', 'SESSION_CHANGED: logout', 'Runtime уже выполняет другое действие'])('does not disconnect an existing runtime on native preflight rejection: %s', (message) => {
    expect(nativeConnectFailurePreservesRuntime(message)).toBe(true);
  });
  it('keeps rollback applicable for a real startup/readiness failure', () => {
    expect(nativeConnectFailurePreservesRuntime('Xray failed to open its listener')).toBe(false);
  });
  it('never confirms a native target with missing or mismatched identity', () => {
    expect(() => assertNativeRuntimeServerMatches(undefined, 'node', '', 'expected')).toThrow();
    expect(() => assertNativeRuntimeServerMatches('node', 'node', '', 'expected')).toThrow();
    expect(() => assertNativeRuntimeServerMatches('node', 'node', 'expected', 'expected')).not.toThrow();
    expect(runtimeConfirmsTargetServer({ bridge: 'tauri', coreInstalled: true, tunnelActive: true, lastPreparedServerId: 'node', message: '' }, 'node', 'expected')).toBe(false);
  });
});
