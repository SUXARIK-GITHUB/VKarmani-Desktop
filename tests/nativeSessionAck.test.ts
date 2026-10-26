import { afterEach, beforeEach, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: mocks.invoke }));
beforeEach(() => {
  vi.resetModules(); mocks.invoke.mockReset();
  vi.stubGlobal('window', { __TAURI_INTERNALS__: {}, setTimeout, clearTimeout });
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });
it('explicit revoke accepts only the actual false native acknowledgement', async () => {
  const { revokeNativeSessionAuthorization } = await import('../src/services/runtime');
  mocks.invoke.mockResolvedValue(false); await revokeNativeSessionAuthorization();
  expect(mocks.invoke).toHaveBeenCalledExactlyOnceWith('set_session_authorized', { authorized: false });
});
it.each([true, null, undefined])('refuses malformed/unconfirmed revoke acknowledgement %j', async result => {
  const { revokeNativeSessionAuthorization } = await import('../src/services/runtime');
  mocks.invoke.mockResolvedValue(result); await expect(revokeNativeSessionAuthorization()).rejects.toThrow('SESSION_REVOKE_UNCONFIRMED');
});
it('IPC rejection remains a failure, with credentials redacted in the surfaced error', async () => {
  const { revokeNativeSessionAuthorization } = await import('../src/services/runtime');
  mocks.invoke.mockRejectedValue('https://sub.vkarmani.com/DO_NOT_EXPOSE');
  try { await revokeNativeSessionAuthorization(); throw new Error('expected rejection'); }
  catch (error) { expect(String(error)).toContain('SESSION_REVOKE_FAILED'); expect(String(error)).not.toContain('DO_NOT_EXPOSE'); }
});
it('timeout is unconfirmed even if the native acknowledgement arrives later', async () => {
  vi.useFakeTimers(); vi.stubGlobal('window', { __TAURI_INTERNALS__: {}, setTimeout, clearTimeout });
  const { revokeNativeSessionAuthorization } = await import('../src/services/runtime');
  let release!: (value: boolean) => void; mocks.invoke.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  const pending = revokeNativeSessionAuthorization(); const rejected = expect(pending).rejects.toThrow('SESSION_REVOKE_FAILED');
  await vi.advanceTimersByTimeAsync(18001); await rejected;
  release(false); await vi.runAllTimersAsync(); expect(mocks.invoke).toHaveBeenCalledTimes(1);
});
it('web preview performs no native command', async () => {
  vi.stubGlobal('window', { setTimeout, clearTimeout });
  const { revokeNativeSessionAuthorization } = await import('../src/services/runtime');
  await revokeNativeSessionAuthorization(); expect(mocks.invoke).not.toHaveBeenCalled();
});
