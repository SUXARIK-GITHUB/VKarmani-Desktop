import { beforeEach, describe, expect, it, vi } from 'vitest';
const native = vi.hoisted(() => ({ connect: vi.fn(), proxy: vi.fn(), rollback: vi.fn(), disconnect: vi.fn() }));
vi.mock('../src/services/runtime', async importOriginal => ({ ...await importOriginal<Record<string, unknown>>(),
  isTauriRuntime: true, requestNativeConnect: native.connect, setNativeSystemProxy: native.proxy,
  rollbackFailedNativeConnect: native.rollback, requestNativeDisconnect: native.disconnect,
}));
import auto from './fixtures/xray/auto.json';
import { parseXrayJsonSubscriptionToServers as parse } from '../src/services/remnawave/subscriptionParser';
import { remnawaveClient } from '../src/services/remnawave';
import { buildServerRuntimeFingerprint } from '../src/utils/serverIdentity';
const [server] = parse(JSON.stringify(auto));
const status = () => ({ lastPreparedServerId: server.id, lastPreparedServerFingerprint: buildServerRuntimeFingerprint(server), configPath: 'owned-B.json' });
beforeEach(() => { vi.clearAllMocks(); native.proxy.mockResolvedValue({ enabled: true }); native.rollback.mockResolvedValue({ tunnelActive: false }); });
describe('native connect cleanup is scoped to the exact returned runtime', () => {
  it.each(['prepare failure', 'PROCESS_STOP_UNCONFIRMED', 'Runtime уже выполняет другое действие', 'Подключение заняло больше'])('never restores proxy/disconnects on rejected connect: %s', async message => {
    native.connect.mockRejectedValueOnce(new Error(message));
    await expect(remnawaveClient.connect(server, { reconnect: true, useSystemProxy: true })).rejects.toThrow();
    expect(native.proxy).not.toHaveBeenCalled(); expect(native.rollback).not.toHaveBeenCalled(); expect(native.disconnect).not.toHaveBeenCalled();
  });
  it('enables proxy only for the owned runtime and preserves successful stats/Auto response', async () => {
    native.connect.mockResolvedValueOnce(status());
    const result = await remnawaveClient.connect(server, { reconnect: true, useSystemProxy: true });
    expect(result.runtime?.configPath).toBe('owned-B.json');
    expect(native.proxy).toHaveBeenCalledWith(true, 'owned-B.json');
    expect(native.rollback).not.toHaveBeenCalled();
  });
  it('post-start proxy failure invokes one ownership-checked rollback, never an unscoped false/disconnect', async () => {
    native.connect.mockResolvedValueOnce(status()); native.proxy.mockRejectedValueOnce(new Error('injected proxy failure'));
    await expect(remnawaveClient.connect(server, { useSystemProxy: true })).rejects.toThrow('injected proxy failure');
    expect(native.rollback).toHaveBeenCalledWith('owned-B.json');
    expect(native.proxy).toHaveBeenCalledTimes(1); expect(native.disconnect).not.toHaveBeenCalled();
  });
  it('stale B cleanup cannot fall back to cancelling C when ownership has changed', async () => {
    native.connect.mockResolvedValueOnce(status()); native.proxy.mockRejectedValueOnce(new Error('RUNTIME_SUPERSEDED'));
    native.rollback.mockRejectedValueOnce(new Error('RUNTIME_SUPERSEDED'));
    await expect(remnawaveClient.connect(server, { useSystemProxy: true })).rejects.toThrow('RUNTIME_SUPERSEDED');
    expect(native.disconnect).not.toHaveBeenCalled();
    expect(native.proxy).not.toHaveBeenCalledWith(false);
  });
});
