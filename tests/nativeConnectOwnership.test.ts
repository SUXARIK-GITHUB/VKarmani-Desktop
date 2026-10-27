import { beforeEach, describe, expect, it, vi } from 'vitest';
const native = vi.hoisted(() => ({ connect: vi.fn(), proxy: vi.fn(), rollback: vi.fn(), disconnect: vi.fn(), flush: vi.fn() }));
vi.mock('../src/services/storage', () => ({ flushPersistentWrites: native.flush }));
vi.mock('../src/services/runtime', async importOriginal => ({ ...await importOriginal<Record<string, unknown>>(),
  isTauriRuntime: true, requestNativeConnect: native.connect, setNativeSystemProxy: native.proxy,
  rollbackFailedNativeConnect: native.rollback, requestNativeDisconnect: native.disconnect,
}));
import auto from './fixtures/xray/auto.json';
import { parseXrayJsonSubscriptionToServers as parse } from '../src/services/remnawave/subscriptionParser';
import { remnawaveClient } from '../src/services/remnawave';
import { buildServerRuntimeFingerprint } from '../src/utils/serverIdentity';
import policyMatrix from './fixtures/policies/tun-admission.json';
import type { SplitTunnelEntry, TunRoutingMode } from '../src/types/vpn';
const [server] = parse(JSON.stringify(auto));
const status = () => ({ lastPreparedServerId: server.id, lastPreparedServerFingerprint: buildServerRuntimeFingerprint(server), configPath: 'owned-B.json' });
beforeEach(() => { vi.resetAllMocks(); native.flush.mockResolvedValue(undefined); native.proxy.mockResolvedValue({ enabled: true }); native.rollback.mockResolvedValue({ tunnelActive: false }); });
it.each(policyMatrix)('actual native-client admission matches shared policy: $name', async row => {
  native.connect.mockResolvedValue(status());
  const before = structuredClone(row.entries);
  const result = remnawaveClient.connect(server, { tunnelMode: 'tun', tunRoutingMode: row.mode as TunRoutingMode, splitTunnelEntries: row.entries as SplitTunnelEntry[] });
  if (row.blocked) {
    await expect(result).rejects.toThrow('RULE_SELECTION_EMPTY');
    expect(native.flush).not.toHaveBeenCalled(); expect(native.connect).not.toHaveBeenCalled();
  } else {
    await result; expect(native.connect).toHaveBeenCalledOnce();
    expect(native.connect.mock.calls[0][2]).toEqual(row.entries.filter(entry => entry.enabled));
  }
  expect(row.entries).toEqual(before);
  expect(native.proxy).not.toHaveBeenCalled(); expect(native.disconnect).not.toHaveBeenCalled();
});
describe('native connect cleanup is scoped to the exact returned runtime', () => {
  it.each(['selected', 'all', 'exclude'] as const)('passes authorized application routing in %s to native without changing rules', async tunRoutingMode => {
    native.connect.mockResolvedValueOnce(status());
    const entries: SplitTunnelEntry[] = [{ id: 'fixture-rule', kind: 'app', value: 'C:/Fixture/app.exe', enabled: true, policy: tunRoutingMode === 'selected' ? 'VPN' : 'DIRECT' }];
    await remnawaveClient.connect(server, { tunnelMode: 'tun', tunRoutingMode, splitTunnelEntries: entries });
    expect(native.connect).toHaveBeenCalledWith(server,'tun',entries,'ipv4',false,undefined,tunRoutingMode);
    expect(native.proxy).not.toHaveBeenCalled();
    expect(native.rollback).not.toHaveBeenCalled(); expect(native.disconnect).not.toHaveBeenCalled();
  });
  it.each(['all', 'exclude'] as const)('keeps ordinary %s TUN available with inactive VPN rules and disabled DIRECT intent', async tunRoutingMode => {
    native.connect.mockResolvedValueOnce(status());
    const entries = [{ id: 'vpn', kind: 'app' as const, value: 'app.exe', enabled: true, policy: 'VPN' as const },
      { id: 'direct', kind: 'service' as const, value: 'PrivateService', enabled: false, policy: 'DIRECT' as const }];
    await remnawaveClient.connect(server, { tunnelMode: 'tun', tunRoutingMode, splitTunnelEntries: entries });
    expect(native.connect).toHaveBeenCalledWith(server, 'tun', [entries[0]], 'ipv4', false, undefined, tunRoutingMode);
    expect(entries[1]).toMatchObject({ enabled: false, policy: 'DIRECT', value: 'PrivateService' });
    expect(native.disconnect).not.toHaveBeenCalled(); expect(native.rollback).not.toHaveBeenCalled();
  });
  it.each(['STATE_WRITE_PENDING', 'STATE_CONFLICT', 'STATE_RESTORE_BLOCKED'])('preserves the existing connection when saving is unconfirmed: %s', async code => {
    native.flush.mockRejectedValueOnce(new Error(code));
    await expect(remnawaveClient.connect(server, { reconnect: true, useSystemProxy: true })).rejects.toThrow(code);
    expect(native.connect).not.toHaveBeenCalled(); expect(native.proxy).not.toHaveBeenCalled();
    expect(native.rollback).not.toHaveBeenCalled(); expect(native.disconnect).not.toHaveBeenCalled();
  });
  it('waits for durable save before starting or replacing a runtime', async () => {
    let release!: () => void;
    native.flush.mockImplementationOnce(() => new Promise<void>(resolve => { release = resolve; }));
    native.connect.mockResolvedValueOnce(status());
    const pending = remnawaveClient.connect(server);
    await vi.waitFor(() => expect(native.flush).toHaveBeenCalled());
    expect(native.connect).not.toHaveBeenCalled(); release();
    await pending; expect(native.connect).toHaveBeenCalledTimes(1);
  });
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
