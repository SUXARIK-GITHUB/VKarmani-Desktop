import { beforeEach, describe, expect, it, vi } from 'vitest';
const ipc = vi.hoisted(() => {
  const data = new Map<string, string>();
  vi.stubGlobal('window', { __TAURI_INTERNALS__: {}, dispatchEvent: vi.fn(), setTimeout: globalThis.setTimeout, clearTimeout: globalThis.clearTimeout, localStorage: {
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => { data.set(key, value); }, removeItem: (key: string) => { data.delete(key); }
  } });
  return { invoke: vi.fn(), data };
});
vi.mock('@tauri-apps/api/core', () => ({ invoke: ipc.invoke }));
import auto from './fixtures/xray/auto.json';
import { parseXrayJsonSubscriptionToServers as parse } from '../src/services/remnawave/subscriptionParser';
import { normalizeStoredSettings, loadSettings, saveSettings } from '../src/services/storage';
import { remnawaveClient } from '../src/services/remnawave';
import { requestNativeConnect } from '../src/services/runtime';
import { ConnectionController } from '../src/services/connectionController';
import { buildServerRuntimeFingerprint } from '../src/utils/serverIdentity';
import type { SplitTunnelEntry, RuntimeStatus } from '../src/types/vpn';
const [server] = parse(JSON.stringify(auto));
const entry: SplitTunnelEntry = { id: 'test', kind: 'app', value: 'Example.exe', policy: 'VPN', enabled: true, schemaVersion: 2 };
const observed = (active: boolean): RuntimeStatus => ({ bridge: 'tauri', coreInstalled: true, tunnelActive: active,
  nativeInstanceId: 'isolated-ipc', runtimeRevision: 1, message: '', xrayPid: active ? 17 : undefined,
  configPath: active ? 'synthetic-owned-config' : undefined, lastPreparedServerId: server.id,
  lastPreparedServerFingerprint: buildServerRuntimeFingerprint(server) });
beforeEach(() => {
  ipc.data.clear(); ipc.invoke.mockReset();
  ipc.invoke.mockImplementation(async (command: string, args: Record<string, unknown>) => {
    // This boundary is deliberately an IPC fixture, not native acceptance.
    if (command === 'request_connect') {
      if (args.networkMode === 'tun' && args.tunRoutingMode === 'selected') throw { code: 'TUN_PROCESS_ENFORCEMENT_UNAVAILABLE', category: 'network', recoverable: false };
      return observed(true);
    }
    return undefined;
  });
});
describe('TUN settings through controller, service and actual IPC serializer', () => {
  it.each([false, 1, 'corrupt', [], ['all']])('path contract: present malformed settings %j stay quarantined', value => {
    expect(normalizeStoredSettings(value)).toMatchObject({ tunRoutingMode: 'selected', tunRoutingModeInvalid: true, autoConnect: false, autoConnectFavorite: false });
  });
  it('path contract: malformed JSON is distinct from absent first-run settings', () => {
    expect(loadSettings()).toMatchObject({ tunRoutingMode: 'all', autoConnect: false });
    ipc.data.set('vkarmani.settings', '{"tunRoutingMode":"selected"');
    expect(loadSettings()).toMatchObject({ tunRoutingMode: 'selected', tunRoutingModeInvalid: true, autoConnect: false });
    expect(ipc.data.get('vkarmani.settings')).toBe('{"tunRoutingMode":"selected"');
  });
  it.each([{ entries: [] }, { entries: [entry] }])('explicit all survives save/restart with app list $entries', async ({ entries }) => {
    ipc.data.set('vkarmani.split-tunnel.entries', JSON.stringify(entries));
    // SettingsTab persists an explicit user intent, overriding legacy inference.
    saveSettings({ ...normalizeStoredSettings(null, entries.length > 0), tunnelMode: 'tun', tunRoutingMode: 'all' });
    const restored = loadSettings(); expect(restored.tunRoutingMode).toBe('all');
    const controller = new ConnectionController();
    const outcome = await controller.run({ kind: 'connect', target: server,
      options: { tunnelMode: restored.tunnelMode, tunRoutingMode: restored.tunRoutingMode, splitTunnelEntries: entries } }, {
      native: true, resolve: async value => value, connect: (value, options) => remnawaveClient.connect(value, options),
      observe: async () => observed(false), disconnect: vi.fn(), disconnectRequested: () => false, phase: vi.fn()
    });
    expect(outcome.kind).toBe('connected');
    expect(ipc.invoke).toHaveBeenCalledWith('request_connect', expect.objectContaining({ networkMode: 'tun', tunRoutingMode: 'all' }));
    expect(ipc.invoke.mock.calls.map(call => call[0])).not.toContain('set_system_proxy');
  });
  it.each(['all','selected','exclude'] as const)('keeps explicit %s even with legacy app entries', mode => {
    expect(normalizeStoredSettings({ tunRoutingMode: mode }, true).tunRoutingMode).toBe(mode);
  });
  it('missing policy is reported as required rather than invented selected', async () => {
    await expect(remnawaveClient.connect(server, { tunnelMode: 'tun' })).rejects.toMatchObject({ code: 'TUN_POLICY_REQUIRED' });
    await expect(requestNativeConnect(server, 'tun')).rejects.toMatchObject({ code: 'TUN_POLICY_REQUIRED' });
    expect(ipc.invoke).not.toHaveBeenCalled();
  });
  it.each([null, '', 'ALL', 'garbage', 1])('corrupt stored mode %j cannot silently become full TUN', async value => {
    const restored = normalizeStoredSettings({ tunnelMode: 'tun', tunRoutingMode: value });
    expect(restored).toMatchObject({ tunRoutingMode: 'selected', tunRoutingModeInvalid: true });
    saveSettings(restored);
    const again = loadSettings(); expect(again).toMatchObject({ tunRoutingModeInvalid: true });
    await expect(remnawaveClient.connect(server, { tunnelMode: 'tun', tunRoutingMode: again.tunRoutingMode,
      ...{ tunRoutingModeInvalid: true } })).rejects.toMatchObject({ code: 'TUN_POLICY_INVALID' });
    expect(ipc.invoke.mock.calls.filter(call => call[0] === 'request_connect')).toHaveLength(0);
  });
  it('keeps selected refusal before runtime, with no cleanup command', async () => {
    await expect(remnawaveClient.connect(server, { tunnelMode: 'tun', tunRoutingMode: 'selected', splitTunnelEntries: [entry] }))
      .rejects.toMatchObject({ code: 'TUN_PROCESS_ENFORCEMENT_UNAVAILABLE' });
    expect(ipc.invoke.mock.calls.map(call => call[0])).toEqual(['request_connect']);
  });
  it('only an explicit policy choice clears quarantine; Proxy remains usable', async () => {
    const invalid = normalizeStoredSettings({ tunRoutingMode: 'corrupt' });
    await expect(remnawaveClient.connect(server, { tunnelMode: 'proxy', tunRoutingModeInvalid: true })).resolves.toBeDefined();
    saveSettings({ ...invalid, tunnelMode: 'tun', tunRoutingMode: 'all', tunRoutingModeInvalid: undefined });
    const restored = loadSettings();
    expect(restored.tunRoutingModeInvalid).toBeUndefined(); expect(restored.tunRoutingMode).toBe('all');
    await expect(remnawaveClient.connect(server, { tunnelMode: 'tun', tunRoutingMode: restored.tunRoutingMode })).resolves.toBeDefined();
  });
  it.each([null, '', 'ALL', 'garbage'])('rejects malformed direct IPC policy %j before any native mutation', async value => {
    await expect(requestNativeConnect(server, 'tun', [], 'ipv4', false, undefined, value as 'all')).rejects.toMatchObject({ code: 'TUN_POLICY_INVALID' });
    expect(ipc.invoke).not.toHaveBeenCalled();
  });
  it('forwards exclude distinctly, and does not enforce a TUN policy in Proxy', async () => {
    await remnawaveClient.connect(server, { tunnelMode: 'tun', tunRoutingMode: 'exclude' });
    expect(ipc.invoke).toHaveBeenLastCalledWith('request_connect', expect.objectContaining({ tunRoutingMode: 'exclude' }));
    await expect(remnawaveClient.connect(server, { tunnelMode: 'proxy' })).resolves.toBeDefined();
  });
});
