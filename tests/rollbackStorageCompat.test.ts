import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NativeStateFake } from './helpers/nativeStateFake';
const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
let backend: NativeStateFake;
let mirror: Map<string, string>;
beforeEach(() => {
  vi.resetModules(); invoke.mockReset(); backend = new NativeStateFake(); mirror = new Map();
  invoke.mockImplementation((command, args) => backend.invoke(command, args));
  vi.stubGlobal('window', { __TAURI_INTERNALS__: {}, localStorage: {
    getItem: (key: string) => mirror.get(key) ?? null,
    setItem: (key: string, value: string) => mirror.set(key, value),
    removeItem: (key: string) => mirror.delete(key),
  }, setTimeout, clearTimeout });
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });
describe('076 UI with authoritative encrypted v2 storage', () => {
  it.each([null, '', 'future', 42, {}, [], ['all']])('blocks invalid present TUN policy %j without broadening it or overwriting originals', async tunRoutingMode => {
    backend.snapshot.payload.public.settings = { tunnelMode: 'tun', autoConnect: true, tunRoutingMode, futureOption: { keep: true } };
    const original = structuredClone(backend.snapshot);
    const storage = await import('../src/services/storage');
    await expect(storage.loadSettingsBackup()).rejects.toMatchObject({ code: 'STATE_SETTINGS_INVALID', category: 'storage' });
    storage.saveSettings(storage.defaultSettings);
    storage.saveSplitTunnelEntries([]);
    await expect(storage.flushPersistentWrites()).rejects.toMatchObject({ code: 'STATE_RESTORE_BLOCKED' });
    expect(backend.snapshot).toEqual(original);
    expect(invoke.mock.calls.map(([command]) => command)).toEqual(['load_state_snapshot']);
  });
  it('blocks a persisted invalid-policy quarantine marker even alongside a valid mode', async () => {
    backend.snapshot.payload.public.settings = { tunRoutingMode: 'selected', tunRoutingModeInvalid: true, autoConnect: true };
    const storage = await import('../src/services/storage');
    await expect(storage.loadPersistentSnapshot()).rejects.toMatchObject({ code: 'STATE_SETTINGS_INVALID' });
    await expect(storage.flushPersistentWrites()).rejects.toMatchObject({ code: 'STATE_RESTORE_BLOCKED' });
  });
  it.each(['all', 'selected', 'exclude'])('preserves explicit %s policy with no rules', async tunRoutingMode => {
    backend.snapshot.payload.public.settings = { tunnelMode: 'tun', autoConnect: true, tunRoutingMode };
    const storage = await import('../src/services/storage');
    expect((await storage.loadSettingsBackup())?.tunRoutingMode).toBe(tunRoutingMode);
    expect((await storage.loadPersistentSnapshot()).settings).toMatchObject({ tunRoutingMode, autoConnect: true });
  });
  it.each([false, true])('retains absent-mode legacy migration with rules=%s', async hasRules => {
    backend.snapshot.payload.public.settings = { language: 'en' };
    backend.snapshot.payload.public.splitTunnelEntries = hasRules ? [{ id: 'legacy', kind: 'app', value: 'app.exe', policy: 'VPN', enabled: true }] : [];
    const storage = await import('../src/services/storage');
    expect((await storage.loadPersistentSnapshot()).settings).toMatchObject({ tunRoutingMode: hasRules ? 'selected' : 'all', autoConnect: false, language: 'en' });
  });
  it('keeps newer per-rule metadata when the076 editor hydrates and saves supported fields', async () => {
    backend.snapshot.payload.public.splitTunnelEntries = [{id:'rule-a',kind:'app',value:'app.exe',enabled:true,policy:'VPN',schemaVersion:2,futureMetadata:{keep:true}}];
    const storage = await import('../src/services/storage');
    const entries = await storage.loadSplitTunnelEntriesBackup();
    expect(entries).toHaveLength(1);
    storage.saveSplitTunnelEntries(entries!.map(entry=>({...entry,enabled:false})));
    await storage.flushPersistentWrites();
    expect(backend.snapshot.payload.public.splitTunnelEntries).toMatchObject([{id:'rule-a',enabled:false,futureMetadata:{keep:true}}]);
  });
  it('rejects caller timeout and keeps autosave blocked after the underlying read succeeds late', async () => {
    vi.useFakeTimers();
    Object.assign(window, { setTimeout, clearTimeout });
    let release!: () => void;
    backend.snapshot.payload.public.settings = { language: 'en', themeGlow: false };
    invoke.mockImplementationOnce(() => new Promise(resolve => { release = () => resolve(structuredClone(backend.snapshot)); }));
    const storage = await import('../src/services/storage');
    const read = expect(storage.loadSettingsBackup()).rejects.toThrow('не ответила');
    await vi.advanceTimersByTimeAsync(7001); await read;
    storage.saveSettings(storage.defaultSettings); storage.saveSelectedServerId('default');
    release(); await vi.advanceTimersByTimeAsync(1);
    await expect(storage.flushPersistentWrites()).rejects.toMatchObject({ code: 'STATE_RESTORE_BLOCKED' });
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(backend.snapshot.payload.public.settings).toEqual({ language: 'en', themeGlow: false });
  });
  it('does not seed native startup from stale local settings, rules or selection', async () => {
    mirror.set('vkarmani.settings', JSON.stringify({ autoConnect: true, language: 'en' }));
    mirror.set('vkarmani.servers.selected', 'stale');
    mirror.set('vkarmani.servers.favorites', '["stale"]');
    backend.snapshot.payload.public = { settings: { language: 'ru', themeGlow: false }, selectedServerId: '', favoriteServerIds: [] };
    const storage = await import('../src/services/storage');
    expect(storage.loadSettings().autoConnect).toBe(false);
    expect(storage.loadSelectedServerId()).toBe(''); expect(storage.loadFavoriteServerIds()).toEqual([]);
    expect((await storage.loadSettingsBackup())?.themeGlow).toBe(false);
    expect(await storage.loadSelectedServerIdBackup()).toBe('');
    expect(await storage.loadFavoriteServerIdsBackup()).toEqual([]);
    expect(backend.snapshot.payload.legacyWebView?.['vkarmani.servers.selected']).toBe('stale');
  });
  it('preserves credential logout tombstone and never resurrects a stale local key', async () => {
    mirror.set('vkarmani.access-key', 'synthetic-stale-private-key');
    const storage = await import('../src/services/storage');
    expect(await storage.loadStoredAccessKeySecure()).toBe('');
    expect(backend.snapshot.payload.accessKey).toBeNull();
    expect(invoke.mock.calls.filter(([name, args]) => name === 'commit_state_patch' && args.request.changes.some((c: {scope: string}) => c.scope === 'credential'))).toEqual([]);
    expect(mirror.has('vkarmani.access-key')).toBe(false);
    expect(backend.snapshot.payload.legacyWebView?.['vkarmani.access-key']).toBe('synthetic-stale-private-key');
  });
  it.each(['STATE_READ_FAILED','STATE_CORRUPT','STATE_UNSUPPORTED_SCHEMA'])('blocks default autosave after %s even if a later read could succeed', async code => {
    invoke.mockRejectedValueOnce({ code });
    const storage = await import('../src/services/storage');
    await expect(storage.loadSettingsBackup()).rejects.toMatchObject({ code });
    storage.saveSettings(storage.defaultSettings); storage.saveSelectedServerId('stale-default');
    await expect(storage.flushPersistentWrites()).rejects.toMatchObject({ code: 'STATE_RESTORE_BLOCKED' });
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(backend.snapshot.payload.public).toEqual({});
  });
  it('blocks read-only recovery snapshot without writing defaults or importing plaintext credentials', async () => {
    backend.snapshot.readOnly = true; backend.snapshot.recoveryToken = 'b'.repeat(64);
    mirror.set('vkarmani.access-key','synthetic-stale');
    const storage = await import('../src/services/storage');
    await expect(storage.loadStoredAccessKeySecure()).rejects.toMatchObject({ code: 'STATE_RECOVERY_REQUIRED' });
    storage.saveFavoriteServerIds([]);
    await expect(storage.flushPersistentWrites()).rejects.toMatchObject({ code: 'STATE_RESTORE_BLOCKED' });
    expect(invoke).toHaveBeenCalledTimes(1); expect(mirror.get('vkarmani.access-key')).toBe('synthetic-stale');
  });
  it('does not restore stale local profiles when authoritative v2 cache is absent', async () => {
    mirror.set('vkarmani.servers.last-known-xray-json', JSON.stringify([{id:'stale',rawUri:'synthetic-private'}]));
    const storage = await import('../src/services/storage');
    expect(storage.loadLastKnownServers()).toEqual([]);
    expect(await storage.loadLastKnownServersBackup()).toBeNull();
    expect(backend.snapshot.payload.protected.lastKnownServers).toBeUndefined();
  });
});
