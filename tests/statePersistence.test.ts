import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NativeStateFake, type PatchRequest } from './helpers/nativeStateFake';
const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
let backend: NativeStateFake;
beforeEach(() => {
  vi.resetModules();invoke.mockReset();backend = new NativeStateFake();
  invoke.mockImplementation((command, args) => backend.invoke(command, args));
  const values = new Map<string, string>();
  vi.stubGlobal('window', { __TAURI_INTERNALS__: {}, localStorage: {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
    removeItem: (key: string) => { values.delete(key); }
  }, setTimeout: globalThis.setTimeout, clearTimeout: globalThis.clearTimeout });
});
afterEach(() => { vi.useRealTimers();vi.unstubAllGlobals(); });
const changes = () => invoke.mock.calls.filter(([command]) => command === 'commit_state_patch').flatMap(([, args]) => (args.request as PatchRequest).changes);

describe('native persistence failure and writer ordering', () => {
  it('persists history through the v2 writer without placing data in WebView storage', async () => {
    const storage = await import('../src/services/storage');
    await storage.saveSessionHistory([{id:'a'.repeat(32),startedAtMs:'0',durationSeconds:1,mode:'proxy',status:'completed'}]);
    await storage.flushPersistentWrites();
    expect(backend.snapshot.payload.public.sessionHistory).toMatchObject([{mode:'proxy',status:'completed'}]);
    expect(await storage.loadSessionHistory()).toMatchObject([{durationSeconds:1}]);
    expect(window.localStorage.getItem('sessionHistory')).toBeNull();
  });
  it('preserves unreadable history and blocks replacement with a fabricated empty log', async () => {
    backend.snapshot.payload.public.sessionHistory={accessKey:'synthetic-private'};
    const storage=await import('../src/services/storage');
    await expect(storage.loadSessionHistory()).rejects.toThrow('SESSION_HISTORY_INVALID');
    expect(changes()).toEqual([]);expect(backend.snapshot.payload.public.sessionHistory).toEqual({accessKey:'synthetic-private'});
  });
  it('does not turn unavailable authoritative settings into missing settings', async () => {
    invoke.mockRejectedValue({ code: 'STATE_READ_FAILED', category: 'storage', recoverable: true, message: 'Synthetic state read failure' });
    const storage = await import('../src/services/storage');
    await expect(storage.loadSettingsBackup()).rejects.toMatchObject({ code: 'STATE_READ_FAILED' });
  });
  it('distinguishes a genuinely absent first-launch state from an I/O failure', async () => {
    const storage = await import('../src/services/storage');
    await expect(storage.loadSettingsBackup()).resolves.toBeNull();
  });
  it('prefers valid native settings over a stale WebView mirror', async () => {
    backend.snapshot.payload.public.settings = { themeGlow: false };
    window.localStorage.setItem('vkarmani.settings', JSON.stringify({ themeGlow: true }));
    const storage = await import('../src/services/storage');
    expect((await storage.loadSettingsBackup())?.themeGlow).toBe(false);
    expect(backend.snapshot.payload.legacyWebView?.['vkarmani.settings']).toContain('true');
    expect(backend.snapshot.payload.public.settings).toEqual({ themeGlow: false });
  });
  it('never starts a second native state writer while an earlier write is pending', async () => {
    const storage = await import('../src/services/storage');await storage.loadFavoriteServerIdsBackup();invoke.mockClear();
    const releases: Array<() => void> = [];let active = 0;let peak = 0;
    invoke.mockImplementation((command, args) => new Promise(resolve => {
      active++;peak = Math.max(peak, active);
      releases.push(() => { active--;void backend.invoke(command, args).then(resolve); });
    }));
    storage.saveSettings({ ...storage.defaultSettings, themeGlow: false });
    storage.saveSettings({ ...storage.defaultSettings, themeGlow: true });
    await vi.waitFor(() => expect(invoke).toHaveBeenCalledTimes(1));
    expect(peak).toBe(1);
    for (let i = 0; i < 8; i++) { releases.splice(0).forEach(release => release());await new Promise(resolve => setTimeout(resolve, 0)); }
    await storage.flushPersistentWrites();expect(peak).toBe(1);
    expect(backend.snapshot.payload.public.settings).toMatchObject({ themeGlow: true });
  });
  it('does not silently replace an unreadable protected cache with public fallback', async () => {
    invoke.mockRejectedValue({ code: 'STATE_CORRUPT', category: 'storage', recoverable: false, message: 'Synthetic DPAPI failure' });
    const storage = await import('../src/services/storage');
    await expect(storage.loadLastKnownServersBackup()).rejects.toMatchObject({ code: 'STATE_CORRUPT' });
  });
  it('coalesces queued values without losing a different state key', async () => {
    const storage = await import('../src/services/storage');await storage.loadFavoriteServerIdsBackup();invoke.mockClear();
    let release!: () => void;
    invoke.mockImplementationOnce((command, args) => new Promise(resolve => { release = () => { void backend.invoke(command, args).then(resolve); }; }));
    storage.saveSelectedServerId('initial');await vi.waitFor(() => expect(invoke).toHaveBeenCalledTimes(1));
    for (let i = 0; i < 50; i++) storage.saveSelectedServerId('latest-' + i);
    storage.saveFavoriteServerIds(['keep']);expect(invoke).toHaveBeenCalledTimes(1);release();
    await storage.flushPersistentWrites();
    expect(changes().map(change => [change.key, change.value])).toEqual([['selectedServerId', 'initial'], ['selectedServerId', 'latest-49'], ['favoriteServerIds', ['keep']]]);
  });
  it('keeps the native writer lease after a renderer deadline expires', async () => {
    const storage = await import('../src/services/storage');await storage.loadFavoriteServerIdsBackup();invoke.mockClear();
    let release!: () => void;
    invoke.mockImplementationOnce((command, args) => new Promise(resolve => { release = () => { void backend.invoke(command, args).then(resolve); }; }));
    vi.useFakeTimers();window.setTimeout = globalThis.setTimeout as typeof window.setTimeout;window.clearTimeout = globalThis.clearTimeout as typeof window.clearTimeout;
    storage.saveSelectedServerId('first');await vi.waitFor(() => expect(invoke).toHaveBeenCalledTimes(1));
    storage.saveFavoriteServerIds(['second']);await vi.advanceTimersByTimeAsync(7100);expect(invoke).toHaveBeenCalledTimes(1);
    for (let i = 0; i < 500; i++) storage.saveFavoriteServerIds(['latest-' + i]);
    expect(vi.getTimerCount()).toBe(0);release();await storage.flushPersistentWrites();
    expect(invoke).toHaveBeenCalledTimes(2);expect(backend.snapshot.payload.public.favoriteServerIds).toEqual(['latest-499']);
  });
  it('reports failed writes to flush and permits an explicit successful retry', async () => {
    const storage = await import('../src/services/storage');await storage.loadFavoriteServerIdsBackup();
    invoke.mockRejectedValue({ code: 'STATE_WRITE_FAILED', category: 'storage', message: 'synthetic failure' });
    storage.saveSelectedServerId('keep');await expect(storage.flushPersistentWrites()).rejects.toMatchObject({ code: 'STATE_WRITE_FAILED' });
    invoke.mockImplementation((command, args) => backend.invoke(command, args));
    storage.saveSelectedServerId('retry');await expect(storage.flushPersistentWrites()).resolves.toBeUndefined();
  });
  it('does not announce logout success when the protected credential cannot be cleared', async () => {
    invoke.mockRejectedValue({ code: 'STATE_WRITE_FAILED' });const storage = await import('../src/services/storage');
    await expect(storage.clearStoredAccessKey()).rejects.toMatchObject({ code: 'STATE_CLEAR_FAILED' });
  });
  it('does not substitute a stale plaintext key for an unreadable native key', async () => {
    invoke.mockRejectedValue({ code: 'STATE_READ_FAILED', category: 'storage' });
    window.localStorage.setItem('vkarmani.access-key', 'synthetic-legacy-key');const storage = await import('../src/services/storage');
    await expect(storage.loadStoredAccessKeySecure()).rejects.toMatchObject({ code: 'STATE_READ_FAILED' });
    expect(window.localStorage.getItem('vkarmani.access-key')).toBe('synthetic-legacy-key');expect(invoke).toHaveBeenCalledTimes(1);
  });
  it('removes an old credential mirror only after a confirmed protected migration', async () => {
    window.localStorage.setItem('vkarmani.access-key', 'synthetic-legacy-key');
    invoke.mockImplementation((command, args) => {
      if (command === 'commit_state_patch' && (args.request as PatchRequest).changes.some(change => change.scope === 'credential')) return Promise.reject({ code: 'STATE_WRITE_FAILED' });
      return backend.invoke(command, args);
    });
    const storage = await import('../src/services/storage');
    await expect(storage.loadStoredAccessKeySecure()).rejects.toMatchObject({ code: 'STATE_MIGRATION_FAILED' });
    expect(window.localStorage.getItem('vkarmani.access-key')).toBe('synthetic-legacy-key');
    invoke.mockImplementation((command, args) => backend.invoke(command, args));
    await expect(storage.loadStoredAccessKeySecure()).resolves.toBe('synthetic-legacy-key');expect(window.localStorage.getItem('vkarmani.access-key')).toBeNull();
  });
  const legacyProfiles = [{ id: 'synthetic', country: 'Test', city: 'Test', flag: 'BY', load: 0, rawUri: 'synthetic-private-profile', runtimeTemplate: { family: 'xray', outbound: { protocol: 'freedom' } } }];
  it('does not migrate or erase a profile from a render-time mirror read', async () => {
    window.localStorage.setItem('vkarmani.servers.last-known-xray-json', JSON.stringify(legacyProfiles));const storage = await import('../src/services/storage');
    expect(storage.loadLastKnownServers()[0].rawUri).toBeUndefined();expect(invoke).not.toHaveBeenCalled();
    expect(window.localStorage.getItem('vkarmani.servers.last-known-xray-json')).toBe(JSON.stringify(legacyProfiles));
  });
  it('retains the original public profile when protected migration fails', async () => {
    backend.snapshot.payload.public.lastKnownServers = legacyProfiles;
    invoke.mockImplementation((command, args) => {
      if (command === 'commit_state_patch' && (args.request as PatchRequest).changes.some(change => change.scope === 'protected')) return Promise.reject({ code: 'STATE_WRITE_FAILED' });
      return backend.invoke(command, args);
    });
    const storage = await import('../src/services/storage');await expect(storage.loadLastKnownServersBackup()).rejects.toMatchObject({ code: 'STATE_MIGRATION_FAILED' });
    expect(changes().some(change => change.scope === 'public')).toBe(false);expect(backend.snapshot.payload.public.lastKnownServers).toEqual(legacyProfiles);
  });
  it('retires public secrets only after a successful protected profile commit', async () => {
    backend.snapshot.payload.public.lastKnownServers = legacyProfiles;const storage = await import('../src/services/storage');
    await expect(storage.loadLastKnownServersBackup()).resolves.toMatchObject([{ rawUri: 'synthetic-private-profile' }]);
    expect(changes().map(change => change.scope)).toEqual(['protected', 'public']);
    expect(JSON.stringify(backend.snapshot.payload.public.lastKnownServers)).not.toContain('synthetic-private-profile');
    expect(window.localStorage.getItem('vkarmani.servers.last-known-xray-json')).not.toContain('synthetic-private-profile');
  });
  it('cancels stale restoration after logout instead of resurrecting a profile', async () => {
    const storage = await import('../src/services/storage');await storage.loadFavoriteServerIdsBackup();invoke.mockClear();
    const loading = storage.loadLastKnownServersBackup();const rejected = expect(loading).rejects.toMatchObject({ code: 'STATE_OPERATION_CANCELLED' });
    await storage.clearLastKnownServers();await rejected;
    expect(changes().every(change => change.value === null)).toBe(true);
  });
});
