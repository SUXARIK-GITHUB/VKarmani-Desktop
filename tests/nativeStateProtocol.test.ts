import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NativeStateFake } from './helpers/nativeStateFake';
const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
let backend: NativeStateFake;
beforeEach(() => {
  vi.resetModules(); invoke.mockReset(); backend = new NativeStateFake();
  invoke.mockImplementation((command, args) => backend.invoke(command, args));
  vi.stubGlobal('window', { __TAURI_INTERNALS__: {}, localStorage: { getItem: () => null, setItem: vi.fn(), removeItem: vi.fn() }, setTimeout, clearTimeout });
});
afterEach(() => vi.unstubAllGlobals());

describe('coherent v2 native protocol', () => {
  it('does not recover a different backup than the user confirmed', async () => {
    backend.snapshot.readOnly = true; backend.snapshot.recoveryToken = 'b'.repeat(64);
    invoke.mockImplementation(async (command, args) => {
      if (command === 'recover_state_snapshot') {
        backend.snapshot.readOnly = false; backend.snapshot.recoveryToken = null; backend.snapshot.generation = 'c'.repeat(48);
        return structuredClone(backend.snapshot);
      }
      return backend.invoke(command, args);
    });
    const native = await import('../src/services/nativeState');
    await expect(native.recoverNativeState('a'.repeat(64))).rejects.toMatchObject({ code: 'STATE_RECOVERY_CHANGED' });
    expect(invoke.mock.calls.some(([name]) => name === 'recover_state_snapshot')).toBe(false);
  });
  it('does not mutate a backup when the user only requested a reload', async () => {
    backend.snapshot.readOnly = true; backend.snapshot.recoveryToken = 'b'.repeat(64);
    invoke.mockImplementation(async (command, args) => {
      if (command === 'recover_state_snapshot') {
        backend.snapshot.readOnly = false; backend.snapshot.recoveryToken = null; backend.snapshot.generation = 'c'.repeat(48);
        return structuredClone(backend.snapshot);
      }
      return backend.invoke(command, args);
    });
    const storage = await import('../src/services/storage');
    await expect(storage.reloadPersistentSnapshot()).rejects.toMatchObject({ code: 'STATE_RECOVERY_REQUIRED' });
    expect(invoke.mock.calls.some(([name]) => name === 'recover_state_snapshot')).toBe(false);
  });
  it.each(['same-generation', 'read-only', 'nonzero-revision'])('rejects invalid recovery ACK %s and retains the recovery snapshot', async variant => {
    backend.snapshot.readOnly = true; backend.snapshot.recoveryToken = 'b'.repeat(64);
    const native = await import('../src/services/nativeState');
    await native.inspectNativeState();
    const candidate = structuredClone(backend.snapshot);
    candidate.readOnly = false; candidate.recoveryToken = null; candidate.generation = 'c'.repeat(48);
    if (variant === 'same-generation') candidate.generation = backend.snapshot.generation;
    if (variant === 'read-only') { candidate.readOnly = true; candidate.recoveryToken = 'd'.repeat(64); }
    if (variant === 'nonzero-revision') candidate.revision = '1';
    invoke.mockImplementation(async (command, args) => command === 'recover_state_snapshot' ? candidate : backend.invoke(command, args));
    await expect(native.recoverNativeState('b'.repeat(64))).rejects.toMatchObject({ code: 'STATE_PROTOCOL_INVALID' });
    expect(native.peekNativeState()).toMatchObject({ readOnly: true, recoveryToken: 'b'.repeat(64) });
  });
  it('hydrates all fields from one revision without stale mirror defaults', async () => {
    backend.snapshot.payload.public = { settings: { themeGlow: false }, favoriteServerIds: ['a'], selectedServerId: 'b' };
    const storage = await import('../src/services/storage');
    const view = await storage.loadPersistentSnapshot();
    expect(view).toMatchObject({ settings: { themeGlow: false }, favorites: ['a'], selected: 'b', entries: [] });
    expect(invoke.mock.calls.map(call => call[0])).toEqual(['load_state_snapshot']);
  });
  it.each([42, '01', '-1', '18446744073709551616', '9'.repeat(1000)])('rejects invalid or lossy wire revision %s', async revision => {
    backend.snapshot.revision = revision as string;
    const native = await import('../src/services/nativeState');
    await expect(native.readNativeState()).rejects.toMatchObject({ code: 'STATE_PROTOCOL_INVALID' });
    expect(invoke).toHaveBeenCalledTimes(1);
  });
  it('retains full u64 precision across a committed acknowledgement', async () => {
    backend.snapshot.revision = '9007199254740993';
    const native = await import('../src/services/nativeState');
    await native.commitNativeChange('public', 'selectedServerId', 'new');
    expect(native.peekNativeState()?.revision).toBe('9007199254740994');
    expect(invoke.mock.calls[1][1].request.expectedRevision).toBe('9007199254740993');
  });
  it('does not rebase queued changes after an external writer wins CAS', async () => {
    const native = await import('../src/services/nativeState'); await native.readNativeState();
    backend.snapshot.revision = '1';
    await expect(native.commitNativeChange('public', 'selectedServerId', 'stale')).rejects.toMatchObject({ code: 'STATE_CONFLICT' });
    await expect(native.commitNativeChange('public', 'selectedServerId', 'also-stale')).rejects.toMatchObject({ code: 'STATE_CONFLICT' });
    expect(invoke.mock.calls.filter(call => call[0] === 'commit_state_patch')).toHaveLength(1);
    expect(backend.snapshot.payload.public.selectedServerId).toBeUndefined();
    await native.inspectNativeState(true);
    await native.commitNativeChange('public', 'selectedServerId', 'confirmed-after-reload');
    expect(backend.snapshot.revision).toBe('2');
  });
  it('keeps the cached revision until a late native commit ACK arrives', async () => {
    const native = await import('../src/services/nativeState'); await native.readNativeState();
    let release!: () => void;
    invoke.mockImplementationOnce((command, args) => new Promise(resolve => { release = () => { void backend.invoke(command, args).then(resolve); }; }));
    const write = native.commitNativeChange('public', 'selectedServerId', 'late');
    await vi.waitFor(() => expect(release).toBeTypeOf('function'));
    expect(native.peekNativeState()?.revision).toBe('0'); release(); await write;
    expect(native.peekNativeState()?.revision).toBe('1');
  });
  it('rejects a successful-looking response from another generation or impossible revision', async () => {
    const native = await import('../src/services/nativeState'); await native.readNativeState();
    const next = structuredClone(backend.snapshot); next.revision = '20';
    invoke.mockResolvedValueOnce({ snapshot: next, deduplicated: false });
    await expect(native.commitNativeChange('public', 'selectedServerId', 'x')).rejects.toMatchObject({ code: 'STATE_PROTOCOL_INVALID' });
    expect(native.peekNativeState()?.revision).toBe('0');
  });
  it('requires explicit hash-token recovery before any write to LKG state', async () => {
    backend.snapshot.readOnly = true; backend.snapshot.recoveryToken = 'b'.repeat(64);
    const native = await import('../src/services/nativeState');
    await expect(native.commitNativeChange('public', 'selectedServerId', 'x')).rejects.toMatchObject({ code: 'STATE_RECOVERY_REQUIRED' });
    expect(invoke).toHaveBeenCalledTimes(1);
    invoke.mockImplementation(async (command, args) => {
      if (command === 'recover_state_snapshot') {
        expect(args).toEqual({ token: 'b'.repeat(64) });
        backend.snapshot.readOnly = false; backend.snapshot.recoveryToken = null; backend.snapshot.generation = 'c'.repeat(48);
        return structuredClone(backend.snapshot);
      }
      return backend.invoke(command, args);
    });
    await native.recoverNativeState('b'.repeat(64)); await native.commitNativeChange('public', 'selectedServerId', 'recovered');
    expect(backend.snapshot.payload.public.selectedServerId).toBe('recovered');
  });
  it('cancels an obsolete profile write after credential session generation changes', async () => {
    const native = await import('../src/services/nativeState'); await native.readNativeState();
    await native.commitNativeChange('credential', 'accessKey', 'new-user');
    await expect(native.commitNativeChange('protected', 'lastKnownServers', [], '0')).rejects.toMatchObject({ code: 'STATE_SESSION_CHANGED' });
    expect(invoke.mock.calls.filter(call => call[0] === 'commit_state_patch')).toHaveLength(1);
  });
  it('freezes new writes until an explicit resume after flush failure', async () => {
    const storage = await import('../src/services/storage'); await storage.loadPersistentSnapshot();
    invoke.mockRejectedValue({ code: 'STATE_WRITE_FAILED' });
    storage.saveSelectedServerId('unconfirmed');
    await expect(storage.quiescePersistentWrites()).rejects.toMatchObject({ code: 'STATE_WRITE_FAILED' });
    invoke.mockImplementation((command, args) => backend.invoke(command, args)); invoke.mockClear();
    storage.saveSelectedServerId('must-not-write'); await Promise.resolve();
    expect(invoke).not.toHaveBeenCalled();
    storage.resumePersistentWrites(); storage.saveSelectedServerId('retry'); await storage.flushPersistentWrites();
    expect(backend.snapshot.payload.public.selectedServerId).toBe('retry');
  });
});
