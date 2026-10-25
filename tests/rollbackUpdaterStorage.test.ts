import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { NativeStateFake } from './helpers/nativeStateFake';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
const mocks = vi.hoisted(() => ({ invoke: vi.fn(), check: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: mocks.invoke }));
vi.mock('@tauri-apps/plugin-updater', () => ({ check: mocks.check }));
vi.mock('../src/services/runtime', () => ({ isTauriRuntime: true, appVersion: '0.13.76' }));
let backend: NativeStateFake;
beforeEach(() => {
  vi.resetModules(); mocks.invoke.mockReset(); mocks.check.mockReset(); backend = new NativeStateFake();
  mocks.invoke.mockImplementation((command, args) => backend.invoke(command, args));
  vi.stubGlobal('window', { __TAURI_INTERNALS__: {}, localStorage: {getItem: () => null, setItem: vi.fn(), removeItem: vi.fn()}, setTimeout, clearTimeout });
  vi.stubGlobal('document', { body: { inert: false } });
});
afterEach(() => vi.unstubAllGlobals());

it('checks installation policy only after verified download and durable flush, closes SDK resources on refusal', async () => {
  const calls: string[] = [];
  const install = vi.fn();
  const close = vi.fn().mockResolvedValue(undefined);
  mocks.check.mockResolvedValue({ download: vi.fn(async () => { calls.push('download'); }), install, close });
  const storage = await import('../src/services/storage'); await storage.loadPersistentSnapshot();
  storage.saveSelectedServerId('saved-before-install');
  const updater = await import('../src/services/updater');
  const beforeInstall = async () => {
    calls.push('policy');
    expect(backend.snapshot.payload.public.selectedServerId).toBe('saved-before-install');
    expect(document.body.inert).toBe(true);
    throw new Error('active connection; user disconnect required');
  };
  const result = await updater.installAvailableUpdate(vi.fn(), beforeInstall);
  expect(result).toMatchObject({ ok: false });
  expect(calls).toEqual(['download', 'policy']);
  expect(install).not.toHaveBeenCalled();
  expect(close).toHaveBeenCalledOnce();
  expect(document.body.inert).toBe(false);
  storage.saveSelectedServerId('editable-again'); await storage.flushPersistentWrites();
  expect(backend.snapshot.payload.public.selectedServerId).toBe('editable-again');
});

it.each([
  { label: 'idle', active: false, runtime: { bridge: 'tauri', tunnelActive: false }, installAllowed: true },
  { label: 'active', active: true, runtime: { bridge: 'tauri', tunnelActive: true }, installAllowed: false },
  { label: 'unavailable', active: false, runtime: null, installAllowed: false },
  { label: 'unverified bridge', active: false, runtime: { bridge: 'web-preview', tunnelActive: false }, installAllowed: false },
  { label: 'native operation', active: false, runtime: { bridge: 'tauri', tunnelActive: false, operation: { kind: 'connect' } }, installAllowed: false },
  { label: 'live PID despite idle UI', active: false, runtime: { bridge: 'tauri', tunnelActive: false, xrayPid: 999 }, installAllowed: false }
])('actual App installer preserves connections and checks $label state', async ({ active, runtime, installAllowed }) => {
  const source = ts.createSourceFile('App.tsx', readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  let handler: ts.FunctionDeclaration | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'handleInstallUpdate') handler = node;
    ts.forEachChild(node, visit);
  }; visit(source);
  const disconnect = vi.fn();
  const install = vi.fn();
  const close = vi.fn().mockResolvedValue(undefined);
  mocks.check.mockResolvedValue({ download: vi.fn(async () => undefined), install, close });
  const storage = await import('../src/services/storage'); await storage.loadPersistentSnapshot();
  const updater = await import('../src/services/updater');
  const connectionLease = { current: false };
  const bindings = {
    persistentStateReady: true, updaterActionLock: { current: false }, connectionActionLock: connectionLease,
    updateInfoRef: { current: { status: 'available', available: true } }, setNativeTrayUpdateState: vi.fn(),
    isTauriRuntime: true, connectionStateRef: { current: active ? 'connected' : 'idle' },
    setUpdateInfo: vi.fn(), tr: (_: string, ru: string) => ru, language: 'ru',
    remnawaveClient: { disconnect }, proxyStatusRef: { current: { enabled: false } }, settingsRef: { current: storage.defaultSettings },
    shouldUseSystemProxy: () => false, setConnectionStateSafe: vi.fn(), setVpnExternalIp: vi.fn(), setSessionDuration: vi.fn(), setConnectivityProbe: vi.fn(),
    refreshDiagnosticsAndRuntime: vi.fn(async () => runtime),
    isConnectionActionBusy: () => false, managedReconnectRef: { current: null },
    normalizeNativeError: () => ({ message: 'synthetic error' }), pushToast: vi.fn(), installAvailableUpdate: updater.installAvailableUpdate
  };
  const js = ts.transpileModule(handler!.getText(source), { compilerOptions: { target: ts.ScriptTarget.ES2020 } }).outputText;
  const run = new Function('bindings', 'const {' + Object.keys(bindings).join(',') + '}=bindings;' + js + ';return handleInstallUpdate;')(bindings);
  await run(false);
  expect(disconnect).not.toHaveBeenCalled();
  expect(install).toHaveBeenCalledTimes(installAllowed ? 1 : 0);
  expect(connectionLease.current).toBe(installAllowed);
});

it('does not check installation policy or run installer after signature/download failure', async () => {
  const beforeInstall = vi.fn(); const install = vi.fn(); const close = vi.fn().mockResolvedValue(undefined);
  mocks.check.mockResolvedValue({ download: vi.fn().mockRejectedValue(new Error('signature verification failed')), install, close });
  const updater = await import('../src/services/updater');
  expect(await updater.installAvailableUpdate(vi.fn(), beforeInstall)).toMatchObject({ ok: false });
  expect(beforeInstall).not.toHaveBeenCalled(); expect(install).not.toHaveBeenCalled(); expect(close).toHaveBeenCalledOnce();
  expect(document.body.inert).toBe(false);
});

it('does not authorize installation after a failed durable write', async () => {
  const storage = await import('../src/services/storage'); await storage.loadPersistentSnapshot();
  mocks.invoke.mockRejectedValue({ code: 'STATE_WRITE_FAILED' }); storage.saveSelectedServerId('unconfirmed');
  const beforeInstall = vi.fn(); const install = vi.fn(); const close = vi.fn().mockResolvedValue(undefined);
  mocks.check.mockResolvedValue({ download: vi.fn().mockResolvedValue(undefined), install, close });
  const updater = await import('../src/services/updater');
  expect(await updater.installAvailableUpdate(vi.fn(), beforeInstall)).toMatchObject({ ok: false });
  expect(beforeInstall).not.toHaveBeenCalled(); expect(install).not.toHaveBeenCalled(); expect(close).toHaveBeenCalledOnce();
  expect(document.body.inert).toBe(false);
});

it('closes metadata-only SDK resources without changing the returned update offer', async () => {
  const close = vi.fn().mockResolvedValue(undefined);
  mocks.check.mockResolvedValue({ currentVersion: '0.13.83', version: '0.13.84-rc.1', close });
  const updater = await import('../src/services/updater');
  expect(await updater.checkForUpdates('stable')).toMatchObject({ available: true, version: '0.13.84-rc.1' });
  expect(close).toHaveBeenCalledOnce();
});
it('keeps settings durable during a slow update download that fails', async () => {
  let rejectDownload!: (error: Error) => void;
  const install = vi.fn();
  mocks.check.mockResolvedValue({ download: vi.fn(() => new Promise((_, reject) => { rejectDownload = reject; })), install, close: vi.fn().mockResolvedValue(undefined) });
  const storage = await import('../src/services/storage'); await storage.loadPersistentSnapshot();
  const updater = await import('../src/services/updater'); const result = updater.installAvailableUpdate(vi.fn());
  await vi.waitFor(() => expect(rejectDownload).toBeTypeOf('function'));
  expect(document.body.inert).toBe(false);
  storage.saveSettings({...storage.defaultSettings, language:'en'}); await storage.flushPersistentWrites();
  expect(backend.snapshot.payload.public.settings).toMatchObject({language:'en'});
  rejectDownload(new Error('synthetic download failure'));
  expect(await result).toMatchObject({ok:false}); expect(install).not.toHaveBeenCalled();
  expect(document.body.inert).toBe(false);
  storage.saveSelectedServerId('after-failure'); await storage.flushPersistentWrites();
  expect(backend.snapshot.payload.public.selectedServerId).toBe('after-failure');
});
it('drains saved edits and blocks input only for final install, restores input on installer failure', async () => {
  let release!: () => void;
  const storage = await import('../src/services/storage'); await storage.loadPersistentSnapshot();
  const install = vi.fn(async () => {
    expect(document.body.inert).toBe(true);
    expect(backend.snapshot.payload.public.settings).toMatchObject({language:'en'});
    throw new Error('synthetic install failure');
  });
  mocks.check.mockResolvedValue({ download: vi.fn(() => new Promise<void>(resolve => { release = resolve; })), install, close: vi.fn().mockResolvedValue(undefined) });
  const updater = await import('../src/services/updater'); const result = updater.installAvailableUpdate(vi.fn());
  await vi.waitFor(() => expect(release).toBeTypeOf('function'));
  storage.saveSettings({...storage.defaultSettings,language:'en'}); release();
  expect(await result).toMatchObject({ok:false}); expect(install).toHaveBeenCalledTimes(1);
  expect(document.body.inert).toBe(false);
  storage.saveSelectedServerId('resumed'); await storage.flushPersistentWrites();
  expect(backend.snapshot.payload.public.selectedServerId).toBe('resumed');
});
