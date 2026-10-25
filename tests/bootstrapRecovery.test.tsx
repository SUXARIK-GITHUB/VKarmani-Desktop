import React from 'react';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
import { renderToStaticMarkup } from 'react-dom/server';
import { expect, it, vi } from 'vitest';
import { RootErrorBoundary } from '../src/components/RootErrorBoundary';
import { StorageRecoveryNotice } from '../src/components/StorageRecoveryNotice';
import { LogoutConfirmModal } from '../src/components/LogoutConfirmModal';
import { NativeStorageError, storageFailure } from '../src/services/nativeState';
import { connectionFailureState } from '../src/utils/runtimeSnapshot';

const appSource = ts.createSourceFile('App.tsx', readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
function appFunction(name: string, bindings: Record<string, unknown>) {
  let found: ts.FunctionDeclaration | undefined;
  const visit = (node: ts.Node) => { if (ts.isFunctionDeclaration(node) && node.name?.text === name) found = node; ts.forEachChild(node, visit); };
  visit(appSource); expect(found).toBeDefined();
  const js = ts.transpileModule(found!.getText(appSource), { compilerOptions: { target: ts.ScriptTarget.ES2020 } }).outputText;
  if (name !== 'invalidateProfileWork' && js.includes('invalidateProfileWork(')) {
    bindings = { ...bindings, invalidateProfileWork: appFunction('invalidateProfileWork', bindings) };
  }
  return new Function('bindings', 'const {' + Object.keys(bindings).join(',') + '}=bindings;' + js + ';return ' + name + ';')(bindings);
}

function profileWorkBindings() {
  return { profileSyncGenerationRef: { current: 7 }, profileSyncInFlightRef: { current: true },
    remnawaveClient: { invalidateProfileSync: vi.fn() }, setAuthLoading: vi.fn(), setIsSyncingProfile: vi.fn() };
}

it('contains render/import failures without displaying exception credentials, retry requests safe start', () => {
  const children = vi.fn((safe: boolean) => <div>{safe ? 'safe' : 'normal'}</div>);
  const boundary = new RootErrorBoundary({ children });
  const incident = RootErrorBoundary.getDerivedStateFromError(new Error('synthetic-secret https://sub.vkarmani.com/private'));
  boundary.state = { ...boundary.state, ...incident };
  const html = renderToStaticMarkup(boundary.render());
  expect(html).toContain('UI_RENDER_FAILED'); expect(html).not.toContain('synthetic-secret'); expect(html).not.toContain('sub.vkarmani.com');
  expect(children).not.toHaveBeenCalled();
  const main = readFileSync(new URL('../src/main.tsx', import.meta.url), 'utf8');
  expect(main).toContain("React.lazy(() => import('./App'))"); expect(main).not.toMatch(/import App from/);
  expect(main).toMatch(/function renderApp\(safeStart: boolean\)[\s\S]+const App = React.lazy/);
  expect(main.indexOf('policyControls.css')).toBeLessThan(main.indexOf("import './styles.css'"));
});

it.each(['ru', 'en'] as const)('storage notice is persistent, privacy-safe and separates confirmation in %s', language => {
  const props = { language, busy: false, safeStart: true, code: 'STATE_RECOVERY_REQUIRED', onInspect: vi.fn(), onConfirm: vi.fn(), onCancel: vi.fn() };
  const preview = renderToStaticMarkup(<StorageRecoveryNotice {...props} confirmBackup={false} />);
  const confirm = renderToStaticMarkup(<StorageRecoveryNotice {...props} confirmBackup />);
  expect(preview).toContain('role="alert"'); expect(preview).not.toContain(language === 'ru' ? 'Восстановить эту копию' : 'Restore this backup');
  expect(confirm).toContain(language === 'ru' ? 'Восстановить эту копию' : 'Restore this backup');
  expect(renderToStaticMarkup(<StorageRecoveryNotice {...props} code="synthetic-secret" confirmBackup={false} />)).not.toContain('synthetic-secret');
  expect(renderToStaticMarkup(<StorageRecoveryNotice {...props} code={undefined} safeStart={false} confirmBackup={false} />)).toBe('');
});

it('initial storage failure blocks authorization before remote validation without invalid-key UI', async () => {
  const failure = { code: 'STATE_READ_FAILED' }; const report = vi.fn(); const authorize = vi.fn(); const setErrorText = vi.fn();
  await appFunction('authorizeWithAccessKey', { isTauriRuntime: true, persistentStateReady: false, storageIssue: failure, reportPersistentFailure: report,
    NativeStorageError: Error, remnawaveClient: { authorizeByAccessKey: authorize }, setErrorText })('https://sub.vkarmani.com/synthetic');
  expect(report).toHaveBeenCalledWith(failure); expect(authorize).not.toHaveBeenCalled(); expect(setErrorText).not.toHaveBeenCalled();
});

it('backup preview never restores; explicit confirmation passes only the reviewed token; duplicates are ignored', async () => {
  const token = 'a'.repeat(64); const reload = vi.fn().mockResolvedValue({ selected: 'saved' }); const apply = vi.fn();
  const preview = vi.fn().mockResolvedValue({ readOnly: true, token }); const setToken = vi.fn(); const safe = vi.fn();
  const common = { ...profileWorkBindings(), storageRecoveryLock: { current: false }, recoveryEpochRef: { current: 0 }, recoveryModeRef: { current: false }, setStorageRecoveryBusy: vi.fn(), setRecoveryMode: safe,
    inspectPersistentRecovery: preview, reloadPersistentSnapshot: reload, applyRestoredPersistentState: apply,
    setStorageIssue: vi.fn(), setStorageRecoveryToken: setToken, reportPersistentFailure: vi.fn(), NativeStorageError: Error };
  await appFunction('handleStorageRecovery', { ...common, storageRecoveryToken: null })(false);
  expect(setToken).toHaveBeenCalledWith(token); expect(reload).not.toHaveBeenCalled(); expect(apply).not.toHaveBeenCalled();
  await appFunction('handleStorageRecovery', { ...common, storageRecoveryToken: token })(true);
  expect(reload).toHaveBeenCalledExactlyOnceWith(token); expect(apply).toHaveBeenCalledWith({ selected: 'saved' }); expect(safe).toHaveBeenCalledWith(true);
  common.storageRecoveryLock.current = true;
  await appFunction('handleStorageRecovery', { ...common, storageRecoveryToken: token })(true);
  expect(reload).toHaveBeenCalledTimes(1);
});

it('failed recovery retains the storage error, clears stale consent and releases the busy lock', async () => {
  const failure = new Error('STATE_RECOVERY_CHANGED'); const report = vi.fn(); const setToken = vi.fn();
  const lock = { current: false }; const busy = vi.fn(); const apply = vi.fn(); const clearIssue = vi.fn();
  await appFunction('handleStorageRecovery', { ...profileWorkBindings(), storageRecoveryLock: lock, recoveryEpochRef: { current: 0 }, recoveryModeRef: { current: false }, setStorageRecoveryBusy: busy,
    setRecoveryMode: vi.fn(), storageRecoveryToken: 'a'.repeat(64), inspectPersistentRecovery: vi.fn(),
    reloadPersistentSnapshot: vi.fn().mockRejectedValue(failure), applyRestoredPersistentState: apply,
    setStorageIssue: clearIssue, setStorageRecoveryToken: setToken, reportPersistentFailure: report, NativeStorageError: Error })(true);
  expect(report).toHaveBeenCalledWith(failure); expect(apply).not.toHaveBeenCalled(); expect(clearIssue).not.toHaveBeenCalled();
  expect(setToken).toHaveBeenCalledWith(null); expect(lock.current).toBe(false); expect(busy.mock.calls).toEqual([[true], [false]]);
});

it('requesting logout opens confirmation without changing generation, profile, ping, storage or runtime', async () => {
  const generation = { current: 7 }; const invalidate = vi.fn(); const cancelPing = vi.fn(); const run = vi.fn(); const open = vi.fn();
  await appFunction('handleClearAccessKey', { profileSyncGenerationRef: generation, remnawaveClient: { invalidateProfileSync: invalidate },
    cancelPing, runActionOnce: run, setLogoutConfirmationOpen: open })();
  expect(generation.current).toBe(7); expect(invalidate).not.toHaveBeenCalled(); expect(cancelPing).not.toHaveBeenCalled();
  expect(run).not.toHaveBeenCalled(); expect(open).toHaveBeenCalledExactlyOnceWith(true);
});

function logoutBindings() {
  const idle = { bridge: 'tauri', nativeInstanceId: 'owned', runtimeRevision: 1, tunnelActive: false, proxyOwnership: 'none', routeOwnership: 'none', systemProxyEnabled: true };
  const bindings: Record<string, any> = { ...profileWorkBindings(), recoveryEpochRef: { current: 4 }, isTauriRuntime: true, language: 'en', NativeStorageError, connectionFailureState,
    tr: (_: unknown, _ru: string, en: string) => en, runActionOnce: async (_: string, operation: () => Promise<void>) => operation(),
    flushPersistentWrites: vi.fn().mockResolvedValue(undefined), profileSyncGenerationRef: { current: 7 },
    remnawaveClient: { invalidateProfileSync: vi.fn(), clearSessionCache: vi.fn(), disconnect: vi.fn().mockResolvedValue(undefined) },
    isConnectionActionBusy: () => false, refreshDiagnosticsAndRuntime: vi.fn().mockResolvedValue(idle),
    clearStoredAccessKey: vi.fn().mockResolvedValue(undefined), clearLastKnownServers: vi.fn().mockResolvedValue(undefined),
    setNativeSessionAuthorized: vi.fn().mockResolvedValue(false), connectedServerIdRef: { current: 'old' },
    authorizedAccessKeyRef: { current: 'synthetic-key' }, serversRef: { current: ['old'] }, selectedServerIdRef: { current: 'old' } };
  for (const name of ['setLogoutConfirmationOpen','cancelPing','clearPendingConnectionQueue','setConnectionStateSafe','setConnectedServerId',
    'setConnectivityProbe','setVpnExternalIp','setSessionDuration','refreshPrimaryExternalIp','setAccessKey','setIsAuthorized','setSession',
    'setDevices','setSessionHistory','setDiagnostics','setServers','setSelectedServerId','pushToast','reportPersistentFailure']) bindings[name] = vi.fn();
  return { bindings, idle, run: () => appFunction('performConfirmedLogout', bindings)() };
}

it('confirmed logout refuses failed saves before disconnect, invalidation or key deletion', async () => {
  const { bindings: b, idle, run } = logoutBindings(); const failure = new NativeStorageError('STATE_CONFLICT', 'synthetic');
  b.flushPersistentWrites.mockRejectedValue(failure); b.refreshDiagnosticsAndRuntime.mockResolvedValue({ ...idle, tunnelActive: true });
  await run(); expect(b.profileSyncGenerationRef.current).toBe(7); expect(b.remnawaveClient.invalidateProfileSync).not.toHaveBeenCalled();
  expect(b.remnawaveClient.disconnect).not.toHaveBeenCalled(); expect(b.clearStoredAccessKey).not.toHaveBeenCalled();
  expect(b.reportPersistentFailure).toHaveBeenCalledWith(failure); expect(b.setConnectionStateSafe).toHaveBeenCalledExactlyOnceWith('connected');
  expect(b.recoveryEpochRef.current).toBe(4); expect(b.profileSyncInFlightRef.current).toBe(true);
  expect(b.remnawaveClient.clearSessionCache).not.toHaveBeenCalled();
});

it.each([null, { bridge: 'tauri', operation: { kind: 'connect' } }, { bridge: 'tauri', proxyOwnership: 'unavailable' }])('unknown or busy runtime prevents credential deletion: %j', async runtime => {
  const { bindings: b, run } = logoutBindings(); b.refreshDiagnosticsAndRuntime.mockResolvedValue(runtime);
  await run(); expect(b.clearStoredAccessKey).not.toHaveBeenCalled(); expect(b.remnawaveClient.disconnect).not.toHaveBeenCalled();
  expect(b.setIsAuthorized).not.toHaveBeenCalled(); expect(b.setConnectionStateSafe).not.toHaveBeenCalledWith('idle');
});

it.each(['failure', 'still-active', 'unknown'] as const)('unconfirmed disconnect retains credentials and does not invent idle: %s', async mode => {
  const { bindings: b, idle, run } = logoutBindings(); const active = { ...idle, tunnelActive: true, xrayPid: 123 };
  b.refreshDiagnosticsAndRuntime.mockResolvedValue(active);
  if (mode === 'failure') b.remnawaveClient.disconnect.mockRejectedValue(new Error('injected disconnect failure'));
  else if (mode === 'unknown') b.refreshDiagnosticsAndRuntime.mockResolvedValueOnce(active).mockResolvedValue(null);
  await run(); expect(b.remnawaveClient.disconnect).toHaveBeenCalledWith({ useSystemProxy: false });
  expect(b.clearStoredAccessKey).not.toHaveBeenCalled(); expect(b.setIsAuthorized).not.toHaveBeenCalled();
  expect(b.setConnectedServerId).not.toHaveBeenCalled(); expect(b.setConnectionStateSafe).not.toHaveBeenCalledWith('idle');
});

it('a foreign proxy with no VKarmani ownership does not cause proxy restoration or block sign out', async () => {
  const { bindings: b, run } = logoutBindings(); await run();
  expect(b.remnawaveClient.disconnect).not.toHaveBeenCalled(); expect(b.clearStoredAccessKey).toHaveBeenCalledTimes(1);
  expect(b.setIsAuthorized).toHaveBeenCalledWith(false);
  expect(b.flushPersistentWrites.mock.invocationCallOrder[0]).toBeLessThan(b.clearStoredAccessKey.mock.invocationCallOrder[0]);
  expect(b.recoveryEpochRef.current).toBe(5); expect(b.profileSyncInFlightRef.current).toBe(false);
  expect(b.setAuthLoading).toHaveBeenCalledWith(false); expect(b.setIsSyncingProfile).toHaveBeenCalledWith(false);
  expect(b.remnawaveClient.clearSessionCache).toHaveBeenCalledTimes(1);
  expect(b.remnawaveClient.clearSessionCache.mock.invocationCallOrder[0]).toBeGreaterThan(b.setNativeSessionAuthorized.mock.invocationCallOrder[0]);
});

it('failed persistent profile deletion retains the client cache and does not report a successful logout', async () => {
  const { bindings: b, run } = logoutBindings(); b.clearLastKnownServers.mockRejectedValue(new NativeStorageError('STATE_WRITE_FAILED', 'synthetic'));
  await run(); expect(b.remnawaveClient.clearSessionCache).not.toHaveBeenCalled();
  expect(b.setIsAuthorized).not.toHaveBeenCalledWith(false); expect(b.reportPersistentFailure).toHaveBeenCalled();
});

it('a superseded login error cannot overwrite newer loading, show an error or authorize a stale key', async () => {
  const releases: Array<(value: unknown) => void> = []; const rejections: Array<(error: Error) => void> = [];
  const epoch = { current: 0 }; const client = { authorizeByAccessKey: vi.fn(() => new Promise((resolve, reject) => { releases.push(resolve); rejections.push(reject); })),
    loadDevices: vi.fn().mockResolvedValue([]), loadServers: vi.fn().mockResolvedValue([]) };
  const b: Record<string, any> = { isTauriRuntime: true, persistentStateReady: true, recoveryEpochRef: epoch,
    recoveryModeRef: { current: false }, settingsRef: { current: {} }, remnawaveClient: client,
    authorizedAccessKeyRef: { current: '' }, overviewAutoRefreshAtRef: { current: 0 }, serversRef: { current: [] },
    selectedServerIdRef: { current: '' }, selectedServer: null, mergeServerMeasurements: (v: unknown) => v,
    saveStoredAccessKey: vi.fn().mockResolvedValue(true), setNativeSessionAuthorized: vi.fn().mockResolvedValue(true),
    pickPreferredServer: () => null, tr: (_: unknown, ru: string) => ru, language: 'ru', normalizeNativeError: (e: Error) => e };
  for (const name of ['writeNativeInterfaceLog','setAuthLoading','setErrorText','setAccessKey','setSession','setDevices','setIsAuthorized',
    'pushToast','setProfileSyncInfo','handleConnectionToggle']) b[name] = vi.fn();
  const authorize = appFunction('authorizeWithAccessKey', b);
  const old = authorize('https://sub.vkarmani.com/old-synthetic');
  const latest = authorize('https://sub.vkarmani.com/new-synthetic');
  rejections[0](new Error('OLD_PROFILE_FAILURE')); await old;
  expect(b.setAuthLoading.mock.calls).toEqual([[true],[true]]);
  expect(b.setErrorText.mock.calls).toEqual([[''],['']]); expect(b.pushToast).not.toHaveBeenCalled();
  releases[1]({ id: 'new' }); await latest;
  expect(b.saveStoredAccessKey).toHaveBeenCalledExactlyOnceWith('https://sub.vkarmani.com/new-synthetic');
  expect(b.setSession).toHaveBeenCalledExactlyOnceWith({ id: 'new' }); expect(b.setAuthLoading).toHaveBeenLastCalledWith(false);
});

it('profile invalidation releases stale busy flags, revokes client work and avoids UI writes on unmount', () => {
  const b = { ...profileWorkBindings(), recoveryEpochRef: { current: 2 } };
  const invalidate = appFunction('invalidateProfileWork', b); invalidate();
  expect(b.recoveryEpochRef.current).toBe(3); expect(b.profileSyncGenerationRef.current).toBe(8);
  expect(b.profileSyncInFlightRef.current).toBe(false); expect(b.remnawaveClient.invalidateProfileSync).toHaveBeenCalledTimes(1);
  expect(b.setAuthLoading).toHaveBeenCalledWith(false); expect(b.setIsSyncingProfile).toHaveBeenCalledWith(false);
  invalidate(false); expect(b.recoveryEpochRef.current).toBe(4);
  expect(b.setAuthLoading).toHaveBeenCalledTimes(1); expect(b.setIsSyncingProfile).toHaveBeenCalledTimes(1);
});

it('confirmed owned disconnect is read back before deleting the key, preserving an unrelated proxy', async () => {
  const { bindings: b, idle, run } = logoutBindings();
  b.refreshDiagnosticsAndRuntime.mockResolvedValueOnce({ ...idle, tunnelActive: true, xrayPid: 123, routeOwnership: 'confirmed', proxyOwnership: 'owned' });
  await run(); expect(b.remnawaveClient.disconnect).toHaveBeenCalledExactlyOnceWith({ useSystemProxy: true });
  expect(b.refreshDiagnosticsAndRuntime).toHaveBeenCalledTimes(2);
  expect(b.clearStoredAccessKey.mock.invocationCallOrder[0]).toBeGreaterThan(b.refreshDiagnosticsAndRuntime.mock.invocationCallOrder[1]);
  expect(b.setIsAuthorized).toHaveBeenCalledWith(false);
});

it('a duplicate or conflicting logout admission cannot invalidate the profile before acquiring the lease', async () => {
  const { bindings: b, run } = logoutBindings(); b.runActionOnce = vi.fn().mockResolvedValue(null); await run();
  expect(b.profileSyncGenerationRef.current).toBe(7); expect(b.remnawaveClient.invalidateProfileSync).not.toHaveBeenCalled();
  expect(b.flushPersistentWrites).not.toHaveBeenCalled(); expect(b.setLogoutConfirmationOpen).not.toHaveBeenCalled();
});

it.each(['ru', 'en'] as const)('logout consent names data scope and offers cancellation in %s', language => {
  const html = renderToStaticMarkup(<LogoutConfirmModal open language={language} busy={false} onCancel={vi.fn()} onConfirm={vi.fn()} />);
  expect(html).toContain('role="dialog"'); expect(html).toContain(language === 'ru' ? 'Отмена' : 'Cancel');
  expect(html).toContain(language === 'ru' ? 'Настройки и правила приложений останутся' : 'Settings and app rules will remain');
});

it.each([false, true])('late login uses current recovery admission while preserving healthy autoconnect: recovery=%s', async recovery => {
  let release!: (servers: unknown[]) => void;
  const server = { id: 'saved', runtimeTemplate: { family: 'xray', outbound: {} } };
  const loadServers = vi.fn(() => new Promise<unknown[]>(resolve => { release = resolve; }));
  const automatic = { current: false }; const connect = vi.fn(); const error = vi.fn();
  const bindings: Record<string, any> = { isTauriRuntime: true, persistentStateReady: true, recoveryEpochRef: { current: 0 }, recoveryMode: false, recoveryModeRef: automatic,
    settingsRef: { current: { autoConnect: true, allowDemoFallback: false, profileSyncOnLogin: false } },
    remnawaveClient: { authorizeByAccessKey: vi.fn().mockResolvedValue({}), loadDevices: vi.fn().mockResolvedValue([]), loadServers, getProfileSyncInfo: vi.fn() },
    authorizedAccessKeyRef: { current: '' }, overviewAutoRefreshAtRef: { current: 0 }, serversRef: { current: [] },
    selectedServerIdRef: { current: server.id }, selectedServer: server, mergeServerMeasurements: (values: unknown[]) => values,
    saveStoredAccessKey: vi.fn().mockResolvedValue(true), setNativeSessionAuthorized: vi.fn().mockResolvedValue(true),
    pickPreferredServer: () => server, handleConnectionToggle: connect, setErrorText: error,
    tr: (_: unknown, ru: string) => ru, language: 'ru', normalizeNativeError: (e: Error) => e };
  for (const name of ['writeNativeInterfaceLog','setAuthLoading','setAccessKey','setSession','setDevices','setIsAuthorized',
    'pushToast','setServers','saveLastKnownServers','setFavoriteServerIds','setProfileSyncInfo','setSelectedServerId']) bindings[name] = vi.fn();
  const pending = appFunction('authorizeWithAccessKey', bindings)('https://sub.vkarmani.com/synthetic');
  await vi.waitFor(() => expect(loadServers).toHaveBeenCalled());
  automatic.current = recovery; release([server]); await pending;
  expect(error.mock.calls).toEqual([['']]); expect(bindings.setProfileSyncInfo).toHaveBeenCalled();
  expect(connect).toHaveBeenCalledTimes(recovery ? 0 : 1);
});

it.each(['response', 'devices'] as const)('recovery invalidates a pending login before it can overwrite the restored key: %s', async phase => {
  let release!: (value: unknown) => void; const epoch = { current: 0 }; const save = vi.fn().mockResolvedValue(true); const setSession = vi.fn();
  const deferred = () => new Promise(resolve => { release = resolve; });
  const client = { authorizeByAccessKey: vi.fn(phase === 'response' ? deferred : async () => ({})),
    loadDevices: vi.fn(phase === 'devices' ? deferred : async () => []), loadServers: vi.fn().mockResolvedValue([]) };
  const error = vi.fn();
  const pending = appFunction('authorizeWithAccessKey', { isTauriRuntime: true, persistentStateReady: true, recoveryEpochRef: epoch,
    recoveryModeRef: { current: true }, settingsRef: { current: {} }, remnawaveClient: client,
    writeNativeInterfaceLog: vi.fn(), setAuthLoading: vi.fn(), setErrorText: error, setAccessKey: vi.fn(),
    authorizedAccessKeyRef: { current: '' }, setSession, setDevices: vi.fn(), saveStoredAccessKey: save,
    setIsAuthorized: vi.fn(), setNativeSessionAuthorized: vi.fn().mockResolvedValue(true),
    tr: (_: unknown, ru: string) => ru, language: 'ru', normalizeNativeError: (e: Error) => e, pushToast: vi.fn() })('https://sub.vkarmani.com/synthetic');
  if (phase === 'devices') await vi.waitFor(() => expect(client.loadDevices).toHaveBeenCalled());
  epoch.current++; release(phase === 'response' ? {} : []); await pending;
  expect(save).not.toHaveBeenCalled(); expect(setSession).not.toHaveBeenCalled(); expect(error.mock.calls).toEqual([['']]);
});

it.each([false, true])('late update check respects current recovery admission: recovery=%s', async recovery => {
  let release!: (result: unknown) => void; const automatic = { current: false }; const install = vi.fn();
  const result = { status: 'available', available: true, version: 'synthetic' };
  const check = vi.fn(() => new Promise(resolve => { release = resolve; }));
  const pending = appFunction('handleCheckUpdates', { updateInfoRef: { current: { status: 'idle' } }, setUpdateInfo: vi.fn(),
    setNativeTrayUpdateState: vi.fn(), checkForUpdates: check, settings: { releaseChannel: 'stable' },
    recoveryModeRef: automatic, isTauriRuntime: true, handleInstallUpdate: install, writeNativeInterfaceLog: vi.fn(),
    tr: (_: unknown, ru: string) => ru, language: 'ru' })(true, true);
  automatic.current = recovery; release(result); expect(await pending).toBe(result);
  expect(install).toHaveBeenCalledTimes(recovery ? 0 : 1);
});

it('the actual recovery listener revokes pending automatic work immediately, supports StrictMode replay and revokes on unmount', () => {
  let effect: ts.ArrowFunction | undefined;
  const find = (node: ts.Node) => {
    if (ts.isCallExpression(node) && node.expression.getText(appSource) === 'useEffect' && node.arguments[0]
      && ts.isArrowFunction(node.arguments[0]) && node.arguments[0].getText(appSource).includes("addEventListener('vkarmani:storage-error'")) effect = node.arguments[0];
    ts.forEachChild(node, find);
  }; find(appSource); expect(effect).toBeDefined();
  const ref = { current: false }; const setMode = vi.fn(); const setIssue = vi.fn();
  const epoch = { current: 0 };
  const profile = { ...profileWorkBindings(), recoveryEpochRef: epoch };
  const report = appFunction('reportPersistentFailure', { ...profile, recoveryModeRef: ref, storageFailure, setStorageIssue: setIssue, setRecoveryMode: setMode });
  let listener!: (event: unknown) => void;
  const bindings = { recoveryMode: false, recoveryEpochRef: epoch, recoveryModeRef: ref, reportPersistentFailure: report, invalidateProfileWork: appFunction('invalidateProfileWork', profile),
    window: { addEventListener: (_: string, callback: typeof listener) => { listener = callback; }, removeEventListener: vi.fn() } };
  const js = ts.transpileModule('const effect=' + effect!.getText(appSource), { compilerOptions: { target: ts.ScriptTarget.ES2020 } }).outputText;
  const setup = new Function('bindings', 'const {' + Object.keys(bindings).join(',') + '}=bindings;' + js + ';return effect;')(bindings);
  const firstCleanup = setup(); expect(ref.current).toBe(false); firstCleanup(); expect(ref.current).toBe(true);
  const cleanup = setup(); expect(ref.current).toBe(false);
  listener({ detail: new NativeStorageError('STATE_WRITE_FAILED', 'synthetic') });
  expect(ref.current).toBe(true); expect(setMode).toHaveBeenCalledWith(true); expect(setIssue).toHaveBeenCalled();
  cleanup(); expect(ref.current).toBe(true);
});
