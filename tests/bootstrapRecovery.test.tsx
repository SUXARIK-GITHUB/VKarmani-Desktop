import React from 'react';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
import { renderToStaticMarkup } from 'react-dom/server';
import { expect, it, vi } from 'vitest';
import { RootErrorBoundary } from '../src/components/RootErrorBoundary';
import { StorageRecoveryNotice } from '../src/components/StorageRecoveryNotice';

const appSource = ts.createSourceFile('App.tsx', readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
function appFunction(name: string, bindings: Record<string, unknown>) {
  let found: ts.FunctionDeclaration | undefined;
  const visit = (node: ts.Node) => { if (ts.isFunctionDeclaration(node) && node.name?.text === name) found = node; ts.forEachChild(node, visit); };
  visit(appSource); expect(found).toBeDefined();
  const js = ts.transpileModule(found!.getText(appSource), { compilerOptions: { target: ts.ScriptTarget.ES2020 } }).outputText;
  return new Function('bindings', 'const {' + Object.keys(bindings).join(',') + '}=bindings;' + js + ';return ' + name + ';')(bindings);
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
  const common = { storageRecoveryLock: { current: false }, setStorageRecoveryBusy: vi.fn(), setRecoveryMode: safe,
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
  await appFunction('handleStorageRecovery', { storageRecoveryLock: lock, setStorageRecoveryBusy: busy,
    setRecoveryMode: vi.fn(), storageRecoveryToken: 'a'.repeat(64), inspectPersistentRecovery: vi.fn(),
    reloadPersistentSnapshot: vi.fn().mockRejectedValue(failure), applyRestoredPersistentState: apply,
    setStorageIssue: clearIssue, setStorageRecoveryToken: setToken, reportPersistentFailure: report, NativeStorageError: Error })(true);
  expect(report).toHaveBeenCalledWith(failure); expect(apply).not.toHaveBeenCalled(); expect(clearIssue).not.toHaveBeenCalled();
  expect(setToken).toHaveBeenCalledWith(null); expect(lock.current).toBe(false); expect(busy.mock.calls).toEqual([[true], [false]]);
});
