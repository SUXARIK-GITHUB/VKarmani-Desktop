import { readFileSync } from 'node:fs';
import ts from 'typescript';
import { expect, it, vi } from 'vitest';
import { tr } from '../src/i18n';

function disableAction(bindings: Record<string, unknown>): () => Promise<void> {
  const source = ts.createSourceFile('App.tsx', readFileSync('src/App.tsx', 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  let action: ts.FunctionDeclaration | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'handleDisableSystemProxy') action = node;
    ts.forEachChild(node, visit);
  };
  visit(source);
  expect(action).toBeDefined();
  const js = ts.transpileModule(action!.getText(source), { compilerOptions: { target: ts.ScriptTarget.ES2020 } }).outputText;
  return new Function('bindings', `const {${Object.keys(bindings).join(',')}}=bindings;${js};return handleDisableSystemProxy;`)(bindings);
}

it('native restore never manufactures disabled status when current WinINet state cannot be observed', () => {
  const source = readFileSync('src-tauri/src/commands.rs', 'utf8').split('pub(crate) fn set_system_proxy_blocking')[1];
  const branch = source.split('let status = if enabled')[1].split('let _ = append_runtime_event')[0];
  expect(branch).toMatch(/None\s*=>\s*current_proxy_snapshot\(\)\?/);
  expect(branch).not.toContain('enabled: false');
  const event = source.split('let _ = append_runtime_event')[1].split('refresh_tray_menu')[0];
  expect(event).not.toContain('восстановлен/отключён');
});

it.each(['ru', 'en'] as const)('a confirmed original enabled Proxy is not announced as disabled in %s', async language => {
  const status = { enabled: true, server: 'synthetic-proxy:8080', method: 'wininet-api' };
  const update = vi.fn(); const toast = vi.fn(); const log = vi.fn();
  await disableAction({ language, tr, runActionOnce: async (_: string, run: () => Promise<void>) => run(),
    remnawaveClient: { applySystemProxy: vi.fn().mockResolvedValue(status) }, setProxyStatus: update,
    refreshDiagnosticsAndRuntime: vi.fn().mockResolvedValue(null), pushToast: toast, writeNativeRoutingLog: log })();
  expect(update).toHaveBeenCalledExactlyOnceWith(status);
  expect(toast).toHaveBeenCalledExactlyOnceWith(language === 'ru' ? 'Состояние системного proxy проверено.' : 'System proxy state checked.', 'info');
  expect(log.mock.calls.flat().join(' ')).not.toMatch(/выключен|disabled/i);
});

it('failed native Proxy observation preserves the last UI state and reports only failure', async () => {
  const update = vi.fn(); const toast = vi.fn(); const log = vi.fn(); const refresh = vi.fn();
  await disableAction({ language: 'en', tr, runActionOnce: async (_: string, run: () => Promise<void>) => run(),
    remnawaveClient: { applySystemProxy: vi.fn().mockRejectedValue(new Error('Synthetic WinINet query failed')) },
    setProxyStatus: update, refreshDiagnosticsAndRuntime: refresh, pushToast: toast, writeNativeRoutingLog: log })();
  expect(update).not.toHaveBeenCalled(); expect(refresh).not.toHaveBeenCalled(); expect(log).not.toHaveBeenCalled();
  expect(toast).toHaveBeenCalledExactlyOnceWith('Synthetic WinINet query failed', 'error');
});
