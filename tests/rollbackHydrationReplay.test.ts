import { readFileSync } from 'node:fs';
import ts from 'typescript';
import { afterEach, expect, it, vi } from 'vitest';
import { NativeStateFake } from './helpers/nativeStateFake';
const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
afterEach(() => vi.unstubAllGlobals());

it.each(['ensureAdminLaunch', 'setNativeLaunchOnStartup'])('defers %s until native settings restoration succeeds', async command => {
  const source = ts.createSourceFile('App.tsx', readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  let effect: ts.CallExpression | undefined;
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && node.expression.getText(source) === 'useEffect'
      && node.arguments[0]?.getText(source).includes(`void ${command}(`)) effect = node;
    ts.forEachChild(node, visit);
  };
  visit(source);
  expect(effect).toBeDefined();
  const call = vi.fn().mockResolvedValue(undefined);
  const attempted = { current: false };
  const js = ts.transpileModule('const effect=' + effect!.arguments[0].getText(source), { compilerOptions: { target: ts.ScriptTarget.ES2020 } }).outputText;
  const run = (ready: boolean) => new Function('bindings', 'const {persistentStateReady,settings,hasTriedAdminLaunch,isTauriRuntime,ensureAdminLaunch,setNativeLaunchOnStartup}=bindings;' + js + ';effect();')({
    persistentStateReady: ready, settings: { runAsAdmin: true, launchOnStartup: false }, hasTriedAdminLaunch: attempted,
    isTauriRuntime: true, ensureAdminLaunch: call, setNativeLaunchOnStartup: call
  });
  run(false);
  expect(call).not.toHaveBeenCalled();
  expect(attempted.current).toBe(false);
  expect(effect!.arguments[1].getText(source)).toContain('persistentStateReady');
  run(true);
  expect(call).toHaveBeenCalledExactlyOnceWith(command === 'ensureAdminLaunch');
});

it('executes the actual App hydration effect twice with cleanup without enabling default autosave', async () => {
  vi.resetModules(); invoke.mockReset(); const backend = new NativeStateFake();
  backend.snapshot.payload.public = { settings: {language:'en',themeGlow:false}, favoriteServerIds:['fav'], selectedServerId:'selected', splitTunnelEntries:[] };
  invoke.mockImplementation((command,args) => backend.invoke(command,args));
  vi.stubGlobal('window', {__TAURI_INTERNALS__:{},localStorage:{getItem:()=>null,setItem:vi.fn(),removeItem:vi.fn()},setTimeout,clearTimeout});
  const storage = await import('../src/services/storage');
  const source = ts.createSourceFile('App.tsx',readFileSync(new URL('../src/App.tsx',import.meta.url),'utf8'),ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX);
  let effect: ts.ArrowFunction | undefined;
  const visit=(node:ts.Node)=>{if(ts.isCallExpression(node)&&node.expression.getText(source)==='useEffect'&&node.arguments[0]&&ts.isArrowFunction(node.arguments[0])&&node.arguments[0].getText(source).includes('persistentRestoreStarted'))effect=node.arguments[0];ts.forEachChild(node,visit);};visit(source);
  expect(effect).toBeDefined();
  const refs={settingsRef:{current:storage.defaultSettings},splitTunnelEntriesRef:{current:[]},favoriteServerIdsRef:{current:[] as string[]},selectedServerIdRef:{current:''}};
  const ready=vi.fn();
  const bindings={isTauriRuntime:true,persistentRestoreStarted:{current:false},setPersistentStateReady:ready,...refs,
    loadSettingsBackup:storage.loadSettingsBackup,loadSplitTunnelEntriesBackup:storage.loadSplitTunnelEntriesBackup,loadFavoriteServerIdsBackup:storage.loadFavoriteServerIdsBackup,loadSelectedServerIdBackup:storage.loadSelectedServerIdBackup,
    setSettings:vi.fn(),setSplitTunnelEntries:vi.fn(),setFavoriteServerIds:vi.fn(),setSelectedServerId:vi.fn(),pushToast:vi.fn(),tr:(_:unknown,ru:string)=>ru,language:'ru',writeNativeInterfaceLog:vi.fn()};
  const js=ts.transpileModule('const hydrationEffect='+effect!.getText(source),{compilerOptions:{target:ts.ScriptTarget.ES2020,module:ts.ModuleKind.ESNext}}).outputText;
  const hydrate=new Function('bindings','const {'+Object.keys(bindings).join(',')+'}=bindings;'+js+';return hydrationEffect;')(bindings) as ()=>()=>void;
  const cleanup=hydrate();cleanup();const finalCleanup=hydrate();
  expect(ready).not.toHaveBeenCalled();
  await vi.waitFor(()=>expect(ready).toHaveBeenCalledWith(true));
  expect(refs.settingsRef.current).toMatchObject({language:'en',themeGlow:false});
  expect(refs.favoriteServerIdsRef.current).toEqual(['fav']);expect(refs.selectedServerIdRef.current).toBe('selected');
  storage.saveSettings(refs.settingsRef.current);storage.saveFavoriteServerIds(refs.favoriteServerIdsRef.current);storage.saveSelectedServerId(refs.selectedServerIdRef.current);await storage.flushPersistentWrites();
  expect(backend.snapshot.payload.public.settings).toMatchObject({language:'en',themeGlow:false});
  expect(backend.snapshot.payload.public.favoriteServerIds).toEqual(['fav']);expect(backend.snapshot.payload.public.selectedServerId).toBe('selected');
  finalCleanup();
});
