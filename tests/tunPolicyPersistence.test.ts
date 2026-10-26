import { readFileSync } from 'node:fs';
import ts from 'typescript';
import { afterEach, expect, it, vi } from 'vitest';
import { NativeStateFake } from './helpers/nativeStateFake';
import matrix from './fixtures/policies/tun-admission.json';
import { isTunProcessRoutingBlocked, normalizeStoredRules } from '../src/utils/appPolicies';
const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ invoke }));
afterEach(() => vi.unstubAllGlobals());

it('persists selected→all→exclude→all and reloads settings/rules without dropping saved VPN or DIRECT intent', async () => {
  vi.resetModules();
  const backend = new NativeStateFake();
  const entries = normalizeStoredRules([...matrix[1].entries, { id:'direct-disabled',kind:'app',value:'direct.exe',enabled:false,policy:'DIRECT',schemaVersion:2 }]);
  backend.snapshot.payload.public = { settings:{tunnelMode:'tun',tunRoutingMode:'selected',themeGlow:false}, splitTunnelEntries:entries };
  invoke.mockImplementation((command,args)=>backend.invoke(command,args));
  vi.stubGlobal('window',{__TAURI_INTERNALS__:{},localStorage:{getItem:()=>null,setItem:vi.fn(),removeItem:vi.fn()},setTimeout,clearTimeout});
  for (const mode of ['selected','all','exclude','all'] as const) {
    const storage = await import('../src/services/storage');
    const loaded = await storage.loadPersistentSnapshot();
    expect(loaded.entries).toEqual(entries);
    storage.saveSettings({...loaded.settings,tunRoutingMode:mode});
    await storage.flushPersistentWrites();
    vi.resetModules();
    const restored = await (await import('../src/services/storage')).loadPersistentSnapshot();
    expect(restored.settings).toMatchObject({tunnelMode:'tun',tunRoutingMode:mode,themeGlow:false});
    expect(restored.entries).toEqual(entries);
    expect(isTunProcessRoutingBlocked(restored.entries,mode)).toBe(mode==='selected');
  }
});

it('both actual App routing controls only change the routing preference, leaving rules untouched', () => {
  const source=ts.createSourceFile('App.tsx',readFileSync(new URL('../src/App.tsx',import.meta.url),'utf8'),ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX);
  const callbacks: ts.Expression[]=[];
  const visit=(node:ts.Node)=>{if(ts.isJsxAttribute(node)&&node.name.getText(source)==='onTunRoutingModeChange'&&node.initializer&&ts.isJsxExpression(node.initializer)&&node.initializer.expression)callbacks.push(node.initializer.expression);ts.forEachChild(node,visit);};visit(source);
  expect(callbacks).toHaveLength(2);
  for(const callback of callbacks){
    const entries=normalizeStoredRules(matrix[1].entries), before=structuredClone(entries);
    let settings={tunRoutingMode:'selected',tunnelMode:'tun',themeGlow:false};
    const settingsRef={current:settings};
    const setSettings=(update:(s:typeof settings)=>typeof settings)=>{settings=update(settings);};
    const js=ts.transpileModule('const change='+callback.getText(source),{compilerOptions:{target:ts.ScriptTarget.ES2020}}).outputText;
    new Function('settingsRef','setSettings',js+';change("all");')(settingsRef,setSettings);
    expect(settingsRef.current).toEqual({tunRoutingMode:'all',tunnelMode:'tun',themeGlow:false});
    expect(settings).toEqual(settingsRef.current); expect(entries).toEqual(before);
  }
});
