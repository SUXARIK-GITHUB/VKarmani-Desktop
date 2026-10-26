import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
import { expect, it, vi } from 'vitest';
import { SplitTunnelModal } from '../src/components/SplitTunnelModal';
import { OverviewTab } from '../src/components/OverviewTab';
import { SettingsTab } from '../src/components/SettingsTab';
import { defaultSettings } from '../src/services/storage';
import { isTunProcessRoutingBlocked, normalizeStoredRules, tunProcessRoutingBlockMessage } from '../src/utils/appPolicies';
import type { SplitTunnelEntry, TunRoutingMode } from '../src/types/vpn';
import matrix from './fixtures/policies/tun-admission.json';
const noop = () => {};
const rules = normalizeStoredRules(matrix[1].entries);
const modal = (mode: TunRoutingMode, entries = rules, language: 'ru' | 'en' = 'en') => <SplitTunnelModal open language={language} entries={entries} runningApps={[]} isLoadingApps={false} onClose={noop} onAddEntry={() => true} onChangePolicy={noop} tunnelMode="tun" tunRoutingMode={mode} onTunRoutingModeChange={noop} onToggleEntry={noop} onRemoveEntry={noop} onPickExecutable={noop} onRefreshRunningApps={noop} />;

it.each(matrix)('frontend and saved rules: $name', row => {
  const entries = normalizeStoredRules(row.entries);
  expect(isTunProcessRoutingBlocked(entries, row.mode as TunRoutingMode)).toBe(row.blocked);
  const restarted = normalizeStoredRules(JSON.parse(JSON.stringify(entries)));
  expect(restarted).toEqual(entries);
  expect(isTunProcessRoutingBlocked(restarted, row.mode as TunRoutingMode)).toBe(row.blocked);
});

it.each(['ru', 'en'] as const)('has an in-modal mode choice and no blanket warning in safe all (%s)', language => {
  const html = renderToStaticMarkup(modal('all', rules, language));
  expect(html).toContain('role="radiogroup" aria-label="' + (language === 'ru' ? 'Маршрутизация приложений' : 'App routing') + '"');
  expect(html).not.toContain('временно заблокирована');
  expect(html).not.toContain('temporarily blocked');
  expect(html).toContain('Discord.exe'); expect(html).toContain('brave.exe');
});

it.each((['ru', 'en'] as const).flatMap(language => (['all', 'selected', 'exclude'] as const).map(mode => ({ language, mode }))))('omits redundant executable help while retaining saved identities and controls ($language/$mode)', ({ language, mode }) => {
  const entries: SplitTunnelEntry[] = [
    { id: 'exact', kind: 'app', value: 'C:/Exact Folder/Discord.exe', enabled: true, policy: 'VPN', schemaVersion: 2 },
    { id: 'by-name', kind: 'app', value: 'brave.exe', enabled: false, policy: 'DIRECT', schemaVersion: 2 },
    { id: 'service', kind: 'service', value: 'DedicatedSvc', enabled: false, policy: 'VPN', schemaVersion: 2 }
  ];
  const before = structuredClone(entries);
  const html = renderToStaticMarkup(modal(mode, entries, language));
  expect(html).not.toContain('Полный путь выбирает один файл');
  expect(html).not.toContain('A full path targets one file');
  expect(html).toContain('C:/Exact Folder/Discord.exe');
  expect(html).toContain('brave.exe');
  expect(html).toContain('DedicatedSvc');
  const routingChoices = html.match(/role="radiogroup" aria-label="(?:Маршрутизация приложений|App routing)">([\s\S]*?)<\/div>/)?.[1];
  expect(routingChoices?.match(/role="radio"/g)).toHaveLength(3);
  expect(html.match(/class="split-entry /g)).toHaveLength(3);
  expect(html).toContain(language === 'ru' ? 'Поиск правил, программ и служб' : 'Search rules, applications and services');
  expect(html).toContain(language === 'ru' ? 'Выбрать .exe' : 'Choose .exe');
  expect(html).toContain(language === 'ru' ? 'Добавить службу' : 'Add service');
  expect(entries).toEqual(before);
  expect(isTunProcessRoutingBlocked(entries, mode)).toBe(mode === 'selected');
});

it('keeps the selected choice without the obsolete warning or forced-All action', () => {
  const html = renderToStaticMarkup(modal('selected'));
  expect(html).not.toContain('Selected-app routing is unavailable');
  expect(html).not.toContain('Switch to All applications');
  expect(html).toContain('aria-checked="true" tabindex="0" class="active">Selected through VPN');
  expect(isTunProcessRoutingBlocked(rules, 'selected')).toBe(true); // Ordinary builds stay protected.
  expect(html).not.toContain('Add at least one');
});

it('preserves DIRECT intent and ordinary-build refusal without obsolete modal/settings banners', () => {
  const direct = normalizeStoredRules(matrix[2].entries);
  for (const html of [renderToStaticMarkup(modal('all', direct)), renderToStaticMarkup(<SettingsTab settings={{...defaultSettings,tunnelMode:'tun'}} splitTunnelEntries={direct} language="en" onToggleSetting={noop} onTunnelModeChange={noop} onIpStackChange={noop} onTunRoutingModeChange={noop} onLanguageChange={noop} onRoutingExclusionsChange={noop} />)]) {
    expect(html).not.toContain('Disable active DIRECT rules');
  }
  expect(direct[0]).toMatchObject({enabled:true,policy:'DIRECT'});
  expect(isTunProcessRoutingBlocked(direct, 'all')).toBe(true);
});

it('removes the extra CTA banner/action while retaining the actual disabled reason on the control', () => {
  const reason = 'Selected-app routing is unavailable';
  const html = renderToStaticMarkup(<OverviewTab connectionState="idle" connectLabel="Connect" selectedServer={null} selectedServerId="" servers={[]} allServerCount={0} searchValue="" sessionDurationText="00:00:00" language="en" showDiagnostics={false} tunnelMode="tun" onToggleConnection={noop} onTunnelModeChange={noop} onSelectServer={noop} onSearchChange={noop} onRefreshServers={noop} onRefreshPing={noop} onToggleFavoriteServer={noop} favoriteServerIds={[]} trafficReceivedText="0" trafficSentText="0" trafficChartBars={[]} vpnExternalIp="" packetLossText="" canConnect={false} connectDisabledReason={reason} activeSplitTunnelCount={3} onOpenSplitTunnel={noop}/>);
  expect(html).toContain('title="' + reason + '"');
  expect(html).not.toContain('vk-connect-disabled-reason');
  expect(html).not.toContain('Configure TUN');
});

it.each(['selected','all','exclude'] as const)('blocked connected Proxy→TUN (%s) preserves the prior connection and preferences before admission', async mode => {
  const source = ts.createSourceFile('App.tsx', readFileSync(new URL('../src/App.tsx', import.meta.url),'utf8'), ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX);
  let handler: ts.FunctionDeclaration | undefined;
  const visit=(node:ts.Node)=>{if(ts.isFunctionDeclaration(node)&&node.name?.text==='handleTunnelModeChange')handler=node;ts.forEachChild(node,visit);};visit(source);
  const entries: SplitTunnelEntry[] = mode === 'selected' ? rules : normalizeStoredRules(matrix[2].entries);
  const mutate=vi.fn(()=>{throw new Error('blocked policy changed a working preference');});
  const bindings={settingsRef:{current:{...defaultSettings,tunnelMode:'proxy',tunRoutingMode:mode}},connectionStateRef:{current:'connected'},splitTunnelEntriesRef:{current:entries},pendingTunnelModeRef:{current:null},pushToast:vi.fn(),tr:(_:string,ru:string)=>ru,language:'ru',isTunProcessRoutingBlocked,isSelectedTunPolicyEmpty:()=>false,isConnectionActionBusy:()=>false,connectionActionLock:{current:false},getConnectedRuntimeServer:()=>null,getServerById:()=>null,selectedServerIdRef:{current:''},selectedServer:null,writeNativeInterfaceLog:noop,updateTunnelModePreference:mutate,refreshDiagnosticsAndRuntime:vi.fn(),scheduleConnectionQueueFlush:noop,flushQueuedConnectionWork:noop,normalizeNativeError:()=>({message:'synthetic'}),writeNativeRoutingLog:noop};
  Object.assign(bindings, { tunProcessRoutingBlockMessage });
  const js=ts.transpileModule(handler!.getText(source),{compilerOptions:{target:ts.ScriptTarget.ES2020}}).outputText;
  const run=new Function('bindings','const {'+Object.keys(bindings).join(',')+'}=bindings;'+js+';return handleTunnelModeChange;')(bindings);
  await run('tun');
  expect(mutate).not.toHaveBeenCalled(); expect(bindings.settingsRef.current.tunnelMode).toBe('proxy');
  expect(bindings.pushToast).toHaveBeenCalled();
});
