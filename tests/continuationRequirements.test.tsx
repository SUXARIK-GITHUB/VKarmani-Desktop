import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { parseXrayJsonSubscriptionToServers as parse } from '../src/services/remnawave/subscriptionParser';
import { getServerSubtitle } from '../src/utils/serverDisplay';
import { applicationChoices, serviceChoices } from '../src/utils/appInventory';
import { applyPingBatch, runPingBatch } from '../src/utils/pingBatch';
import { SplitTunnelModal } from '../src/components/SplitTunnelModal';
import type { VpnServer, WindowsServiceInfo } from '../src/types/vpn';

const node = (metadata = {}) => ({ protocol:'vless',host:'node.example.test',port:443,
  uuid:'11111111-1111-4111-8111-111111111111',security:'tls', ...metadata });
const servers = (metadata = {}) => parse(JSON.stringify({response:{rawHosts:[node(metadata)]}}));

describe('R06 explicit server descriptions', () => {
  it('keeps a real name separate from its descriptive metadata', () => {
    const [server] = servers({name:'Germany',serverDescription:'Games 🎮 · без рекламы'});
    expect(server.rawLabel).toBe('Germany');
    expect(server.description).toBe('Games 🎮 · без рекламы');
    expect(getServerSubtitle(server)).toBe(server.description);
  });
  it.each([{name:'Germany'},{remark:'technical-node'},{metadata:{name:'Germany'}}])('does not invent descriptions from labels: %j', metadata => {
    const [server] = servers(metadata);
    expect(server.description).toBeUndefined();
    expect(getServerSubtitle(server)).toMatch(/^VLESS(?: \| [A-Z]+)?$/);
  });
  it('retains Unicode descriptions independently of short label bounds and renders text safely', () => {
    const description = '<img src=x onerror=alert(1)> ' + 'Беларусь 🎮 '.repeat(80);
    const [server] = servers({name:'BY',clientOverrides:{serverDescription:description}});
    expect(server.description).toBe(description.trim());
    const markup = renderToStaticMarkup(<small title={getServerSubtitle(server)}>{getServerSubtitle(server)}</small>);
    expect(markup).not.toContain('<img');expect(markup).toContain('&lt;img');
    expect(Array.from(servers({name:'BY',description:'🎮'.repeat(2100)})[0].description!)).toHaveLength(2048);
  });
  it('does not synthesize descriptions for full Xray configs', () => {
    const [server] = parse(JSON.stringify({remarks:'Germany',outbounds:[{protocol:'vless',tag:'proxy',settings:{vnext:[{address:'node.example.test',port:443,users:[{id:node().uuid}]}]}}]}));
    expect(server.description).toBeUndefined();expect(getServerSubtitle(server)).toContain('VLESS');
  });
});

describe('R03 admission rejection is not a network measurement', () => {
  it.each(['PING_BUSY: native ping budget exhausted',new Error('PING_BUSY: native ping budget exhausted')])('retains a known RTT on busy native admission: %s', async error => {
    const catalog: VpnServer[] = [{...servers({name:'Germany'})[0],latency:31,latencyStatus:'ok'}];
    const batch = await runPingBatch(catalog,async()=>{throw error;},new AbortController().signal);
    expect(batch.cancelled).toBe(1);expect(batch.unreachable).toBe(0);
    expect(applyPingBatch(catalog,catalog,batch)[0]).toBe(catalog[0]);
  });
  it('still records an actual endpoint refusal', async () => {
    const catalog = servers({name:'Germany'});
    const batch = await runPingBatch(catalog,async()=>{throw Error('connection refused');},new AbortController().signal);
    expect(batch.unreachable).toBe(1);expect(applyPingBatch(catalog,catalog,batch)[0].latencyStatus).toBe('failed');
  });
});

describe('R27/R28 process, executable and service identities', () => {
  it('groups case/slash variants while preserving separate paths and process counts', () => {
    const list = applicationChoices([{pid:1,name:'app.exe',path:'C:\\Программы\\App.exe'},
      {pid:2,name:'APP.exe',path:'c:/программы/app.EXE'},
      {pid:2,name:'APP.exe',path:'c:/программы/app.EXE'},
      {pid:3,name:'app.exe',path:'D:/Other/app.exe'}]);
    expect(list).toHaveLength(2);expect(list[0].processIds).toEqual([1,2]);
    expect(list[1].executable).toBe('D:/Other/app.exe');
  });
  it('never upgrades inaccessible, relative or device paths to broad basename rules', () => {
    const list = applicationChoices([undefined,'app.exe','\\\\?\\C:\\App.exe','C:/../App.exe'].map((path,index)=>({pid:index+1,name:'app.exe',path})));
    expect(list).toHaveLength(4);expect(list.every(choice=>choice.executable===null)).toBe(true);
  });
  it('deduplicates SCM names, not service executable paths, and fails closed on conflicting identities', () => {
    const svc = (name:string,exePath='C:/Windows/svchost.exe'):WindowsServiceInfo=>({name,displayName:name,exePath,processId:10,state:'Running',supported:false});
    const list = serviceChoices([svc('Dnscache'),svc('DNSCACHE'),svc('Other')]);
    expect(list).toHaveLength(2);expect(list.map(s=>s.name)).toEqual(['Dnscache','Other']);
    expect(serviceChoices([{...svc('Own','C:/Own.exe'),supported:true},{...svc('OWN','D:/Other.exe'),supported:true}])[0].supported).toBe(false);
  });
  it.each(['ru','en'] as const)('provides separate searches, visible limits and disabled unsafe choices in %s', language => {
    const noop=()=>{};
    const html = renderToStaticMarkup(<SplitTunnelModal open language={language} entries={[]} runningApps={Array.from({length:161},(_,index)=>({pid:index,name:`app${index}.exe`,path:index?`C:/Apps/app${index}.exe`:undefined}))} isLoadingApps={false} onClose={noop} onAddEntry={()=>true} onChangePolicy={noop} tunnelMode="tun" tunRoutingMode="all" onToggleEntry={noop} onRemoveEntry={noop} onPickExecutable={noop} onRefreshRunningApps={noop}/>);
    expect(html).toContain(language==='ru'?'Показано: 160 из 161':'Showing 160 of 161');
    expect(html).toContain(language==='ru'?'Поиск правил':'Search rules');
    expect(html).toContain(language==='ru'?'Поиск служб':'Search services');
    expect(html).toContain(language==='ru'?'Показать ещё':'Show more');
    expect(html).toContain('class="running-app-row" disabled=""');
  });
});
