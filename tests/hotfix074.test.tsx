import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it, vi } from 'vitest';
import auto from './fixtures/xray/auto.json';
import legacy from './fixtures/policies/legacy-upgrade.json';
import { parseXrayJsonSubscriptionToServers as parse } from '../src/services/remnawave/subscriptionParser';
import { getServerPingTargets } from '../src/utils/serverPing';
import { applyPingBatch, runPingBatch, PING_CONCURRENCY, PING_BATCH_TIMEOUT_MS } from '../src/utils/pingBatch';
import type { ConnectivityProbe, VpnServer } from '../src/types/vpn';
import { activeSettingsSection, settingsScrollTarget } from '../src/utils/settingsNavigation';
import { copyInformation } from '../src/utils/clipboard';
import { getServerCountryCode, resolveServerFlag } from '../src/utils/serverDisplay';
import { ServerFlag } from '../src/components/ServerFlag';
import { policyEntryDisplay } from '../src/utils/policyDisplay';
import { normalizeStoredRules } from '../src/utils/appPolicies';
import { SplitTunnelModal } from '../src/components/SplitTunnelModal';
import { SettingsTab } from '../src/components/SettingsTab';
import { defaultSettings } from '../src/services/storage';

const profile = (input = auto) => parse(JSON.stringify(input))[0];
const reply = (latencyMs: number, success = true): ConnectivityProbe => ({ success, latencyMs, checkedAt:'synthetic', httpPortOpen:false, socksPortOpen:false, message:'synthetic' });
const ordinary = (id: string): VpnServer => ({ id, country:id, city:'', flag:'', protocol:'Xray', load:0, host:`${id}.example.test`, port:443 });
describe('Auto logical measurement in the shared queue', () => {
  it('measures selected graph members, not the representative endpoint or cached member tags', () => {
    const p = profile(); p.runtimeTemplate!.memberTags = ['direct']; p.host = 'wrong.example.test';
    expect(getServerPingTargets(p).map(t => t.host)).toEqual(['a.example.com','b.example.com']);
    expect(p.host).toBe('wrong.example.test'); expect(p.runtimeTemplate!.fullConfig).toEqual(auto);
  });
  it.each([0,1,2,3,4,5,6,7])('keeps minimum positive reachable RTT after member permutation %i', async index => {
    const input = structuredClone(auto); if (index % 2) input.outbounds.reverse();
    const p = profile(input), before = JSON.stringify(p);
    const batch = await runPingBatch([p], async member => { await new Promise(r => setTimeout(r, index % 3)); return reply(member.host === 'a.example.com' ? 81 : 17); }, new AbortController().signal);
    expect(batch.results).toHaveLength(1); expect(batch.results[0]).toMatchObject({id:p.id,status:'ok',probe:{latencyMs:17}});
    expect(applyPingBatch([p], [p], batch)[0]).toBe(p); // Foreign snapshot cannot commit.
    const snapshot=[p]; expect(applyPingBatch(snapshot,snapshot,batch)[0].latency).toBe(17);
    expect(JSON.stringify(p)).toBe(before);
  });
  it('retains a healthy member when another rejects, and recovers its minimum on the next batch', async () => {
    const p=profile(); let broken=true;
    const measure=async(member:VpnServer)=>{if(member.host==='a.example.com'&&broken)throw Error('timeout');return reply(member.host==='a.example.com'?5:31);};
    expect((await runPingBatch([p],measure,new AbortController().signal)).results[0].probe?.latencyMs).toBe(31);
    broken=false; expect((await runPingBatch([p],measure,new AbortController().signal)).results[0].probe?.latencyMs).toBe(5);
  });
  it('preserves failed ordinary-node diagnostics while Auto aggregates member RTTs', async () => {
    const failed=reply(9,false);
    const batch=await runPingBatch([ordinary('ordinary')],async()=>failed,new AbortController().signal);
    expect(batch.results[0]).toMatchObject({status:'unreachable',probe:failed});
  });
  it.each([0,-1,NaN,Infinity])('rejects invalid successful latency %s', async value => {
    expect((await runPingBatch([profile()],async()=>reply(value),new AbortController().signal)).unreachable).toBe(1);
  });
  it('supports case-sensitive no-match fallback and excludes unrelated outbounds', () => {
    const input=structuredClone(auto); input.routing.balancers[0].selector=['POOL-'];
    expect(getServerPingTargets(profile(input)).map(t=>t.host)).toEqual(['b.example.com']);
    input.routing.balancers[0].fallbackTag='';
    const p=profile();p.runtimeTemplate!.fullConfig=input;expect(getServerPingTargets(p)).toEqual([]);
  });
  it('deduplicates an overlapping fallback and identical endpoints within a profile', () => {
    const input=structuredClone(auto); input.outbounds[1].settings={servers:[{address:'a.example.com',port:443,password:'synthetic'}]};
    expect(getServerPingTargets(profile(input))).toHaveLength(1);
  });
  it('uses the primary routed balancer when several balancers are retained', () => {
    const input=structuredClone(auto);
    input.routing.balancers.push({tag:'second',selector:['pool-b'],strategy:{type:'leastLoad',settings:{expected:1}},fallbackTag:'pool-b'});
    input.routing.rules.unshift({type:'field',domain:['domain:second.example'],balancerTag:'second'} as typeof input.routing.rules[number]);
    expect(getServerPingTargets(profile(input)).map(t=>t.host)).toEqual(['b.example.com']);
    expect(profile(input).runtimeTemplate!.fullConfig).toEqual(input);
  });
  it.each([null,[],{},'', ' ',42])('rejects malformed member endpoints %j without inventing latency', async address => {
    const p=profile(); const input=structuredClone(auto);
    (input.outbounds[0].settings!.vnext![0] as unknown as Record<string,unknown>).address=address;
    (input.outbounds[1].settings!.servers![0] as unknown as Record<string,unknown>).address=address;
    p.runtimeTemplate!.fullConfig=input; const probe=vi.fn();
    expect((await runPingBatch([p],probe,new AbortController().signal)).unreachable).toBe(1);expect(probe).not.toHaveBeenCalled();
  });
  it.each([null,undefined,{success:true,latencyMs:'7'},{success:'yes',latencyMs:7}])('rejects malformed probe replies %j without unhandled rejection',async value=>{
    expect((await runPingBatch([profile()],async()=>value as ConnectivityProbe,new AbortController().signal)).unreachable).toBe(1);
  });
  it('uses one four-worker budget across multiple Auto profiles and ordinary entries', async () => {
    const second=structuredClone(auto);second.remarks='Second independent profile';
    const targets=[profile(),ordinary('one'),profile(second),ordinary('two')];let active=0,peak=0;const called:string[]=[];const progress:number[]=[];
    const batch=await runPingBatch(targets,async t=>{called.push(t.host!);active++;peak=Math.max(active,peak);await new Promise(r=>setTimeout(r,3));active--;return reply(12);},new AbortController().signal,n=>progress.push(n));
    expect(peak).toBe(PING_CONCURRENCY);expect(active).toBe(0);expect(called).toHaveLength(6);expect(batch.success).toBe(4);expect(progress).toEqual([1,2,3,4]);
    const committed=applyPingBatch(targets,targets,batch);expect(committed).toHaveLength(4);expect(committed.map(p=>p.id)).toEqual(targets.map(p=>p.id));
  });
  it('cancels Auto members and queued profiles without late commit or leaked timers', async () => {
    const controller=new AbortController();const targets=[profile(),profile(),ordinary('next'),ordinary('last')];let calls=0;
    const pending=runPingBatch(targets,()=>{calls++;return new Promise(()=>{});},controller.signal);await Promise.resolve();controller.abort();
    const batch=await pending;expect(calls).toBe(4);expect(batch.cancelled).toBe(4);expect(applyPingBatch(targets,targets,batch)).toEqual(targets);
  });
  it('bounds all-timeout multi-profile work to the existing 60-second batch deadline', async () => {
    vi.useFakeTimers({toFake:['setTimeout','clearTimeout','performance']});
    try {const targets=Array.from({length:50},()=>profile());const pending=runPingBatch(targets,()=>new Promise(()=>{}),new AbortController().signal);await vi.advanceTimersByTimeAsync(PING_BATCH_TIMEOUT_MS);const batch=await pending;expect(batch.timeout).toBe(50);expect(batch.durationMs).toBeLessThanOrEqual(PING_BATCH_TIMEOUT_MS);expect(vi.getTimerCount()).toBe(0);}finally{vi.useRealTimers();}
  });
  it('fails closed on corrupt/unsupported/no-member graphs without network work', async () => {
    const p=profile();p.runtimeTemplate!.fullConfig={outbounds:[]};const probe=vi.fn();const batch=await runPingBatch([p],probe,new AbortController().signal);expect(probe).not.toHaveBeenCalled();expect(batch.unreachable).toBe(1);
  });
});
describe('Settings geometry and explicit clipboard results', () => {
  it('selects the last section crossing the measured sticky activation line', () => {
    const sections=[{id:'general',top:200},{id:'network',top:560},{id:'diagnostics',top:1400}];
    expect(activeSettingsSection(sections,0,154)).toBe('general');expect(activeSettingsSection(sections,410,154)).toBe('network');expect(activeSettingsSection(sections,1250,154)).toBe('diagnostics');
    expect(activeSettingsSection(sections,410,74)).toBe('general');
  });
  it('clamps measured click destinations at both boundaries',()=>{expect(settingsScrollTarget(560,154,2000)).toBe(406);expect(settingsScrollTarget(10,154,2000)).toBe(0);expect(settingsScrollTarget(560,154,300)).toBe(300);});
  it('reports clipboard success only after resolution, with no payload/error logging',async()=>{let finish!:()=>void;const writer=vi.fn(()=>new Promise<void>(r=>{finish=r;}));let settled=false;const copy=copyInformation('synthetic device details',{writeText:writer}).then(result=>{settled=true;return result;});await Promise.resolve();expect(settled).toBe(false);finish();expect(await copy).toBe(true);expect(writer).toHaveBeenCalledOnce();});
  it('handles rejected and missing clipboard',async()=>{expect(await copyInformation('synthetic',{writeText:async()=>{throw Error('sensitive error');}})).toBe(false);expect(await copyInformation('synthetic')).toBe(false);});
});
describe('EU region and local quarantined rule UI', () => {
  it.each(['ru','en'] as const)('has no raw DIRECT badge or new native policy select in Settings %s',language=>{
    const noop=()=>{};
    const html=renderToStaticMarkup(<SettingsTab settings={defaultSettings} language={language} onToggleSetting={noop} onTunnelModeChange={noop} onIpStackChange={noop} onTunRoutingModeChange={noop} onLanguageChange={noop} onRoutingExclusionsChange={noop}/>);
    expect(html).not.toContain('>DIRECT<');expect(html).not.toContain('<select');expect(html).toContain(language==='ru'?'Напрямую':'Direct');
  });
  it.each(['EU','eu','Eu','🇪🇺'])('renders the normalized region %s using the common resolver and actual SVG', flag => {
    const server={country:'EU Auto',flag}; expect(getServerCountryCode(server)).toBe('EU'); expect(resolveServerFlag(server)).toBe('🇪🇺');
    const html=renderToStaticMarkup(<ServerFlag server={server}/>);expect(html).toContain('<svg');expect(html).toContain('#003399');expect(html.match(/#FFCC00/g)).toHaveLength(12);
  });
  it('recognizes lower-case EU labels without the Auto name and preserves country/fallback behavior',()=>{for(const rawLabel of ['EU','eu','Eu','EU Auto'])expect(getServerCountryCode({rawLabel})).toBe('EU');expect(getServerCountryCode({rawLabel:'Auto'})).toBeUndefined();expect(resolveServerFlag({flag:'de'})).toBe('🇩🇪');expect(resolveServerFlag({rawLabel:'unknown'})).toBe('🌐');});
  it('preserves silent migration/delete/re-add over repeated serialization cycles',()=>{
    const migrated=normalizeStoredRules(legacy.splitTunnelEntries), before=structuredClone(migrated);
    let rules=migrated.filter(r=>r.id!=='script');rules.push({id:'replacement',kind:'app',value:'New.exe',enabled:true,policy:'VPN',schemaVersion:2});
    for(let i=0;i<5;i++)rules=normalizeStoredRules(JSON.parse(JSON.stringify(rules)));
    expect(migrated).toEqual(before);expect(rules.some(r=>r.id==='script')).toBe(false);expect(rules.filter(r=>r.id==='replacement')).toHaveLength(1);
  });
  it.each(['ru','en'] as const)('renders quarantined records locally with human policies in %s and no technical sentinel/reason',language=>{
    const entries=normalizeStoredRules([{id:'bad',kind:'app',value:'<invalid stored policy>',enabled:true},{id:'path',kind:'app',value:'C:/Apps/Example.exe',enabled:true}]);
    expect(policyEntryDisplay(entries[0],language).detail).toBe('');
    const html=renderToStaticMarkup(<SplitTunnelModal open language={language} entries={entries} runningApps={[]} isLoadingApps={false} onClose={()=>{}} onAddEntry={()=>true} onChangePolicy={()=>{}} tunnelMode="tun" tunRoutingMode="all" onToggleEntry={()=>{}} onRemoveEntry={()=>{}} onPickExecutable={()=>{}} onRefreshRunningApps={()=>{}}/>);
    expect(html).not.toContain('invalid stored policy');expect(html).not.toContain(entries[0].invalidReason);expect(html).not.toContain('<select');expect(html).not.toContain('>DIRECT<');expect(html).toContain(language==='ru'?'Требует настройки':'Needs setup');expect(html).toContain('Example.exe');
  });
});
