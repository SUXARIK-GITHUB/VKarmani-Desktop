import { describe, it, expect, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import type { VpnServer } from '../src/types/vpn';
import { mergeServerMeasurements, serverMeasurementIdentity } from '../src/utils/serverMeasurements';
import { connectionQuality, qualityLabel } from '../src/utils/connectionQuality';
import { ConnectionQualityIndicator } from '../src/components/ConnectionQualityIndicator';
import { applyPingBatch } from '../src/utils/pingBatch';
import { RemnawaveClient } from '../src/services/remnawave';
import { decodeProfileCache, encodeProfileCache } from '../src/services/profileCache';
import { parseXrayJsonSubscriptionToServers } from '../src/services/remnawave/subscriptionParser';
import { saveLastKnownServers, loadLastKnownServers } from '../src/services/storage';
import auto from './fixtures/xray/auto.json';

const at='2026-10-05T10:00:00Z';
const node=(id='A',host='example.test',port=443):VpnServer=>({id,country:id,city:'',flag:'',load:0,protocol:'Xray',host,port});
const measured=(server:VpnServer,latency=47,checkedAt=at):VpnServer=>({...server,latency,latencyStatus:'ok',latencyCheckedAt:checkedAt,latencyIdentity:serverMeasurementIdentity(server),latencySource:'physical-tcp'});

describe('catalog/measurement reconciliation',()=>{
  it('keeps measurements through reorder, new objects and display changes',()=>{
    const old=[measured(node('A')),measured(node('B'),82)];
    const result=mergeServerMeasurements([{...node('B'),country:'renamed'},node('C'),node('A')],old);
    expect(result.map(x=>[x.id,x.latency,x.latencyStatus])).toEqual([['B',82,'ok'],['C',null,'unchecked'],['A',47,'ok']]);
    expect(result[0].country).toBe('renamed');
  });
  it.each([['host',node('B','other.test')],['port',node('B','example.test',8443)],['transport',{...node('B'),transportLabel:'ws'}]] as const)('invalidates only changed %s identity',(_,changed)=>{
    const old=[measured(node('A')),measured(node('B'))];
    const result=mergeServerMeasurements([node('A'),changed],old);
    expect(result[0].latency).toBe(47);expect(result[1].latencyStatus).toBe('unchecked');
  });
  it('does not transfer by display name or restore removed IDs',()=>{
    expect(mergeServerMeasurements([node('new')],[measured(node('old'))])[0].latencyStatus).toBe('unchecked');
  });
  it('takes newer valid measurement and keeps stale measurements while refresh runs',()=>{
    const old=measured(node(),82,'2026-10-05T09:00:00Z'),newer=measured(node(),47,at);
    expect(mergeServerMeasurements([newer],[old])[0].latency).toBe(47);
    expect(mergeServerMeasurements([node()],[newer],Date.parse(at)+3600000)[0].latency).toBe(47);
  });
  it.each([NaN,Infinity,-5,0])('rejects invalid latency %s',latency=>expect(mergeServerMeasurements([node()],[measured(node(),latency)])[0].latencyStatus).toBe('unchecked'));
  it('rejects future/invalid timestamps',()=>{
    for(const timestamp of ['bad','2099-01-01T00:00:00Z'])expect(mergeServerMeasurements([node()],[measured(node(),47,timestamp)])[0].latencyStatus).toBe('unchecked');
  });
  it('failed result clears stale success/green bars',()=>{
    const failed={...measured(node(),47),latency:null,latencyStatus:'failed' as const,latencyCheckedAt:'2026-10-05T10:01:00Z'};
    const result=mergeServerMeasurements([failed],[measured(node())])[0];
    expect(result.latency).toBeNull();expect(connectionQuality(result).level).toBe(0);
  });
  it('Auto graph invalidates independently of ordinary endpoint measurements',()=>{
    const logical=parseXrayJsonSubscriptionToServers(JSON.stringify(auto))[0];
    expect(logical.runtimeTemplate?.profileKind).toBe('auto');
    const changed={...logical,runtimeTemplate:{...logical.runtimeTemplate!,fullConfig:{...logical.runtimeTemplate!.fullConfig,remarks:'changed graph'}}};
    const result=mergeServerMeasurements([changed,node('ordinary')],[measured(logical),measured(node('ordinary'))]);
    expect(result[0].latencyStatus).toBe('unchecked');expect(result[1].latency).toBe(47);
  });
  it('keeps metadata in protected codec and caches without extra credentials',async()=>{
    const profile=parseXrayJsonSubscriptionToServers(JSON.stringify(auto))[0],value=measured(profile);
    const decoded=decodeProfileCache(encodeProfileCache([value])) as VpnServer[];
    expect(decoded[0].latencyIdentity).toMatch(/^[a-f0-9]{64}$/);
    expect(decoded[0].latency).toBe(47);
    const client=new RemnawaveClient();client.hydrateCachedServers([profile]);client.updateCachedMeasurements([value]);
    vi.stubGlobal('window',{setTimeout,clearTimeout});
    try { expect((await client.loadServers())[0].latency).toBe(47); }
    finally { vi.unstubAllGlobals(); }
    const publicMetadata={...value,runtimeTemplate:undefined};
    expect(mergeServerMeasurements([profile],[publicMetadata])[0].latency).toBe(47);
  });
  it('preserves actual sub-millisecond RTT instead of clamping to one',()=>{
    const list=[node()];const result=applyPingBatch(list,list,{results:[{id:'A',status:'ok',probe:{success:true,latencyMs:0.3} as never}],durationMs:1,success:1,timeout:0,unreachable:0,cancelled:0});
    expect(result[0].latency).toBe(0.3);expect(qualityLabel(result[0],'en')).toContain('<1 ms');
  });
  it('public save/load retains measurement metadata and newer values win over a later secure backup',()=>{
    const data=new Map<string,string>();vi.stubGlobal('window',{setTimeout,clearTimeout,localStorage:{getItem:(key:string)=>data.get(key)??null,setItem:(key:string,value:string)=>data.set(key,value)}});
    try {
      const profile=parseXrayJsonSubscriptionToServers(JSON.stringify(auto))[0];const newer=measured(profile,82,'2026-10-05T10:01:00Z');
      saveLastKnownServers([newer]);const restored=loadLastKnownServers();
      expect(restored[0].runtimeTemplate).toBeUndefined();expect(restored[0].rawUri).toBeUndefined();
      expect(restored[0].latencyIdentity).toBe(newer.latencyIdentity);expect(restored[0].latencySource).toBe('physical-tcp');
      const final=mergeServerMeasurements([measured(profile,47,at)],restored);
      expect(final[0].latency).toBe(82);expect(final[0].runtimeTemplate).toEqual(profile.runtimeTemplate);
    } finally {vi.unstubAllGlobals();}
  });
  it('24-hour logical cache simulation stays one bounded catalog and retains inactive measurements',()=>{
    const start=Date.parse(at);let catalog=Array.from({length:1000},(_,i)=>measured(node(String(i)),47,at));
    for(let hour=1;hour<=24;hour++){
      const now=start+hour*3600000;const rebuilt=catalog.map(s=>({...s,latency:null,latencyStatus:'unchecked' as const,latencyCheckedAt:undefined}));
      catalog=mergeServerMeasurements(rebuilt,catalog,now);
      expect(catalog).toHaveLength(1000);expect(catalog.every(s=>s.latency===47&&s.latencyCheckedAt===at)).toBe(true);
      expect(catalog.every(s=>!('measurementHistory' in s))).toBe(true);
    }
  });
});

describe('actual measured quality in unchanged icon footprint',()=>{
  it.each([[20,4,'excellent'],[50,4,'excellent'],[51,3,'good'],[100,3,'good'],[101,2,'fair'],[180,2,'fair'],[181,1,'poor'],[300,1,'poor'],[301,1,'very-poor'],[1000,1,'very-poor']] as const)('%sms => %s bars/%s',(latency,level,state)=>{
    expect(connectionQuality(measured(node(),latency))).toMatchObject({level,state});
  });
  it('unknown/checking/failed have no active bars, regardless of connected/favorite data',()=>{
    expect(connectionQuality(node()).level).toBe(0);
    expect(connectionQuality(measured(node()),true)).toMatchObject({level:0,state:'checking'});
    expect(connectionQuality({...measured(node()),latencyStatus:'failed'})).toMatchObject({level:0,state:'failed'});
  });
  it.each(['ru','en'] as const)('provides text accessibility without color reliance (%s)',language=>{
    const html=renderToStaticMarkup(<ConnectionQualityIndicator server={measured(node())} language={language}/>);
    expect(html).toContain('role="img"');expect(html).toContain('aria-label=');expect(html).toContain('<title>');expect(html).toContain('47');
    expect((html.match(/<rect/g)??[]).length).toBe(4);
  });
  it('uses the logical Auto RTT without separate member rows',()=>{
    const logical=measured(parseXrayJsonSubscriptionToServers(JSON.stringify(auto))[0],120);
    expect(connectionQuality(logical)).toMatchObject({level:2,state:'fair'});
  });
});
