import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const mocks=vi.hoisted(()=>({fetch:vi.fn(),cache:vi.fn()}));
vi.mock('../src/services/runtime',async importOriginal=>({ ...await importOriginal<typeof import('../src/services/runtime')>(),fetchRemoteText:mocks.fetch,cacheNativeProfileSync:mocks.cache }));
import { RemnawaveClient } from '../src/services/remnawave';
import { parseXrayJsonSubscriptionToServers as parse } from '../src/services/remnawave/subscriptionParser';
import { resolveConnectedProfile, buildServerRuntimeFingerprint } from '../src/utils/serverIdentity';
import { normalizeStoredSettings, saveSettings, loadSettings, loadSplitTunnelEntries } from '../src/services/storage';
const key='https://sub.vkarmani.com/qa-synthetic-fixture';
const config=(name:string)=>({remarks:name,outbounds:[{tag:'proxy',protocol:'vless',settings:{vnext:[{address:`${name.toLowerCase()}.example.test`,port:443,users:[{id:'00000000-0000-4000-8000-000000000001'}]}]}}]});
beforeEach(()=>{vi.stubGlobal('window',{setTimeout,clearTimeout});mocks.fetch.mockReset();mocks.cache.mockReset();mocks.cache.mockResolvedValue(undefined);});
afterEach(()=>vi.unstubAllGlobals());
describe('actual subscription-client atomic refresh and generation ownership',()=>{
  it('commits all logical profiles in payload order after validation and preserves stable IDs under reorder',async()=>{
    const client=new RemnawaveClient();mocks.fetch.mockResolvedValue(JSON.stringify([config('A'),config('B')]));
    const one=await client.syncProfile(key);expect(one.servers.map(s=>s.sourceOrder)).toEqual([0,1]);const ids=one.servers.map(s=>s.id);
    mocks.fetch.mockResolvedValue(JSON.stringify([config('B'),config('A')]));const two=await client.syncProfile(key);expect(two.servers.map(s=>s.id)).toEqual([...ids].reverse());expect(two.servers.map(s=>s.sourceOrder)).toEqual([0,1]);
  });
  it.each(['not-json',JSON.stringify([config('A'),null]),JSON.stringify([config('A'),{outbounds:[],routing:{rules:[{outboundTag:'missing'}]}}])])('retains the complete previous cache for malformed/partial subscription %s',async text=>{
    const client=new RemnawaveClient();const old=parse(JSON.stringify([config('PreviousA'),config('PreviousB')]));client.hydrateCachedServers(old);mocks.fetch.mockResolvedValue(text);
    await expect(client.syncProfile(key)).rejects.toThrow();expect(await client.loadServers()).toEqual(old);
  });
  it('does not commit before native metadata stage succeeds; failure preserves previous complete list',async()=>{
    const client=new RemnawaveClient();const old=parse(JSON.stringify(config('Previous')));client.hydrateCachedServers(old);mocks.fetch.mockResolvedValue(JSON.stringify([config('A'),config('B')]));mocks.cache.mockRejectedValue(new Error('metadata stage failed'));
    await expect(client.syncProfile(key)).rejects.toThrow('metadata stage failed');expect(await client.loadServers()).toEqual(old);
  });
  it('ignores older refresh completion and cannot roll back a newer committed list',async()=>{
    const client=new RemnawaveClient();let resolveOld!:(s:string)=>void;mocks.fetch.mockImplementationOnce(()=>new Promise(r=>resolveOld=r));const old=client.syncProfile(key);const oldRejection=expect(old).rejects.toThrow('PROFILE_SYNC_CANCELLED');
    mocks.fetch.mockResolvedValue(JSON.stringify(config('New')));const newer=await client.syncProfile(key);resolveOld(JSON.stringify(config('Old')));await oldRejection;expect(await client.loadServers()).toEqual(newer.servers);
  });
  it('invalidates pending refresh on logout/unmount without connecting or touching native network',async()=>{
    const client=new RemnawaveClient();let resolve!:(s:string)=>void;mocks.fetch.mockImplementation(()=>new Promise(r=>resolve=r));const pending=client.syncProfile(key);const rejected=expect(pending).rejects.toThrow('PROFILE_SYNC_CANCELLED');client.invalidateProfileSync();resolve(JSON.stringify(config('Stale')));await rejected;expect(await client.loadServers()).toEqual([]);expect(mocks.cache).not.toHaveBeenCalled();
  });
  it('new/removed servers replace cache atomically, preserving connected runtime is a separate ownership',async()=>{
    const client=new RemnawaveClient();mocks.fetch.mockResolvedValue(JSON.stringify([config('A'),config('B')]));const old=await client.syncProfile(key);mocks.fetch.mockResolvedValue(JSON.stringify([config('C'),config('B')]));const next=await client.syncProfile(key);expect(next.servers[0].id).not.toBe(old.servers[0].id);expect(next.servers[1].id).toBe(old.servers[1].id);expect(next.servers).toHaveLength(2);
  });
});
describe('persistent preference and legacy TUN mode',()=>{
 it('persists ON/OFF across save/load without a remote operation',()=>{
  const data=new Map<string,string>();vi.stubGlobal('window',{localStorage:{getItem:(key:string)=>data.get(key)??null,setItem:(key:string,value:string)=>data.set(key,value)}});
  try{for(const sortServersByPing of [false,true,false]){saveSettings({...normalizeStoredSettings({}),sortServersByPing});expect(loadSettings().sortServersByPing).toBe(sortServersByPing);}}finally{vi.unstubAllGlobals();}
 });
 it('fresh empty TUN selects all; legacy existing rules retain selected scope; explicit modes survive',()=>{
  expect(normalizeStoredSettings({tunnelMode:'tun'}).tunRoutingMode).toBe('all');expect(normalizeStoredSettings({tunnelMode:'tun'},true).tunRoutingMode).toBe('selected');for(const tunRoutingMode of ['all','selected','exclude'] as const)expect(normalizeStoredSettings({tunRoutingMode},true).tunRoutingMode).toBe(tunRoutingMode);
 });
});

describe('connected runtime versus refreshed catalog',()=>{
 it('retains removed/changed active graph, with no selection-by-index or automatic reconnect',()=>{
  const [active]=parse(JSON.stringify(config('A')));const hash=buildServerRuntimeFingerprint(active);const [other]=parse(JSON.stringify(config('B')));
  expect(resolveConnectedProfile([other],active.id,hash,active)).toBe(active);
  const changed={...other,id:active.id};expect(resolveConnectedProfile([changed],active.id,hash,active)).toBe(active);
  expect(resolveConnectedProfile([other],other.id,buildServerRuntimeFingerprint(other),active)).toBe(other);
  expect(resolveConnectedProfile([other],'unrelated',undefined,active)).toBeNull();
 });
});

describe('storage quarantine and missing/corrupt settings scope',()=>{
 it.each(['{}','not-json'])('preserves corrupt stored policy %s visibly and disabled',raw=>{
  const data=new Map([['vkarmani.split-tunnel.entries',raw]]);vi.stubGlobal('window',{localStorage:{getItem:(key:string)=>data.get(key)??null}});
  const entries=loadSplitTunnelEntries();expect(entries).toHaveLength(1);expect(entries[0].enabled).toBe(false);expect(entries[0].invalidReason).toBe('RULE_SCHEMA_INVALID');expect(loadSettings().tunRoutingMode).toBe('selected');
 });
 it('missing or null settings with legacy rules must not broaden selected routing to all',()=>{expect(normalizeStoredSettings(null,true).tunRoutingMode).toBe('selected');});
});
