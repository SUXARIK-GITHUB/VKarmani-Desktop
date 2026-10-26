import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const mocks=vi.hoisted(()=>({fetch:vi.fn(),json:vi.fn(),cache:vi.fn()}));
vi.mock('../src/services/runtime',async importOriginal=>({ ...await importOriginal<typeof import('../src/services/runtime')>(),fetchRemoteText:mocks.fetch,fetchRemoteJson:mocks.json,cacheNativeProfileSync:mocks.cache }));
import { RemnawaveClient } from '../src/services/remnawave';
import { parseXrayJsonSubscriptionToServers as parse } from '../src/services/remnawave/subscriptionParser';
import { resolveConnectedProfile, buildServerRuntimeFingerprint } from '../src/utils/serverIdentity';
import { serverMeasurementIdentity } from '../src/utils/serverMeasurements';
import { normalizeStoredSettings, saveSettings, loadSettings, loadSplitTunnelEntries } from '../src/services/storage';
const key='https://sub.vkarmani.com/qa-synthetic-fixture';
const config=(name:string)=>({remarks:name,outbounds:[{tag:'proxy',protocol:'vless',settings:{vnext:[{address:`${name.toLowerCase()}.example.test`,port:443,users:[{id:'00000000-0000-4000-8000-000000000001'}]}]}}]});
beforeEach(()=>{vi.stubGlobal('window',{setTimeout,clearTimeout});mocks.fetch.mockReset();mocks.json.mockReset();mocks.cache.mockReset();mocks.cache.mockResolvedValue(undefined);});
afterEach(()=>vi.unstubAllGlobals());
describe('actual subscription-client atomic refresh and generation ownership',()=>{
  it.each(['authorizeByAccessKey', 'syncProfile'] as const)('binds catalog retention and endpoint candidates to the requested key: %s', async method => {
    const client = new RemnawaveClient();
    mocks.fetch.mockResolvedValue(JSON.stringify([config('AccountA1'), config('AccountA2')]));
    await client.authorizeByAccessKey(key); mocks.fetch.mockClear();
    mocks.fetch.mockResolvedValue(JSON.stringify(config('AccountB')));
    await client[method](key + '-different');
    expect(mocks.fetch.mock.calls.every(([url]) => !url.includes('/qa-synthetic-fixture/') && !url.includes('/qa-synthetic-fixture/json'))).toBe(true);
    expect((await client.loadServers()).map(s => s.rawLabel)).toEqual(['AccountB']);
  });
  it('new-key info-only authorization does not inherit servers or metadata from the previous key', async () => {
    const client = new RemnawaveClient(); mocks.fetch.mockResolvedValue(JSON.stringify([config('A1'),config('A2')]));
    await client.authorizeByAccessKey(key);
    mocks.fetch.mockRejectedValue(new Error('synthetic Xray profile unavailable')); mocks.json.mockResolvedValue({});
    await client.authorizeByAccessKey(key + '-info');
    expect(await client.loadServers()).toEqual([]);
    expect(client.getProfileSyncInfo().rawUrl).toBeUndefined();
  });
  it('same-key full-profile fallback survives protected hydration, while unbound hydration cannot authorize retention', async () => {
    const old = parse(JSON.stringify([config('A1'),config('A2')]));
    for (const owner of [key, undefined]) {
      const client = new RemnawaveClient(); client.hydrateCachedServers(old, owner);
      mocks.fetch.mockRejectedValue(new Error('synthetic unavailable')); mocks.json.mockResolvedValue({});
      await client.authorizeByAccessKey(key);
      expect((await client.loadServers()).map(s => s.rawLabel)).toEqual(owner ? ['A1','A2'] : []);
    }
  });
  it('failed replacement key leaves the old committed catalog/session intact', async () => {
    const client = new RemnawaveClient(); mocks.fetch.mockResolvedValue(JSON.stringify(config('Committed')));
    const previous = await client.authorizeByAccessKey(key); const servers = await client.loadServers();
    mocks.fetch.mockRejectedValue(new Error('synthetic failure')); mocks.json.mockRejectedValue(new Error('synthetic info failure'));
    await expect(client.authorizeByAccessKey(key + '-failed')).rejects.toThrow();
    expect(client.getCachedSession()).toBe(previous); expect(await client.loadServers()).toEqual(servers);
  });
  it('an older native metadata acknowledgement cannot replace the newer subscription catalog', async () => {
    const client = new RemnawaveClient(); let release!: () => void;
    mocks.fetch.mockResolvedValue(JSON.stringify(config('A')));
    mocks.cache.mockImplementationOnce(() => new Promise<void>(resolve => { release = resolve; }));
    const pending = client.syncProfile(key); const rejected = expect(pending).rejects.toThrow('PROFILE_SYNC_CANCELLED');
    await vi.waitFor(() => expect(mocks.cache).toHaveBeenCalled());
    mocks.fetch.mockResolvedValue(JSON.stringify(config('B'))); const latest = await client.authorizeByAccessKey(key + '-b');
    release(); await rejected;
    expect(client.getCachedSession()).toBe(latest); expect((await client.loadServers()).map(s => s.rawLabel)).toEqual(['B']);
  });
  it('a failed different-key sync cannot return or relabel the previous account as its fallback', async () => {
    const client = new RemnawaveClient(); mocks.fetch.mockResolvedValue(JSON.stringify(config('Committed')));
    const session = await client.authorizeByAccessKey(key); const profile = client.getProfileSyncInfo(); const servers = await client.loadServers();
    mocks.fetch.mockRejectedValue(new Error('synthetic unavailable'));
    await expect(client.syncProfile(key + '-other', true)).rejects.toThrow();
    expect(client.getCachedSession()).toBe(session); expect(client.getProfileSyncInfo()).toBe(profile); expect(await client.loadServers()).toEqual(servers);
  });
  it('confirmed logout clears the old catalog so a different key cannot inherit its larger profile', async () => {
    const client = new RemnawaveClient();
    mocks.fetch.mockResolvedValue(JSON.stringify([config('OldA'), config('OldB')]));
    await client.authorizeByAccessKey(key);
    expect(await client.loadServers()).toHaveLength(2); expect(client.getCachedSession()).not.toBeNull();
    client.clearSessionCache();
    expect(await client.loadServers()).toEqual([]); expect(client.getCachedSession()).toBeNull();
    expect(client.getProfileSyncInfo()).toMatchObject({ status: 'idle', configCount: 0 });
    expect(client.getProfileSyncInfo().rawUrl).toBeUndefined();
    mocks.fetch.mockResolvedValue(JSON.stringify(config('NewAccount')));
    const session = await client.authorizeByAccessKey(key + '-different');
    expect(session.accessKey).toBe(key + '-different');
    expect((await client.loadServers()).map(s => s.rawLabel)).toEqual(['NewAccount']);
  });
  it('cache retirement revokes pending authorization and sync before either can repopulate it', async () => {
    for (const method of ['authorizeByAccessKey', 'syncProfile'] as const) {
      const client = new RemnawaveClient(); let release!: (value: string) => void;
      mocks.fetch.mockImplementationOnce(() => new Promise<string>(resolve => { release = resolve; }));
      const pending = client[method](key); const rejected = expect(pending).rejects.toThrow('PROFILE_SYNC_CANCELLED');
      client.clearSessionCache(); release(JSON.stringify(config('Stale'))); await rejected;
      expect(await client.loadServers()).toEqual([]); expect(client.getCachedSession()).toBeNull();
    }
  });
  it('revokes pending authorization as well as sync, without stale cache or fallback', async () => {
    const client = new RemnawaveClient(); let release!: (value: string) => void;
    mocks.fetch.mockImplementationOnce(() => new Promise<string>(resolve => { release = resolve; }));
    const pending = client.authorizeByAccessKey(key);
    const rejected = expect(pending).rejects.toThrow('PROFILE_SYNC_CANCELLED');
    client.invalidateProfileSync(); release(JSON.stringify(config('Stale'))); await rejected;
    expect(await client.loadServers()).toEqual([]); expect(client.getCachedSession()).toBeNull();
    expect(mocks.json).not.toHaveBeenCalled(); expect(mocks.cache).not.toHaveBeenCalled();
  });
  it('older authorization cannot overwrite a newer key or catalog', async () => {
    const client = new RemnawaveClient(); let release!: (value: string) => void;
    mocks.fetch.mockImplementationOnce(() => new Promise<string>(resolve => { release = resolve; }));
    const pending = client.authorizeByAccessKey(key); const rejected = expect(pending).rejects.toThrow('PROFILE_SYNC_CANCELLED');
    mocks.fetch.mockResolvedValue(JSON.stringify(config('New')));
    const latest = await client.authorizeByAccessKey(key + '-new'); const servers = await client.loadServers();
    release(JSON.stringify(config('Stale'))); await rejected;
    expect(client.getCachedSession()).toBe(latest); expect(await client.loadServers()).toEqual(servers);
  });
  it.each([false, true])('revokes late info fallback even when demo fallback=%s', async allowDemo => {
    const client = new RemnawaveClient(); let release!: (value: unknown) => void;
    mocks.fetch.mockRejectedValue(new Error('synthetic unavailable'));
    mocks.json.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
    const pending = client.authorizeByAccessKey(key, allowDemo); const rejected = expect(pending).rejects.toThrow('PROFILE_SYNC_CANCELLED');
    await vi.waitFor(() => expect(mocks.json).toHaveBeenCalled()); client.invalidateProfileSync(); release({}); await rejected;
    expect(client.getCachedSession()).toBeNull(); expect(await client.loadServers()).toEqual([]);
  });
  it('successful refresh/reorder preserves the measured cache; changed endpoints invalidate only themselves',async()=>{
    const client=new RemnawaveClient();mocks.fetch.mockResolvedValue(JSON.stringify([config('A'),config('B')]));
    const first=await client.syncProfile(key);const measured=first.servers.map((s,i)=>({...s,latency:47+i,latencyStatus:'ok' as const,latencyCheckedAt:new Date().toISOString(),latencyIdentity:serverMeasurementIdentity(s),latencySource:'physical-tcp' as const}));
    client.updateCachedMeasurements(measured);
    mocks.fetch.mockResolvedValue(JSON.stringify([config('B'),config('A')]));const reordered=await client.syncProfile(key);
    expect(reordered.servers.map(s=>s.latency)).toEqual([48,47]);
    mocks.fetch.mockResolvedValue(JSON.stringify([config('C'),config('A')]));const changed=await client.syncProfile(key);
    expect(changed.servers.map(s=>s.latencyStatus)).toEqual(['unchecked','ok']);expect(changed.servers[1].latency).toBe(47);
    expect(await client.loadServers()).toEqual(changed.servers);
  });
  it('commits all logical profiles in payload order after validation and preserves stable IDs under reorder',async()=>{
    const client=new RemnawaveClient();mocks.fetch.mockResolvedValue(JSON.stringify([config('A'),config('B')]));
    const one=await client.syncProfile(key);expect(one.servers.map(s=>s.sourceOrder)).toEqual([0,1]);const ids=one.servers.map(s=>s.id);
    mocks.fetch.mockResolvedValue(JSON.stringify([config('B'),config('A')]));const two=await client.syncProfile(key);expect(two.servers.map(s=>s.id)).toEqual([...ids].reverse());expect(two.servers.map(s=>s.sourceOrder)).toEqual([0,1]);
  });
  it.each(['not-json',JSON.stringify([config('A'),null]),JSON.stringify([config('A'),{outbounds:[],routing:{rules:[{outboundTag:'missing'}]}}])])('retains the complete previous cache for malformed/partial subscription %s',async text=>{
    const client=new RemnawaveClient();const old=parse(JSON.stringify([config('PreviousA'),config('PreviousB')]));client.hydrateCachedServers(old,key);mocks.fetch.mockResolvedValue(text);
    await expect(client.syncProfile(key)).rejects.toThrow();expect(await client.loadServers()).toEqual(old);
  });
  it('does not commit before native metadata stage succeeds; failure preserves previous complete list',async()=>{
    const client=new RemnawaveClient();const old=parse(JSON.stringify(config('Previous')));client.hydrateCachedServers(old,key);mocks.fetch.mockResolvedValue(JSON.stringify([config('A'),config('B')]));mocks.cache.mockRejectedValue(new Error('metadata stage failed'));
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
