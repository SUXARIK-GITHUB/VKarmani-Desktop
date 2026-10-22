import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const mocks=vi.hoisted(()=>({fetch:vi.fn(),cache:vi.fn()}));
vi.mock('../src/services/runtime',async original=>({...await original<typeof import('../src/services/runtime')>(),fetchRemoteSubscription:mocks.fetch,cacheNativeProfileSync:mocks.cache}));
import { RemnawaveClient } from '../src/services/remnawave';
import { parseSubscriptionUserinfo, withSubscriptionUserinfo } from '../src/utils/subscriptionMetadata';
import type { RemnawaveSession } from '../src/types/vpn';

const key='https://sub.vkarmani.com/qa-synthetic-metadata';
const text=JSON.stringify({remarks:'Germany',outbounds:[{tag:'proxy',protocol:'vless',settings:{vnext:[{address:'node.example.test',port:443,users:[{id:'11111111-1111-4111-8111-111111111111'}]}]}}]});
const empty=parseSubscriptionUserinfo(null);
const session:RemnawaveSession={accessKey:'synthetic',userId:'synthetic',displayName:'Test',loginHint:'',deviceLimit:null,source:'public-api',plan:{title:'Subscription',expiresAt:'—',trafficUsedGb:null,trafficLimitGb:null,devices:null}};
beforeEach(()=>{vi.stubGlobal('window',{setTimeout,clearTimeout});mocks.fetch.mockReset();mocks.cache.mockReset();mocks.cache.mockResolvedValue(undefined);});
afterEach(()=>vi.unstubAllGlobals());

describe('R33/R34 exact subscription-userinfo contract',()=>{
  it('preserves uint64 byte counters without Number rounding and distinguishes real zero from missing',()=>{
    const info=parseSubscriptionUserinfo('upload=0; download=18446744073709551615; total=0; expire=0');
    expect(info.download).toBe('18446744073709551615');
    const mapped=withSubscriptionUserinfo(session,info);
    expect(mapped.plan).toMatchObject({downloadBytes:'18446744073709551615',totalBytes:'0',expiresAtUnix:'0',devices:null});
    expect(mapped.deviceLimit).toBeNull();expect(withSubscriptionUserinfo(session,empty).plan.trafficUsedGb).toBeNull();
  });
  it.each(['expire=-1','expire=1; expire=0','upload=NaN','download=1.5','total=18446744073709551616','upload=+1','upload=0x10','expire','upload=1=2','upload=' ,'x'.repeat(2049)])('rejects malformed or ambiguous metadata %s',header=>{
    expect(()=>parseSubscriptionUserinfo(header)).toThrow('SUBSCRIPTION_USERINFO_INVALID');
  });
  it('accepts future unknown header fields without treating them as device counts',()=>{
    const info=parseSubscriptionUserinfo('future=value; deviceLimit=3; upload=00012');
    expect(info).toEqual({upload:'12',download:null,total:null,expire:null});
  });
  it('uses confirmed expiry only and rejects expired subscriptions',()=>{
    expect(()=>withSubscriptionUserinfo(session,parseSubscriptionUserinfo('expire=1'),2000)).toThrow('SUBSCRIPTION_EXPIRED');
    expect(withSubscriptionUserinfo(session,parseSubscriptionUserinfo('expire=0'),2000).plan.expiresAtUnix).toBe('0');
    expect(withSubscriptionUserinfo(session,parseSubscriptionUserinfo('expire=2000000000'),2000).plan.expiresAt).toBe('2033-05-18T03:33:20.000Z');
  });
});

describe('R36 validated login response handoff and generations',()=>{
  it('does not let a later manual refresh reuse an already displayed login response',async()=>{
    mocks.fetch.mockResolvedValue({text,userinfo:empty});const client=new RemnawaveClient();
    await client.authorizeByAccessKey(key,false);await client.loadServers();await client.syncProfile(key,false);
    expect(mocks.fetch).toHaveBeenCalledTimes(2);
  });
  it('cancels an older profile refresh when a new authorization begins',async()=>{
    let release!:(value:unknown)=>void;
    mocks.fetch.mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));
    mocks.fetch.mockResolvedValue({text,userinfo:empty});const client=new RemnawaveClient();
    const old=client.syncProfile(key,false).catch(error=>error);
    const newer=await client.authorizeByAccessKey(key+'-new',false);
    release({text:text.replace('node.example.test','old.example.test'),userinfo:empty});
    expect(await old).toMatchObject({message:'PROFILE_SYNC_CANCELLED'});
    expect(client.getCachedSession()).toBe(newer);expect((await client.loadServers())[0].host).toBe('node.example.test');
    await expect(client.syncProfile(key,false)).rejects.toThrow('PROFILE_SESSION_MISMATCH');
  });
  it('never retains a larger previous account profile for a new account with fewer nodes',async()=>{
    const config=JSON.parse(text);mocks.fetch.mockResolvedValueOnce({text:JSON.stringify([config,{...config,remarks:'Other',outbounds:[{...config.outbounds[0],settings:{vnext:[{address:'old.example.test',port:443,users:[{id:'11111111-1111-4111-8111-111111111111'}]}]}}]}]),userinfo:empty});
    const client=new RemnawaveClient();await client.authorizeByAccessKey(key,false);
    expect(await client.loadServers()).toHaveLength(2);
    mocks.fetch.mockResolvedValue({text:JSON.stringify({rawHosts:[{protocol:'vless',host:'new.example.test',port:443,uuid:'11111111-1111-4111-8111-111111111111',security:'tls',name:'NewAccount'}]}),userinfo:empty});await client.authorizeByAccessKey(key+'-other',false);
    expect(await client.loadServers()).toHaveLength(1);
  });
  it('uses one validated body/header pair for authorization and the immediately following sync, then fetches fresh',async()=>{
    mocks.fetch.mockResolvedValue({text,userinfo:parseSubscriptionUserinfo('upload=0; download=1024; total=2048; expire=0')});
    const client=new RemnawaveClient();const authorized=await client.authorizeByAccessKey(key,false);
    expect(authorized.plan).toMatchObject({downloadBytes:'1024',totalBytes:'2048',devices:null});
    expect(authorized.deviceLimit).toBeNull();expect(mocks.fetch).toHaveBeenCalledTimes(1);
    const synced=await client.syncProfile(key,false);expect(synced.servers).toHaveLength(1);expect(mocks.fetch).toHaveBeenCalledTimes(1);
    await client.syncProfile(key,false);expect(mocks.fetch).toHaveBeenCalledTimes(2);
  });
  it('does not fabricate traffic/device values for a valid response without headers',async()=>{
    mocks.fetch.mockResolvedValue({text,userinfo:empty});
    const result=await new RemnawaveClient().authorizeByAccessKey(key,false);
    expect(result.plan).toMatchObject({trafficUsedGb:null,trafficLimitGb:null,devices:null,expiresAt:'—'});expect(result.deviceLimit).toBeNull();
  });
  it('does not let an older login overwrite a newer authorization',async()=>{
    let release!:(value:unknown)=>void;
    mocks.fetch.mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));
    mocks.fetch.mockResolvedValue({text,userinfo:empty});
    const client=new RemnawaveClient();const old=client.authorizeByAccessKey(key,false).catch(error=>error);
    const newer=await client.authorizeByAccessKey(key+'-new',false);
    release({text,userinfo:empty});expect(await old).toMatchObject({message:'AUTHORIZATION_CANCELLED'});
    expect(client.getCachedSession()).toBe(newer);expect(mocks.fetch).toHaveBeenCalledTimes(2);
  });
  it('invalidates an in-flight authorization without publishing its stale result',async()=>{
    let release!:(value:unknown)=>void;
    mocks.fetch.mockImplementation(()=>new Promise(resolve=>{release=resolve;}));
    const client=new RemnawaveClient();const pending=client.authorizeByAccessKey(key,false).catch(error=>error);
    client.invalidateProfileSync();release({text,userinfo:empty});expect(await pending).toMatchObject({message:'AUTHORIZATION_CANCELLED'});
    expect(client.getCachedSession()).toBeNull();
  });
});
