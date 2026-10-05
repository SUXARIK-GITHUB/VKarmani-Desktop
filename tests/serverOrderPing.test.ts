import { describe, expect, it, vi } from 'vitest';
import type { VpnServer, ConnectivityProbe } from '../src/types/vpn';
import { rankServersForDisplay } from '../src/utils/serverSorting';
import { applyPingBatch, runPingBatch, PING_CONCURRENCY, PING_BATCH_TIMEOUT_MS, PING_ITEM_TIMEOUT_MS } from '../src/utils/pingBatch';
import { normalizeStoredSettings } from '../src/services/storage';
import { decodeProfileCache, encodeProfileCache } from '../src/services/profileCache';

const server = (id: string, sourceOrder = 0, latency: number | null = null): VpnServer => ({ id, sourceOrder, country:id, city:'', flag:'', load:0, protocol:'Xray', host:'example.test', port:443, latency, latencyStatus: latency ? 'ok' : 'failed' });
const probe = (latencyMs = 10): ConnectivityProbe => ({ success:true, latencyMs, checkedAt:'test', httpPortOpen:false, socksPortOpen:false, message:'synthetic' });
const order = (items: VpnServer[], enabled = false, favorites: string[] = []) => rankServersForDisplay(items, 'auto', favorites, enabled).map(s => s.id);

describe('logical source order and persistent sort preference', () => {
  const items = [server('A',0,30),server('B',1,20),server('C',2),server('D',3,10)];
  it('defaults absent/invalid setting to OFF for fresh and upgraded settings', () => {
    for (const value of [null,{}, {sortServersByPing:'true'}]) expect(normalizeStoredSettings(value).sortServersByPing).toBe(false);
    expect(normalizeStoredSettings({sortServersByPing:true}).sortServersByPing).toBe(true);
    expect(normalizeStoredSettings({sortServersByPing:false}).sortServersByPing).toBe(false);
  });
  it('OFF uses A B C D, ON D B A C, and toggle restores source order without fetch', () => {
    expect(order(items)).toEqual(['A','B','C','D']); expect(order(items,true)).toEqual(['D','B','A','C']); expect(order(items)).toEqual(['A','B','C','D']);
  });
  it('preserves favorite pin order in both modes and stable source ties', () => {
    expect(order(items,false,['C','B'])).toEqual(['C','B','A','D']); expect(order(items,true,['C','B'])).toEqual(['C','B','D','A']);
    expect(order([server('B',1,20),server('A',0,20)],true)).toEqual(['A','B']);
  });
  it('new refresh source indexes replace old order, IDs/favorites survive reorder', () => {
    const refreshed = [...items].reverse().map((s, sourceOrder) => ({...s,sourceOrder}));
    expect(order(refreshed)).toEqual(['D','C','B','A']); expect(order(refreshed,false,['B'])).toEqual(['B','D','C','A']);
  });
  it('Auto is one logical entry, source order survives encrypted cache codec', () => {
    const logical = [server('A',0,40),{...server('Auto',1,10),runtimeTemplate:{family:'xray' as const,protocol:'vless' as const,outbound:{},profileKind:'auto' as const,memberTags:['physical1','physical2']}},server('B',2,20)];
    const loaded = decodeProfileCache(encodeProfileCache(logical)) as VpnServer[];
    expect(order(loaded)).toEqual(['A','Auto','B']); expect(order(loaded,true)).toEqual(['Auto','B','A']); expect(loaded).toHaveLength(3);
  });
});

describe('bounded ping batch and atomic generation commit', () => {
  it.each([0,1,2,11,50,100,500])('runs %i logical entries concurrently within four workers', async count => {
    const targets=Array.from({length:count},(_,i)=>server(String(i),i)); let active=0,peak=0,ticks=0;
    const timer=setInterval(()=>ticks++,1); const memoryBefore=process.memoryUsage().heapUsed; const started=performance.now();
    const result=await runPingBatch(targets,async()=>{active++;peak=Math.max(peak,active);await new Promise(r=>setTimeout(r,2));active--;return probe();},new AbortController().signal);
    clearInterval(timer);
    expect(result.success).toBe(count);expect(peak).toBeLessThanOrEqual(PING_CONCURRENCY);expect(active).toBe(0);
    if(count>1)expect(peak).toBe(Math.min(count,PING_CONCURRENCY));if(count>10)expect(ticks).toBeGreaterThan(0);
    console.log(JSON.stringify({pingSyntheticCount:count,durationMs:Math.round(performance.now()-started),peakWorkers:peak,eventLoopTicks:ticks,heapDelta:process.memoryUsage().heapUsed-memoryBefore}));
  });
  it('publishes nothing while individual results settle; commits every result once', async () => {
    const targets=[server('A',0),server('B',1)];const resolvers:((p:ConnectivityProbe)=>void)[]=[];
    const pending=runPingBatch(targets,()=>new Promise(r=>resolvers.push(r)),new AbortController().signal);
    await Promise.resolve();resolvers[1](probe(5));await Promise.resolve();expect(targets.every(s=>s.latency===null)).toBe(true);
    resolvers[0](probe(30));const batch=await pending;const committed=applyPingBatch(targets,targets,batch);
    expect(committed.map(s=>s.latency)).toEqual([30,5]);expect(order(committed)).toEqual(['A','B']);expect(order(committed,true)).toEqual(['B','A']);
  });
  it('keeps successful results when other entries reject or are unreachable', async () => {
    const targets=[server('ok'),server('bad'),server('closed')];
    const batch=await runPingBatch(targets,async s=>{if(s.id==='bad')throw new Error('closed');return s.id==='closed'?{...probe(),success:false}:probe(11);},new AbortController().signal);
    expect(batch).toMatchObject({success:1,unreachable:2,timeout:0,cancelled:0});
  });
  it('ignores old results after refresh/replacement even if the same IDs remain', async () => {
    const original=[server('same',0)];const batch=await runPingBatch(original,async()=>probe(),new AbortController().signal);
    const replacement=[{...server('same',0),host:'new.example.test'}];expect(applyPingBatch(replacement,original,batch)).toBe(replacement);
  });
  it('cancels without starting queued entries, cleans listeners/timers and cannot commit cancelled latencies', async () => {
    vi.useFakeTimers({toFake:['setTimeout','clearTimeout','performance']});
    try {
      const controller=new AbortController();let called=0,settled=false;const targets=Array.from({length:11},(_,i)=>server(String(i),i));
      const pending=runPingBatch(targets,()=>{called++;return new Promise(()=>{});},controller.signal).then(batch=>{settled=true;return batch;});
      await Promise.resolve();controller.abort();await Promise.resolve();expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(PING_ITEM_TIMEOUT_MS);const batch=await pending;
      expect(called).toBe(4);expect(batch.cancelled).toBe(11);expect(applyPingBatch(targets,targets,batch)).toEqual(targets);expect(vi.getTimerCount()).toBe(0);
    } finally {vi.useRealTimers();}
  });
  it('bounds all-timeout batches and marks unstarted targets without unbounded native admission', async () => {
    vi.useFakeTimers({toFake:['setTimeout','clearTimeout','performance']});
    try {const targets=Array.from({length:500},(_,i)=>server(String(i),i));let called=0;const pending=runPingBatch(targets,()=>{called++;return new Promise(()=>{});},new AbortController().signal);await vi.advanceTimersByTimeAsync(PING_BATCH_TIMEOUT_MS);const batch=await pending;expect(batch.timeout).toBe(500);expect(batch.durationMs).toBeLessThanOrEqual(PING_BATCH_TIMEOUT_MS);expect(called).toBe(28);expect(vi.getTimerCount()).toBe(0);}finally{vi.useRealTimers();}
  });
  it('setting toggle during batch changes final display only, never source indices/selection', async () => {
    const targets=[server('A',0),server('B',1)];const batch=await runPingBatch(targets,async s=>probe(s.id==='A'?50:10),new AbortController().signal);const done=applyPingBatch(targets,targets,batch);expect(order(done,true)).toEqual(['B','A']);expect(order(done)).toEqual(['A','B']);expect(done.map(s=>s.sourceOrder)).toEqual([0,1]);
  });
});
