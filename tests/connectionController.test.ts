import {describe,it,expect,vi} from 'vitest';
import {ConnectionController,type ConnectionPorts,type ConnectionRequest} from '../src/services/connectionController';
import type {RuntimeStatus,ConnectResult} from '../src/types/vpn';
import auto from './fixtures/xray/auto.json';
import {parseXrayJsonSubscriptionToServers as parse} from '../src/services/remnawave/subscriptionParser';
import {buildServerRuntimeFingerprint} from '../src/utils/serverIdentity';
const [a]=parse(JSON.stringify(auto));const b={...a,id:'B'};
const runtime=(active=false,revision=1):RuntimeStatus=>({bridge:'tauri',nativeInstanceId:'test',runtimeRevision:revision,coreInstalled:true,tunnelActive:active,xrayPid:active?17:undefined,launchMode:'sidecar',message:'',lastPreparedServerId:a.id,lastPreparedServerFingerprint:buildServerRuntimeFingerprint(a)});
const response=(server=a):ConnectResult=>({externalIp:'',dnsMode:'',transport:'',runtime:{...runtime(true,3),lastPreparedServerId:server.id,lastPreparedServerFingerprint:buildServerRuntimeFingerprint(server)}});
const deferred=<T,>()=>{let resolve!:(value:T)=>void;let reject!:(value:unknown)=>void;const promise=new Promise<T>((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};};
const setup=(pending=()=>false)=>{const controller=new ConnectionController(pending);const ports:ConnectionPorts={native:true,resolve:vi.fn(async server=>server),connect:vi.fn(async server=>response(server)),disconnect:vi.fn(async()=>undefined),observe:vi.fn(async()=>runtime()),disconnectRequested:()=>false,phase:vi.fn()};const request:ConnectionRequest={kind:'switch',target:b,previous:a,options:{tunnelMode:'tun'},rollbackOptions:{tunnelMode:'proxy'}};return {controller,ports,request};};
describe('one connection owner and authoritative recovery',()=>{
  it('claims before preparation, rejects double entry and confirms the exact target',async()=>{
    const {controller,ports,request}=setup();const preparing=deferred<typeof b>();ports.resolve=()=>preparing.promise;
    const first=controller.run(request,ports);expect(controller.active).toBe(true);expect(await controller.run(request,ports)).toEqual({kind:'busy'});
    preparing.resolve(b);expect(await first).toMatchObject({kind:'connected',server:{id:'B'},rolledBack:false});expect(controller.busy).toBe(false);
  });
  it('disconnect needs no server/catalog and only commits observed idle',async()=>{
    const {controller,ports}=setup();expect(await controller.run({kind:'disconnect',options:{}},ports)).toMatchObject({kind:'idle'});expect(ports.resolve).not.toHaveBeenCalled();expect(ports.disconnect).toHaveBeenCalledOnce();
  });
  it('does not stop or roll back when preparation fails',async()=>{const {controller,ports,request}=setup();ports.resolve=async()=>null;expect(await controller.run(request,ports)).toMatchObject({kind:'rejected'});expect(ports.connect).not.toHaveBeenCalled();});
  it('preserves an active old runtime after failed target start',async()=>{const {controller,ports,request}=setup();ports.connect=vi.fn().mockRejectedValue(new Error('arbitrary operation порт'));ports.observe=async()=>runtime(true);expect(await controller.run(request,ports)).toMatchObject({kind:'active'});expect(ports.connect).toHaveBeenCalledOnce();});
  it('rolls back once only from confirmed idle using the old mode',async()=>{const {controller,ports,request}=setup();ports.connect=vi.fn().mockRejectedValueOnce(new Error('failed')).mockResolvedValueOnce(response());expect(await controller.run(request,ports)).toMatchObject({kind:'connected',rolledBack:true});expect(ports.connect).toHaveBeenNthCalledWith(2,a,{tunnelMode:'proxy',reconnect:true});});
  it('pending native promise survives caller timeout and blocks rollback and new commands',async()=>{let pending=true;const {controller,ports,request}=setup(()=>pending);pending=false;ports.connect=vi.fn(async()=>{pending=true;throw new Error('timeout');});expect(await controller.run(request,ports)).toMatchObject({kind:'pending'});expect(ports.connect).toHaveBeenCalledOnce();pending=false;expect(await controller.run(request,ports)).toEqual({kind:'busy'});expect(controller.reconcile(runtime(false,2))).toBe('idle');expect(controller.busy).toBe(false);});
  it.each([null,{...runtime(),runtimeRevision:NaN},{...runtime(),xrayPid:17},{...runtime(),operation:{id:1,kind:'connect',stage:'starting',startedAt:0,deadlineAt:1}}])('unknown or partial native state never authorizes rollback',async observed=>{const {controller,ports,request}=setup();ports.connect=vi.fn().mockRejectedValue(new Error('failed'));ports.observe=async()=>observed;expect(await controller.run(request,ports)).toMatchObject({kind:'pending'});expect(ports.connect).toHaveBeenCalledOnce();});
  it('disconnect intent suppresses both preparation and rollback',async()=>{const {controller,ports,request}=setup();ports.disconnectRequested=()=>true;expect(await controller.run(request,ports)).toMatchObject({kind:'rejected'});expect(ports.connect).not.toHaveBeenCalled();ports.disconnectRequested=()=>false;ports.connect=vi.fn(async()=>{ports.disconnectRequested=()=>true;throw new Error('failed');});expect(await controller.run(request,ports)).toMatchObject({kind:'idle'});expect(ports.connect).toHaveBeenCalledOnce();});
  it('dispose rejects late completion and retains ownership until it settles',async()=>{const {controller,ports,request}=setup();const late=deferred<ConnectResult>();ports.connect=()=>late.promise;const first=controller.run(request,ports);await Promise.resolve();controller.dispose();controller.activate();expect(controller.active).toBe(true);late.resolve(response(b));expect(await first).toEqual({kind:'stale'});});
  it('rejects old revisions and retired epochs during recovery',async()=>{const {controller,ports,request}=setup();const current=runtime(false,8);controller.accept(current,current);ports.connect=vi.fn().mockRejectedValue(new Error('failed'));ports.observe=async()=>runtime(false,7);expect(await controller.run(request,ports)).toMatchObject({kind:'pending'});const next={...current,nativeInstanceId:'new',runtimeRevision:0};expect(controller.accept(current,next)).toBe(next);expect(controller.accept(next,current)).toBe(next);expect(controller.reconcile(current)).toBe('pending');});
  it('captures rollback options before asynchronous preparation',async()=>{const {controller,ports,request}=setup();const late=deferred<typeof b>();ports.resolve=()=>late.promise;ports.connect=vi.fn().mockRejectedValueOnce(new Error('failed')).mockResolvedValueOnce(response());const first=controller.run(request,ports);request.rollbackOptions!.tunnelMode='tun';late.resolve(b);await first;expect(ports.connect).toHaveBeenNthCalledWith(2,a,{tunnelMode:'proxy',reconnect:true});});
  it('does not publish a mismatched or still-running success as connected',async()=>{const {controller,ports,request}=setup();ports.connect=vi.fn().mockResolvedValue(response(a));ports.observe=async()=>runtime(true);expect(await controller.run(request,ports)).toMatchObject({kind:'active'});});
});


describe('TUN physical/route/owner failures keep the shared controller contract',()=>{
  it.each(['RUNTIME_CLEANUP_INCOMPLETE','NETWORK_BINDING_CHANGED','NETWORK_BINDING_UNCONFIRMED','CORE_PORT_CONFLICT','ROUTE_INTERFACE_CHANGED','ROUTE_JOURNAL_UNAVAILABLE','TUN_INTERFACE_NOT_READY','TUN_ROUTES_UNCONFIRMED','TUN_PROCESS_ENFORCEMENT_UNAVAILABLE'])('preserves active old runtime and performs one rollback only after authoritative idle: %s',async code=>{
    for(const active of [true,false]){
      const {controller,ports,request}=setup();
      ports.connect=vi.fn().mockRejectedValueOnce({code,category:'network',retryable:false}).mockResolvedValueOnce(response());
      ports.observe=async()=>runtime(active,2);
      const result=await controller.run(request,ports);
      expect(result).toMatchObject(active?{kind:'active'}:{kind:'connected',rolledBack:true});
      if(active) expect(result).toMatchObject({error:{code}});
      expect(ports.connect).toHaveBeenCalledTimes(active?1:2);
      expect(ports.disconnect).not.toHaveBeenCalled();
      expect(controller.busy).toBe(false);
    }
  });
  it('does not race a queued disconnect or retry after cancelled TUN setup',async()=>{
    const {controller,ports,request}=setup();const pending=deferred<ConnectResult>();
    ports.connect=vi.fn(()=>pending.promise);const first=controller.run(request,ports);
    await Promise.resolve();ports.disconnectRequested=()=>true;
    expect(await controller.run({kind:'disconnect',options:{}},ports)).toEqual({kind:'busy'});
    pending.reject({code:'OPERATION_CANCELLED',category:'network',retryable:false});
    expect(await first).toMatchObject({kind:'idle'});expect(ports.connect).toHaveBeenCalledOnce();
    expect(await controller.run({kind:'disconnect',options:{}},ports)).toMatchObject({kind:'idle'});
    expect(ports.disconnect).toHaveBeenCalledOnce();
  });
});
