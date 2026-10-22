import type {ConnectResult,RuntimeStatus,VpnServer} from '../types/vpn';
import type {remnawaveClient} from './remnawave';
import {buildServerRuntimeFingerprint} from '../utils/serverIdentity';
import {runtimeConfirmsTargetServer} from './connectionGuards';
import {NativeOperationError} from '../utils/nativeErrors';
import {acceptRuntimeSnapshot,validNativeRuntimeSnapshot} from '../utils/runtimeSnapshot';

export type ConnectionOptions=NonNullable<Parameters<typeof remnawaveClient.connect>[1]>;
export type ConnectionPhase='preparing'|'connecting'|'disconnecting'|'rollback'|'reconciling';
export interface ConnectionPorts {
  native:boolean;
  resolve:(server:VpnServer|null)=>Promise<VpnServer|null>;
  connect:(server:VpnServer,options:ConnectionOptions)=>Promise<ConnectResult>;
  disconnect:()=>Promise<void>;
  observe:()=>Promise<RuntimeStatus|null>;
  disconnectRequested:()=>boolean;
  phase:(phase:ConnectionPhase)=>void;
}
export interface ConnectionRequest {
  kind:'connect'|'switch'|'disconnect';target?:VpnServer|null;previous?:VpnServer|null;
  options:ConnectionOptions;rollbackOptions?:ConnectionOptions;
}
export type ConnectionOutcome=
  |{kind:'busy'}|{kind:'stale'}
  |{kind:'connected';server:VpnServer;response:ConnectResult;rolledBack:boolean;error?:unknown}
  |{kind:'active'|'idle'|'pending';runtime:RuntimeStatus|null;error?:unknown}
  |{kind:'rejected';error:unknown};
const failure=(code:string)=>new NativeOperationError(code,'network',false,'Connection state requires verification.');

/** One owner for connect/switch/mode/IP/rules/rollback/disconnect. No timers can
 * release an owner and no localized error text can authorize a network action. */
export class ConnectionController {
  private sequence=0;
  private owner:number|null=null;
  private enabled=true;
  private needsObservation=false;
  private retiredInstances=new Set<string>();
  private observed:RuntimeStatus|null=null;
  constructor(private nativePending:()=>boolean=()=>false){}
  get generation(){return this.sequence;}
  get active(){return this.owner!==null;}
  get busy(){return this.active||this.needsObservation||this.nativePending();}
  activate(){this.enabled=true;}
  dispose(){this.enabled=false;this.sequence++;}
  invalidate(){return ++this.sequence;}
  current(id:number){return this.enabled&&id===this.sequence;}
  accepts(current:RuntimeStatus,next:RuntimeStatus){
    return (next.bridge!=='tauri'||validNativeRuntimeSnapshot(next))
      &&!this.retiredInstances.has(next.nativeInstanceId??'')
      &&!(current.nativeInstanceId&&next.nativeInstanceId&&current.nativeInstanceId!==next.nativeInstanceId&&this.retiredInstances.size>=32)
      &&acceptRuntimeSnapshot(current,next)===next;
  }
  accept(current:RuntimeStatus,next:RuntimeStatus){
    if(!this.accepts(current,next))return current;
    if(current.nativeInstanceId&&next.nativeInstanceId&&current.nativeInstanceId!==next.nativeInstanceId){
      // Bounded fail-closed history: repeated instance churn requires a new UI
      // session rather than forgetting a retired identity and resurrecting it.
      if(this.retiredInstances.size>=32)return current;
      this.retiredInstances.add(current.nativeInstanceId);
    }
    this.observed=next;return next;
  }
  reconcile(runtime:RuntimeStatus|null):'pending'|'active'|'idle'{
    if(this.active||this.nativePending()||!runtime||runtime.bridge==='tauri'&&!validNativeRuntimeSnapshot(runtime)||runtime.operation||(!runtime.tunnelActive&&runtime.xrayPid)
      ||this.observed&&!this.accepts(this.observed,runtime))return 'pending';
    this.accept(this.observed??runtime,runtime);
    this.needsObservation=false;
    return runtime.tunnelActive?'active':'idle';
  }
  async run(request:ConnectionRequest,ports:ConnectionPorts):Promise<ConnectionOutcome>{
    if(!this.enabled||this.busy)return {kind:'busy'};
    const id=++this.sequence;this.owner=id;
    let submitted=false;
    const isCurrent=()=>this.current(id);
    const observe=async()=>{
      const wasPending=this.nativePending();
      try{
        const next=await ports.observe();
        if(wasPending)return null;
        if(!next||this.observed&&!this.accepts(this.observed,next))return null;
        if(next.bridge==='tauri'&&!validNativeRuntimeSnapshot(next))return null;
        return this.accept(this.observed??next,next);
      }catch{return null;}
    };
    const classify=(runtime:RuntimeStatus|null):'pending'|'active'|'idle'=>{
      if(this.nativePending()||!runtime||ports.native&&!validNativeRuntimeSnapshot(runtime)||runtime.operation||!runtime.tunnelActive&&runtime.xrayPid)return 'pending';
      return runtime.tunnelActive?'active':'idle';
    };
    const confirmed=(response:ConnectResult,server:VpnServer)=>!ports.native||Boolean(response.runtime&&validNativeRuntimeSnapshot(response.runtime)
      &&!response.runtime.operation&&!this.nativePending()&&(!this.observed||this.accepts(this.observed,response.runtime))
      &&runtimeConfirmsTargetServer(response.runtime,server.id,buildServerRuntimeFingerprint(server)));
    try{
      request={...request,options:structuredClone(request.options),rollbackOptions:request.rollbackOptions?structuredClone(request.rollbackOptions):undefined,
        previous:request.previous?structuredClone(request.previous):request.previous};
      if(request.kind==='disconnect'){
        ports.phase('disconnecting');submitted=true;
        await ports.disconnect();
        if(!isCurrent())return {kind:'stale'};
        const runtime=await observe();if(!isCurrent())return {kind:'stale'};
        const kind=classify(runtime);this.needsObservation=kind==='pending';
        return {kind,runtime,...(kind==='active'?{error:failure('RUNTIME_DISCONNECT_FAILED')}:{})};
      }
      ports.phase('preparing');
      const target=await ports.resolve(request.target??null);
      if(!isCurrent())return {kind:'stale'};
      if(ports.disconnectRequested())return {kind:'rejected',error:failure('OPERATION_CANCELLED')};
      if(!target?.runtimeTemplate)return {kind:'rejected',error:failure('PROFILE_SERVER_MISSING')};
      if(request.target&&request.target.id!==target.id)return {kind:'rejected',error:failure('RUNTIME_IDENTITY_UNCONFIRMED')};
      ports.phase('connecting');submitted=true;
      // Request values are captured by the caller before asynchronous preparation.
      const response=await ports.connect(target,{...request.options,reconnect:request.kind==='switch'||request.options.reconnect});
      if(!isCurrent())return {kind:'stale'};
      if(!confirmed(response,target))throw failure('RUNTIME_IDENTITY_UNCONFIRMED');
      return {kind:'connected',server:target,response,rolledBack:false};
    }catch(error){
      if(!isCurrent())return {kind:'stale'};
      if(!submitted)return {kind:'rejected',error};
      ports.phase('reconciling');
      const runtime=await observe();if(!isCurrent())return {kind:'stale'};
      const kind=classify(runtime);
      if(kind!=='idle'){
        this.needsObservation=kind==='pending';return {kind,runtime,error};
      }
      if(request.kind==='switch'&&request.previous?.runtimeTemplate&&!ports.disconnectRequested()){
        try{
          ports.phase('rollback');
          const response=await ports.connect(request.previous,{...(request.rollbackOptions??request.options),reconnect:true});
          if(!isCurrent())return {kind:'stale'};
          if(!confirmed(response,request.previous))throw failure('RUNTIME_IDENTITY_UNCONFIRMED');
          return {kind:'connected',server:request.previous,response,rolledBack:true,error};
        }catch(rollbackError){
          if(!isCurrent())return {kind:'stale'};
          const finalRuntime=await observe();if(!isCurrent())return {kind:'stale'};
          const finalKind=classify(finalRuntime);this.needsObservation=finalKind==='pending';
          return {kind:finalKind,runtime:finalRuntime,error:rollbackError};
        }
      }
      return {kind:'idle',runtime,error};
    }finally{
      if(this.owner===id)this.owner=null;
    }
  }
}
