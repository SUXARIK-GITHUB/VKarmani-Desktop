import type{RuntimeStatus}from'../types/vpn';
export function validNativeRuntimeSnapshot(runtime:RuntimeStatus):boolean{
 return runtime.bridge==='tauri'&&typeof runtime.nativeInstanceId==='string'&&runtime.nativeInstanceId.length>0&&runtime.nativeInstanceId.length<=128&&!/[\u0000-\u001f\u007f]/.test(runtime.nativeInstanceId)
  &&Number.isSafeInteger(runtime.runtimeRevision)&&runtime.runtimeRevision!>=0&&typeof runtime.tunnelActive==='boolean'
  &&(!runtime.tunnelActive||Number.isSafeInteger(runtime.xrayPid)&&runtime.xrayPid!>0)
  &&(runtime.xrayPid==null||Number.isSafeInteger(runtime.xrayPid)&&runtime.xrayPid>0);
}
export function acceptRuntimeSnapshot(current:RuntimeStatus,next:RuntimeStatus):RuntimeStatus{
 if(next.bridge==='tauri'&&(!next.nativeInstanceId||!Number.isSafeInteger(next.runtimeRevision)||next.runtimeRevision!<0))return current;
 if(current.nativeInstanceId&&current.nativeInstanceId===next.nativeInstanceId&&typeof current.runtimeRevision==='number'&&typeof next.runtimeRevision==='number'&&next.runtimeRevision<current.runtimeRevision)return current;
 return next;
}
export function connectionFailureState(runtime:RuntimeStatus|null,attempt:number,currentAttempt:number,disconnectPending=false):'stale'|'unknown'|'pending'|'active'|'idle'{
 if(attempt!==currentAttempt)return 'stale';
 if(!runtime||(runtime.bridge==='tauri'&&(!runtime.nativeInstanceId||!Number.isSafeInteger(runtime.runtimeRevision)||runtime.runtimeRevision!<0)))return 'unknown';
 if(runtime.operation)return 'pending';
 if(disconnectPending&&!runtime.tunnelActive)return 'idle';
 return runtime.tunnelActive?'active':'idle';
}
