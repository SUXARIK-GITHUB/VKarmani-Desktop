import type{RuntimeStatus}from'../types/vpn';
export function acceptRuntimeSnapshot(current:RuntimeStatus,next:RuntimeStatus):RuntimeStatus{
 if(next.bridge==='tauri'&&(!next.nativeInstanceId||typeof next.runtimeRevision!=='number'))return current;
 if(current.nativeInstanceId&&current.nativeInstanceId===next.nativeInstanceId&&typeof current.runtimeRevision==='number'&&typeof next.runtimeRevision==='number'&&next.runtimeRevision<current.runtimeRevision)return current;
 return next;
}
export function connectionFailureState(runtime:RuntimeStatus|null,attempt:number,currentAttempt:number,disconnectPending=false):'stale'|'unknown'|'pending'|'active'|'idle'{
 if(attempt!==currentAttempt)return 'stale';
 if(!runtime||(runtime.bridge==='tauri'&&(!runtime.nativeInstanceId||typeof runtime.runtimeRevision!=='number')))return 'unknown';
 if(runtime.operation)return 'pending';
 if(disconnectPending&&!runtime.tunnelActive)return 'idle';
 return runtime.tunnelActive?'active':'idle';
}
