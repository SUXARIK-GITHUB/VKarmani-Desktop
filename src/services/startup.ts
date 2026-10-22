import packageJson from '../../package.json';

export const STARTUP_CODES = ['STARTUP_NORMAL','STARTUP_CRASH_LOOP','STARTUP_SAFE_MODE_REQUESTED','STARTUP_GUARD_INVALID','STARTUP_GUARD_UNAVAILABLE','STARTUP_GUARD_BUSY','STARTUP_GUARD_WRITE_FAILED','STARTUP_CLOCK_UNTRUSTED','STARTUP_PLATFORM_UNSUPPORTED','STARTUP_NOT_READY','STARTUP_TOKEN_STALE','STARTUP_SAFE_MODE_REQUIRED','STARTUP_NOT_STABLE_YET','STARTUP_RUNTIME_PRESENT','STARTUP_STATUS_UNAVAILABLE','STARTUP_OPERATION_FAILED'] as const;
export type StartupCode = typeof STARTUP_CODES[number];
export interface StartupStatus {
  schemaVersion:1; mode:'normal'|'safe'; code:StartupCode; appVersion:string;
  failures:number; attemptId:string|null; retryAllowed:boolean; readyAfterMs:number;
}
type Invoke = <T>(command:string,args?:Record<string,unknown>)=>Promise<T>;
export function nativeStartupAvailable(){return typeof window!=='undefined'&&Boolean((window as unknown as {__TAURI_INTERNALS__?:unknown}).__TAURI_INTERNALS__);}
export function safeStartupStatus(code:StartupCode='STARTUP_STATUS_UNAVAILABLE'):StartupStatus {
  return {schemaVersion:1,mode:'safe',code,appVersion:packageJson.version,failures:0,attemptId:null,retryAllowed:false,readyAfterMs:0};
}
export function startupErrorCode(error:unknown):StartupCode {
  try{if(error&&typeof error==='object'&&'code' in error&&STARTUP_CODES.includes(error.code as StartupCode))return error.code as StartupCode;}catch{/* Untrusted error accessors must not break recovery. */}
  return 'STARTUP_OPERATION_FAILED';
}
export function validateStartupStatus(value:unknown):StartupStatus {
  if(!value||typeof value!=='object'||Array.isArray(value))throw Error('STARTUP_STATUS_UNAVAILABLE');
  const v=value as Record<string,unknown>;
  const fields=['schemaVersion','mode','code','appVersion','failures','attemptId','retryAllowed','readyAfterMs'];
  if(Object.keys(v).length!==fields.length||Object.keys(v).some(k=>!fields.includes(k))
    ||v.schemaVersion!==1||!['normal','safe'].includes(String(v.mode))||!STARTUP_CODES.includes(v.code as StartupCode)
    ||v.appVersion!==packageJson.version||typeof v.failures!=='number'||!Number.isInteger(v.failures)||v.failures<0||v.failures>3
    ||!(v.attemptId===null||typeof v.attemptId==='string'&&/^[a-f0-9]{48}$/i.test(v.attemptId))
    ||typeof v.retryAllowed!=='boolean'||typeof v.readyAfterMs!=='number'||!Number.isInteger(v.readyAfterMs)||v.readyAfterMs<0||v.readyAfterMs>30000
    ||v.mode==='normal'&&(v.code!=='STARTUP_NORMAL'||v.attemptId===null||v.retryAllowed)
    ||v.mode==='safe'&&(v.code==='STARTUP_NORMAL'||v.retryAllowed&&v.attemptId===null))throw Error('STARTUP_STATUS_UNAVAILABLE');
  return {schemaVersion:1,mode:v.mode as StartupStatus['mode'],code:v.code as StartupCode,appVersion:v.appVersion as string,
    failures:v.failures as number,attemptId:v.attemptId as string|null,retryAllowed:v.retryAllowed,readyAfterMs:v.readyAfterMs as number};
}
const invoke:Invoke=async<T>(command:string,args?:Record<string,unknown>)=>{
  const api=await import('@tauri-apps/api/core');return api.invoke<T>(command,args);
};
export function createStartupClient(transport:Invoke){
  const token=(attemptId:string|null)=>{if(!attemptId||!/^[a-f0-9]{48}$/i.test(attemptId))throw Error('STARTUP_TOKEN_STALE');return {attemptId};};
  return {
    read:async()=>{
      let timer:ReturnType<typeof setTimeout>|undefined;
      // Only the read-only status has a deadline. Admission/retry writes must
      // never be reported as cancelled while an unknown native write continues.
      try{return validateStartupStatus(await Promise.race([
        transport<unknown>('startup_status'),
        new Promise<never>((_,reject)=>{timer=setTimeout(()=>reject({code:'STARTUP_STATUS_UNAVAILABLE'}),5000);})
      ]));}finally{if(timer!==undefined)clearTimeout(timer);}
    },
    admit:(id:string|null)=>transport<void>('startup_admit_app',token(id)),
    ready:(id:string|null)=>transport<void>('startup_acknowledge_ready',token(id)),
    retry:(id:string|null)=>transport<void>('startup_retry_next_launch',token(id)),
    exit:()=>transport<void>('startup_exit')
  };
}
export const startupClient=createStartupClient(invoke);
