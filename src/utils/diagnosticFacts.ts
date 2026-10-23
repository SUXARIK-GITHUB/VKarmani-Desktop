import type {ConnectFailureObservation,DiagnosticFacts,DiagnosticPort,RepairReceipt} from '../types/vpn';
import {isPublicNativeCode,publicFailureDetails} from './nativeErrors';
const receiptCodes=new Set(['REPAIR_STARTED','REPAIR_COMPLETED','REPAIR_PROXY_UNCONFIRMED','REPAIR_PARTIAL_ROUTES_UNCONFIRMED','REPAIR_ROUTES_UNCONFIRMED','REPAIR_RUNTIME_PRESENT','REPAIR_BUSY','REPAIR_EXECUTION_UNCONFIRMED']);
/** Fixed public schema only: never spread an IPC object into a support bundle. */
export function publicDiagnosticFacts(value:unknown):DiagnosticFacts|null{
  try{
    if(!value||typeof value!=='object')return null;const v=value as Record<string,unknown>;
    const pick=(key:string,allowed:string[])=>typeof v[key]==='string'&&allowed.includes(v[key] as string)?v[key] as string:'unavailable';
    if(!Number.isSafeInteger(v.checkedAtUnixMs)||Number(v.checkedAtUnixMs)<0||Number(v.checkedAtUnixMs)>8640000000000000)return null;
    const receipts:RepairReceipt[]=[];
    if(Array.isArray(v.repairHistory))for(const item of v.repairHistory.slice(-32)){
      if(!item||typeof item!=='object')continue;const r=item as Record<string,unknown>;
      if(!Number.isSafeInteger(r.atUnixMs)||Number(r.atUnixMs)<0||Number(r.atUnixMs)>8640000000000000||typeof r.code!=='string'||!receiptCodes.has(r.code)||typeof r.restoreProxy!=='boolean'||!Number.isInteger(r.routeCount)||Number(r.routeCount)<0||Number(r.routeCount)>4)continue;
      receipts.push({atUnixMs:Number(r.atUnixMs),code:r.code,restoreProxy:r.restoreProxy,routeCount:Number(r.routeCount)});
    }
    let ports:DiagnosticPort[]|undefined;
    if(Array.isArray(v.ports)&&v.ports.length===3){
      const seen=new Set<number>();const parsed:DiagnosticPort[]=[];
      for(const raw of v.ports){
        if(!raw||typeof raw!=='object')break;const p=raw as Record<string,unknown>;
        if(typeof p.port!=='number'||![10808,10809,10810].includes(p.port)||seen.has(p.port)||typeof p.state!=='string'||!['free','owned','foreign','unconfirmed','unavailable'].includes(p.state))break;
        seen.add(p.port);parsed.push({port:p.port as DiagnosticPort['port'],state:p.state as DiagnosticPort['state']});
      }
      if(parsed.length===3)ports=parsed.sort((a,b)=>a.port-b.port);
    }
    return {checkedAtUnixMs:Number(v.checkedAtUnixMs),ports,lastConnectFailure:publicConnectFailure(v.lastConnectFailure),tunInterface:pick('tunInterface',['ready','not-applicable']) as DiagnosticFacts['tunInterface'],resourceIntegrity:pick('resourceIntegrity',['verified','mismatch']) as DiagnosticFacts['resourceIntegrity'],
      storageMetadata:pick('storageMetadata',['present','missing']) as DiagnosticFacts['storageMetadata'],logsMetadata:pick('logsMetadata',['present','missing']) as DiagnosticFacts['logsMetadata'],
      elevation:pick('elevation',['elevated','standard']) as DiagnosticFacts['elevation'],repairHistory:receipts,
      repairHistoryStatus:pick('repairHistoryStatus',['available']) as DiagnosticFacts['repairHistoryStatus']};
  }catch{return null;}
}
export function publicConnectFailure(value:unknown):ConnectFailureObservation|undefined{
  try{
    if(!value||typeof value!=='object')return;const v=value as Record<string,unknown>;
    if(!Number.isSafeInteger(v.checkedAtUnixMs)||Number(v.checkedAtUnixMs)<0||Number(v.checkedAtUnixMs)>8640000000000000)return;
    if(v.operationId!==null&&(!Number.isSafeInteger(v.operationId)||Number(v.operationId)<0))return;
    if(v.mode!=='tun'&&v.mode!=='proxy')return;
    if(!['running','exited','not-started','unavailable'].includes(String(v.process)))return;
    if(v.exitCode!==null&&(!Number.isInteger(v.exitCode)||Number(v.exitCode)<-2147483648||Number(v.exitCode)>2147483647))return;
    if(!['enabled','disabled','unavailable'].includes(String(v.systemProxy)))return;
    if(!Number.isInteger(v.ownedRouteCount)||Number(v.ownedRouteCount)<0||Number(v.ownedRouteCount)>4)return;
    if(!v.failure||typeof v.failure!=='object')return;const f=v.failure as Record<string,unknown>;
    if(!isPublicNativeCode(f.code)||typeof f.retryable!=='boolean')return;
    const {stage,cause,win32Code}=publicFailureDetails(f);
    const ports=publicDiagnosticFacts({checkedAtUnixMs:0,ports:v.ports})?.ports;if(!ports)return;
    const ownership=(raw:unknown)=>typeof raw==='string'&&['owned','none','changed','incomplete','prepared','unknown','unavailable'].includes(raw)?raw:'unavailable';
    return {checkedAtUnixMs:Number(v.checkedAtUnixMs),operationId:v.operationId as number|null,mode:v.mode,
      failure:{code:f.code,category:['network','permission','lifecycle'].includes(String(f.category))?String(f.category):'network',retryable:f.retryable,stage,cause,win32Code},
      process:v.process as ConnectFailureObservation['process'],exitCode:v.exitCode as number|null,ports,systemProxy:v.systemProxy as ConnectFailureObservation['systemProxy'],
      proxyOwnership:ownership(v.proxyOwnership),routeOwnership:ownership(v.routeOwnership),ownedRouteCount:Number(v.ownedRouteCount)};
  }catch{return;}
}
