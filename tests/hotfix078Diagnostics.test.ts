import {describe,expect,it} from 'vitest';
import {diagnosticChecks} from '../src/utils/diagnosticChecks';
import type {ConnectivityProbe,RuntimeStatus} from '../src/types/vpn';
const runtime:RuntimeStatus={bridge:'tauri',coreInstalled:true,tunnelActive:true,xrayPid:17,launchMode:'xray-sidecar',message:'synthetic',networkMode:'tun',tunInterfaceName:'VKarmani',proxyOwnership:'none',routeOwnership:'confirmed',systemProxyEnabled:false,
 diagnosticFacts:{checkedAtUnixMs:1,resourceIntegrity:'verified',storageMetadata:'present',logsMetadata:'present',elevation:'elevated',repairHistory:[],repairHistoryStatus:'available',ports:[{port:10808,state:'owned'},{port:10809,state:'owned'},{port:10810,state:'owned'}]}};
const direct:ConnectivityProbe={success:true,checkedAt:'synthetic',kind:'server-direct',httpPortOpen:false,socksPortOpen:false,latencyMs:1,message:'direct TCP'};
describe('0.13.78 independent network evidence',()=>{
 it.each(['ru','en'] as const)('never turns direct ping or listener metadata into VPN/DNS PASS (%s)',language=>{
  const checks=diagnosticChecks(runtime,language,'synthetic',direct);const status=(id:string)=>checks.find(c=>c.id===id)?.status;
  expect(status('HTTP_LISTENER')).toBe('PASS');expect(status('SOCKS_LISTENER')).toBe('PASS');
  expect(status('VPN_EGRESS')).toBe('NOT_RUN');expect(status('DNS_LEAK')).toBe('NOT_RUN');expect(status('TUN_EGRESS')).toBe('NOT_RUN');
 });
 it('separates foreign listener availability from ownership and never borrows its successful HTTP probe',()=>{
  const changed={...runtime,diagnosticFacts:{...runtime.diagnosticFacts!,ports:[{port:10808 as const,state:'foreign' as const},{port:10809 as const,state:'foreign' as const},{port:10810 as const,state:'free' as const}]}};
  const checks=diagnosticChecks(changed,'en','synthetic',{...direct,kind:'xray-http',httpPortOpen:true,socksPortOpen:true});
  expect(checks.find(c=>c.id==='HTTP_LISTENER')?.status).toBe('FAIL');
  expect(checks.find(c=>c.id==='VPN_EGRESS')?.status).toBe('NOT_RUN');
 });
 it('keeps absent facts and a stale/legacy probe unknown instead of showing closed listeners',()=>{
  const checks=diagnosticChecks({...runtime,diagnosticFacts:undefined},'en','synthetic',{...direct,kind:undefined});
  expect(checks.find(c=>c.id==='HTTP_LISTENER')?.status).toBe('NOT_RUN');
  expect(checks.find(c=>c.id==='VPN_EGRESS')?.status).toBe('NOT_RUN');
 });
});
