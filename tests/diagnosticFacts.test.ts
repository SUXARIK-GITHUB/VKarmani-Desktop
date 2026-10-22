import {describe,it,expect} from 'vitest';
import {publicDiagnosticFacts} from '../src/utils/diagnosticFacts';
import {diagnosticChecks,diagnosticCategories} from '../src/utils/diagnosticChecks';
import type {RuntimeStatus} from '../src/types/vpn';
const facts={checkedAtUnixMs:1,resourceIntegrity:'verified',storageMetadata:'present',logsMetadata:'present',elevation:'standard',repairHistoryStatus:'available',repairHistory:[{atUnixMs:1,code:'REPAIR_STARTED',restoreProxy:true,routeCount:2}]};
const runtime={bridge:'tauri',coreInstalled:true,tunnelActive:false,diagnosticFacts:facts} as RuntimeStatus;
describe('diagnostic public facts boundary',()=>{
  it('reports real local listener ownership without inferring egress or allowing private PID/path fields',()=>{
    const ports=[10808,10809,10810].map(port=>({port,state:'free',pid:987,exePath:'C:/private-fixture/private.exe'}));
    const observed={...runtime,diagnosticFacts:{...facts,ports}} as RuntimeStatus;
    const check=diagnosticChecks(observed,'en').find(c=>c.id==='PORT_OWNERSHIP')!;
    expect(check.status).toBe('PASS');expect(check.evidence).toContain('10810=free');expect(check.evidence).toContain('GetExtendedTcpTable');
    expect(JSON.stringify(publicDiagnosticFacts(observed.diagnosticFacts))).not.toMatch(/private-fixture|exePath|987/);
    expect(diagnosticChecks(observed,'en').find(c=>c.id==='TUN_EGRESS')?.status).toBe('NOT_RUN');
  });
  it.each([['foreign','FAIL'],['unconfirmed','WARN'],['unavailable','WARN'],['owned','WARN']])('classifies idle port state %s as %s', (state,status)=>{
    const observed={...runtime,diagnosticFacts:{...facts,ports:[{port:10808,state},{port:10809,state:'free'},{port:10810,state:'free'}]}} as RuntimeStatus;
    expect(diagnosticChecks(observed,'en').find(c=>c.id==='PORT_OWNERSHIP')?.status).toBe(status);
  });
  it('only reports healthy active ports when all three belong to the known active runtime',()=>{
    const observed={...runtime,tunnelActive:true,xrayPid:17,diagnosticFacts:{...facts,ports:[10808,10809,10810].map(port=>({port,state:'owned'}))}} as RuntimeStatus;
    expect(diagnosticChecks(observed,'en').find(c=>c.id==='PORT_OWNERSHIP')?.status).toBe('PASS');
    expect(diagnosticChecks({...observed,operation:{id:1,kind:'connect',stage:'starting',startedAt:0,deadlineAt:1}},'en').find(c=>c.id==='PORT_OWNERSHIP')?.status).toBe('WARN');
  });
  it.each([[{port:10808,state:'free'}],Array(3).fill({port:10808,state:'free'}),[{port:10808,state:'free'},{port:10809,state:'free'},{port:9999,state:'free'}],[{port:10808,state:'private-string'},{port:10809,state:'free'},{port:10810,state:'free'}]])('incomplete/duplicate/invalid port data stays NOT_RUN',ports=>{
    expect(publicDiagnosticFacts({...facts,ports})?.ports).toBeUndefined();
    expect(diagnosticChecks({...runtime,diagnosticFacts:{...facts,ports}} as RuntimeStatus,'en').find(c=>c.id==='PORT_OWNERSHIP')?.status).toBe('NOT_RUN');
  });
  it('covers all thirteen categories without claiming egress, DNS or WFP',()=>{
    const checks=diagnosticChecks(runtime,'en');expect([...new Set(checks.map(c=>c.category))].sort()).toEqual([...diagnosticCategories].sort());
    for(const id of ['TUN_EGRESS','PORT_OWNERSHIP','DNS_LEAK','WFP_ISOLATION'])expect(checks.find(c=>c.id===id)?.status).toBe('NOT_RUN');
    expect(checks.find(c=>c.id==='RESOURCE_INTEGRITY')?.evidence).toContain('bounded-file-read');
    expect(checks.find(c=>c.id==='STORAGE_METADATA')?.summary).toContain('no DPAPI');
  });
  it('only copies bounded allowlisted receipts and strips private fields',()=>{
    const data=publicDiagnosticFacts({...facts,privateNonce:'not-exportable',repairHistory:Array(60).fill({...facts.repairHistory[0],url:'not-exportable'})});
    expect(data?.repairHistory).toHaveLength(32);expect(JSON.stringify(data)).not.toContain('not-exportable');
    expect(publicDiagnosticFacts({...facts,repairHistory:[{...facts.repairHistory[0],code:'private secret'}]})?.repairHistory).toEqual([]);
  });
  it.each([null,{}, {...facts,checkedAtUnixMs:NaN},{...facts,checkedAtUnixMs:Infinity},{...facts,checkedAtUnixMs:-1}])('fails closed for malformed observations',raw=>expect(publicDiagnosticFacts(raw)).toBeNull());
  it('does not treat arbitrary native strings as evidence',()=>{
    const output=publicDiagnosticFacts({...facts,resourceIntegrity:'secret fixture',elevation:'https://private.invalid',repairHistory:[{...facts.repairHistory[0],routeCount:5}]});
    expect(output?.resourceIntegrity).toBe('unavailable');expect(output?.elevation).toBe('unavailable');expect(output?.repairHistory).toEqual([]);
  });
  it('mismatch fails integrity while unavailable stays NOT_RUN',()=>{
    for(const [value,status] of [['mismatch','FAIL'],['unavailable','NOT_RUN']])expect(diagnosticChecks({...runtime,diagnosticFacts:{...runtime.diagnosticFacts!,resourceIntegrity:value as 'mismatch'|'unavailable'}},'en').find(c=>c.id==='RESOURCE_INTEGRITY')?.status).toBe(status);
  });
});
