import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {structuredNativeError} from '../src/utils/nativeErrors';
import {publicConnectFailure,publicDiagnosticFacts} from '../src/utils/diagnosticFacts';

const receipt={checkedAtUnixMs:1,operationId:4,mode:'proxy',failure:{code:'CORE_CONFIG_REJECTED',category:'network',retryable:false,stage:'preflight',cause:'CORE_FRAGMENT_LENGTH_INVALID'},process:'not-started',exitCode:null,ports:[10808,10809,10810].map(port=>({port,state:'foreign'})),systemProxy:'enabled',proxyOwnership:'none',routeOwnership:'none',ownedRouteCount:0};
describe('P0 recovery 079 preserves exact failure-time facts',()=>{
  it.each(['ru','en'] as const)('exposes only fixed stage/cause and localized explanation in %s',language=>{
    const error=structuredNativeError({...receipt.failure,details:'private UUID',message:'private URL'},'fallback',language)!;
    expect(error.code).toBe('CORE_CONFIG_REJECTED');expect(error.stage).toBe('preflight');expect(error.causeCode).toBe('CORE_FRAGMENT_LENGTH_INVALID');
    expect(error.message).toContain('CORE_FRAGMENT_LENGTH_INVALID');expect(error.message).not.toMatch(/private|fallback/);
    const denied=structuredNativeError({code:'CORE_SPAWN_ACCESS_DENIED',stage:'spawn',win32Code:5},'fallback',language)!;
    expect(denied.win32Code).toBe(5);
  });
  it('arbitrary nested context, unknown stages and mismatched Windows codes never cross into UI',()=>{
    const error=structuredNativeError({...receipt.failure,stage:'private stage',cause:'private token',win32Code:193},'fallback','en')!;
    expect(error.stage).toBeUndefined();expect(error.causeCode).toBeUndefined();expect(error.win32Code).toBeUndefined();expect(error.message).not.toContain('private');
  });
  it('a cleanup snapshot cannot overwrite the historical observation or infer VPN egress',()=>{
    const facts=publicDiagnosticFacts({checkedAtUnixMs:2,lastConnectFailure:receipt,ports:[10808,10809,10810].map(port=>({port,state:'free'}))})!;
    expect(facts.ports!.every(p=>p.state==='free')).toBe(true);
    expect(facts.lastConnectFailure!.ports.every(p=>p.state==='foreign')).toBe(true);
    expect(facts.lastConnectFailure!.checkedAtUnixMs).toBe(1);expect(JSON.stringify(facts)).not.toMatch(/egress.*PASS|dns.*PASS/i);
  });
  it('strips private fields at every level and rejects malformed/overlarge observations',()=>{
    const safe=publicConnectFailure({...receipt,url:'private',failure:{...receipt.failure,details:'private'},ports:receipt.ports.map(p=>({...p,pid:1234,path:'private'}))})!;
    expect(JSON.stringify(safe)).not.toMatch(/private|1234|path|details|url/);
    for(const invalid of [null,{}, {...receipt,ownedRouteCount:5},{...receipt,checkedAtUnixMs:Infinity},{...receipt,ports:Array(3).fill({port:10808,state:'owned'})},{...receipt,mode:'private'},{...receipt,failure:{code:'CORE_PRIVATE_SECRET',retryable:false}}])expect(publicConnectFailure(invalid)).toBeUndefined();
    expect(publicConnectFailure(Object.defineProperty({},'checkedAtUnixMs',{get(){throw Error('private');}}))).toBeUndefined();
  });
  it('captures native failure before every explicit readiness/route cleanup and gates WinINet on owned listeners',()=>{
    const source=readFileSync('src-tauri/src/commands.rs','utf8');
    for(const reason of ['connect_readiness_failed','tun_routes_failed','connect_final_check_failed']){
      const cleanup=source.indexOf(`restore_saved_proxy_state(&app, &state, "${reason}")`);
      expect(cleanup).toBeGreaterThan(0);expect(source.lastIndexOf('record_connect_failure',cleanup)).toBeGreaterThan(source.lastIndexOf('let child_pid =',cleanup));
    }
    const proxy=source.slice(source.indexOf('pub(crate) fn set_system_proxy_blocking'),source.indexOf('pub(crate) async fn repair_runtime_environment'));
    expect(proxy.indexOf('owned_runtime_ports_ready')).toBeLessThan(proxy.indexOf('enable_owned_windows_proxy'));
    expect(proxy).not.toContain('tcp_port_open');
  });
});
