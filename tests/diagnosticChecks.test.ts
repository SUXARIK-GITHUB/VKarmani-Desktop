import {describe,expect,it} from 'vitest';
import {diagnosticChecks,formatUnixTimestamp,mayRepairOwnedState} from '../src/utils/diagnosticChecks';
import {safePublicDigest} from '../src/utils/diagnosticsExport';
import type {RemnawaveSession,RuntimeStatus} from '../src/types/vpn';
const runtime:RuntimeStatus={bridge:'tauri',coreInstalled:true,tunnelActive:false,launchMode:'xray-sidecar',message:'synthetic',proxyOwnership:'none',routeOwnership:'none',subscriptionState:'unconfirmed'};
describe('R40/R41 read-only findings and narrow repair plan',()=>{
  it.each(['ru','en'] as const)('reports per-check provenance without fabricating network/security success in %s',language=>{
    const checks=diagnosticChecks(runtime,language,'2026-10-22T00:00:00.000Z');
    expect(new Set(checks.map(check=>check.id)).size).toBe(checks.length);
    expect(checks.every(check=>check.summary&&check.evidence&&check.checkedAt==='2026-10-22T00:00:00.000Z')).toBe(true);
    for(const id of ['DNS_LEAK','WFP_ISOLATION','RESOURCE_INTEGRITY'])expect(checks.find(check=>check.id===id)?.status).toBe('NOT_RUN');
    expect(checks.find(check=>check.id==='RUNTIME_PROCESS')?.status).toBe('NOT_RUN');
  });
  it('classifies actual changed ownership as a failure and denies repair',()=>{
    const altered={...runtime,proxyOwnership:'changed',routeOwnership:'changed'};
    expect(diagnosticChecks(altered,'en').filter(check=>check.status==='FAIL').map(check=>check.id)).toEqual(['PROXY_OWNERSHIP','ROUTE_OWNERSHIP']);
    expect(mayRepairOwnedState(altered)).toBe(false);
  });
  it('does not copy untrusted native error/state/path content into evidence',()=>{
    const raw={...runtime,proxyOwnership:'https://sub.vkarmani.com/synthetic-secret',routeOwnership:'C:/Private/fixture',message:'synthetic-sensitive'};
    expect(JSON.stringify(diagnosticChecks(raw,'en'))).not.toMatch(/synthetic-secret|C:\/Private|synthetic-sensitive/);
  });
  it.each([{},{tunnelActive:true},{xrayPid:55},{operation:{id:1}},{routeOwnership:'unavailable'},{proxyOwnership:'changed'},{bridge:'web-preview'}])('requires a disconnected, known and owned repair target %j',patch=>{
    expect(mayRepairOwnedState({...runtime,...patch} as RuntimeStatus)).toBe(false);
  });
  it('allows only recorded owned state and never claims idle absence needs repair',()=>{
    expect(mayRepairOwnedState({...runtime,proxyOwnership:'owned'})).toBe(true);
    expect(mayRepairOwnedState({...runtime,routeOwnership:'confirmed'})).toBe(true);
    expect(mayRepairOwnedState(null)).toBe(false);
  });
  it('keeps unknown/invalid timestamps distinct from human-readable verified dates',()=>{
    for(const value of [null,undefined,'1234',NaN,-1,Infinity,8640000000001])expect(formatUnixTimestamp(value,'en')).toBe('No data');
    expect(formatUnixTimestamp(2000000000,'en')).not.toContain('2000000000');
  });
});
describe('R42 public digest redaction boundary',()=>{
  const digest='a'.repeat(64);
  it('preserves only a typed 64-hex public digest',()=>{
    expect(safePublicDigest(digest,null)).toBe(digest);
    expect(safePublicDigest('SECRET '+digest,null)).toBe('');expect(safePublicDigest('<img>',null)).toBe('');
  });
  it('still redacts a credential injected into a digest field',()=>{
    const session={accessKey:'VKARMANI-'+digest.toUpperCase(),userId:'synthetic'} as RemnawaveSession;
    expect(safePublicDigest(digest,session)).toBe('[redacted]');
  });
});
