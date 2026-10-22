import { describe, expect, it } from 'vitest';
import type { ConnectionState, RuntimeStatus } from '../src/types/vpn';
import { canAutoInstallUpdate, updateNeedsOwnedCleanup } from '../src/utils/updateSafety';

const clean = (): RuntimeStatus => ({bridge:'tauri',coreInstalled:true,tunnelActive:false,message:'fixture',systemProxyEnabled:false,proxyOwnership:'none',routeOwnership:'none'});
describe('R38 automatic installation preserves active or unknown control channels', () => {
  it('allows only a positively observed idle native runtime without proxy/route ownership', () => {
    expect(canAutoInstallUpdate(clean(),'idle')).toBe(true);
    expect(updateNeedsOwnedCleanup(clean())).toBe(false);
    expect(canAutoInstallUpdate(null,'idle')).toBe(false);
    expect(canAutoInstallUpdate({bridge:'tauri',coreInstalled:false,tunnelActive:false,message:'loading'},'idle')).toBe(false);
  });
  it.each(['connecting','connected','disconnecting'] as ConnectionState[])('never automatically installs during %s', connection => {
    expect(canAutoInstallUpdate(clean(),connection)).toBe(false);
  });
  it.each([
    {tunnelActive:true}, {xrayPid:123}, {systemProxyEnabled:true}, {systemProxyEnabled:undefined},
    {proxyOwnership:'owned'}, {proxyOwnership:'corrupt'}, {proxyOwnership:'changed'}, {proxyOwnership:'unavailable'},
    {proxyOwnership:undefined}, {routeOwnership:'confirmed'}, {routeOwnership:'missing'}, {routeOwnership:undefined},
    {proxyAutoConfigUrl:'https://pac.example.test/owned-fixture'}, {bridge:'web-preview' as const},
    {operation:{id:1,kind:'connect',stage:'validate',startedAt:1,deadlineAt:2}}
  ])('defers active, foreign, pending or uncertain observations %j', patch => {
    expect(canAutoInstallUpdate({...clean(),...patch},'idle')).toBe(false);
  });
  it('does not disconnect solely because the bridge is Tauri or a foreign proxy is enabled', () => {
    expect(updateNeedsOwnedCleanup({...clean(),systemProxyEnabled:true})).toBe(false);
    for (const patch of [{tunnelActive:true},{xrayPid:123},{proxyOwnership:'owned'},{routeOwnership:'confirmed'}]) expect(updateNeedsOwnedCleanup({...clean(),...patch})).toBe(true);
  });
});
