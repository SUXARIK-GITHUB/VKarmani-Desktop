import { afterEach, expect, it, vi } from 'vitest';
import { isTunProcessRoutingBlocked, normalizeStoredRules, tunProcessRoutingBlockMessage } from '../src/utils/appPolicies';
import { checkForUpdates, installAvailableUpdate } from '../src/services/updater';

afterEach(() => vi.unstubAllEnvs());
const entries = normalizeStoredRules([
  {id:'vpn',kind:'app',value:'C:/A/app.exe',policy:'VPN',enabled:true,schemaVersion:2},
  {id:'direct',kind:'app',value:'D:/B/app.exe',policy:'DIRECT',enabled:true,schemaVersion:2},
  {id:'service',kind:'service',value:'DedicatedSvc',policy:'VPN',enabled:false,schemaVersion:2}
]);

it.each(['all','selected','exclude'] as const)('only the explicitly marked owner test permits the old %s process graph, retaining all records', mode => {
  const before = structuredClone(entries);
  vi.stubEnv('VITE_VKARMANI_LOCAL_TEST', '');
  expect(isTunProcessRoutingBlocked(entries, mode)).toBe(true);
  vi.stubEnv('VITE_VKARMANI_LOCAL_TEST', '1');
  expect(isTunProcessRoutingBlocked(entries, mode)).toBe(false);
  expect(tunProcessRoutingBlockMessage(entries, mode, 'ru')).toBe('');
  expect(entries).toEqual(before);
});

it('still refuses selected without enabled VPN identities and reports the real reason', () => {
  vi.stubEnv('VITE_VKARMANI_LOCAL_TEST', '1');
  const directOnly = entries.map(e => ({...e, enabled:e.policy === 'DIRECT'}));
  expect(isTunProcessRoutingBlocked(directOnly,'selected')).toBe(true);
  expect(tunProcessRoutingBlockMessage(directOnly,'selected','en')).toContain('at least one');
});

it('never checks, downloads, installs, seals storage or invokes callbacks from the local updater', async () => {
  vi.stubEnv('VITE_VKARMANI_LOCAL_TEST','1');
  const callback=vi.fn();
  expect((await checkForUpdates('stable')).available).toBe(false);
  expect(await installAvailableUpdate(callback,callback)).toMatchObject({ok:false});
  expect(callback).not.toHaveBeenCalled();
});
