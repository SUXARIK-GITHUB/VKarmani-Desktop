import { describe, expect, it } from 'vitest';
import legacy from './fixtures/policies/legacy-upgrade.json';
import overwritten from './fixtures/policies/overwritten-072.json';
import normalized from './fixtures/policies/normalized-upgrade.json';
import { normalizeStoredRules, normalizeRuleValue, activePolicyEntries } from '../src/utils/appPolicies';

describe('persisted production policy upgrade', () => {
  it('keeps valid legacy executables and quarantines unsupported values without sentinel replacement', () => {
    const rules = normalizeStoredRules(legacy.splitTunnelEntries);
    expect(rules).toEqual(normalized.splitTunnelEntries);
    expect(rules.filter(r => r.enabled).map(r => r.value)).toEqual(['Discord.exe','Telegram.exe','backgroundTaskHost.exe']);
    expect(rules.find(r => r.id === 'script')).toMatchObject({value:'legacy-helper.bat',enabled:false});
    expect(rules.find(r => r.id === 'legacy-service')?.kind).toBe('app');
    for (const rule of rules.filter(r => r.enabled)) expect(() => normalizeRuleValue(rule.kind,rule.value)).not.toThrow();
  });
  it('recovers 0.13.72 sentinel poisoning without inventing overwritten original identities', () => {
    const rules = normalizeStoredRules(overwritten.splitTunnelEntries);
    expect(rules.filter(r => r.enabled).map(r => r.value)).toEqual(['Discord.exe','Telegram.exe']);
    expect(rules[2]).toMatchObject({value:'<invalid stored policy>',enabled:false});
  });
});

describe('strict identity/upgrade and active-policy matrix', () => {
  it.each(['chrome.exe','telegram.exe','C:/Program Files/App/App.exe','C:/Program Files (x86)/App/App.exe','C:/Пользователи/Юзер/Тест/App.EXE','multi.part.name.exe','C:/folder.exe/real.app.exe',`C:/${'long'.repeat(100)}/app.exe`])('accepts executable identity %s without broadening path', value => {
    const normalized=normalizeRuleValue('app',value);expect(normalized).toBe(value); if(value.includes('/'))expect(normalized).toContain('/');
  });
  it.each(['','   ','C:/Program Files/App/','C:/not-an-executable.txt','relative/path.exe','1:/app.exe','C::/app.exe','a?.exe','https://example.test/app.exe','Service Display Name','[object Object]','null','undefined','"C:/unclosed.exe','C:/folder/../app.exe'])('rejects malformed active application target %s', value => expect(()=>normalizeRuleValue('app',value)).toThrow());
  it('normalizes closed quotes, spaces, old bare names and missing policy; disables unsupported state visibly',()=>{
    const rules=normalizeStoredRules([{id:'old',kind:'app',value:' chrome ',enabled:true},{id:'quoted',kind:'app',value:'"C:\\Program Files\\App\\App.exe" --flag',enabled:true}]);
    expect(rules.map(r=>r.value)).toEqual(['chrome.exe','C:/Program Files/App/App.exe']);expect(normalizeStoredRules([null,{},'undefined']).every(r=>!r.enabled&&r.invalidReason)).toBe(true);
  });
  it('ignores inactive VPN rules in all/exclude modes but retains active DIRECT exclusions',()=>{
    const rules=[{id:'stale',kind:'app' as const,value:'bad',enabled:true,policy:'VPN' as const},{id:'direct',kind:'app' as const,value:'chrome.exe',enabled:true,policy:'DIRECT' as const}];
    expect(activePolicyEntries(rules,'all').map(r=>r.id)).toEqual(['direct']);expect(activePolicyEntries(rules,'exclude').map(r=>r.id)).toEqual(['direct']);expect(activePolicyEntries(rules,'selected')).toHaveLength(2);
  });
  it('preserves migration results across repeated save/load and cannot reinterpret modern services',()=>{
    const once=normalizeStoredRules(legacy.splitTunnelEntries);expect(normalizeStoredRules(JSON.parse(JSON.stringify(once)))).toEqual(once);
    const modern=normalizeStoredRules([{id:'svc',kind:'service',value:'SomeService.exe',enabled:true,policy:'VPN',schemaVersion:2}]);expect(modern[0]).toMatchObject({kind:'service',enabled:false,invalidReason:'RULE_INVALID'});
  });
});

import { isSelectedTunPolicyEmpty } from '../src/utils/appPolicies';
it('the connection UI accepts empty ALL/exclude but refuses SELECTED without a VPN target',()=>{
 expect(isSelectedTunPolicyEmpty([], 'all')).toBe(false);expect(isSelectedTunPolicyEmpty([], 'exclude')).toBe(false);expect(isSelectedTunPolicyEmpty([], 'selected')).toBe(true);
 expect(isSelectedTunPolicyEmpty([{id:'direct',kind:'app',value:'chrome.exe',policy:'DIRECT',enabled:true}], 'selected')).toBe(true);
 expect(isSelectedTunPolicyEmpty([{id:'vpn',kind:'app',value:'chrome.exe',policy:'VPN',enabled:true}], 'selected')).toBe(false);
});
