import { describe, expect, it } from 'vitest';
import { insertRule, normalizeStoredRules, normalizeRuleValue, rulesOverlap } from '../src/utils/appPolicies';
describe('app/service policies', () => {
  it('migrates legacy enabled selection to VPN and preserves DIRECT/disabled rules', () => {
    expect(normalizeStoredRules([{id:'1',kind:'app',value:' app.exe ',enabled:true},{id:'2',kind:'service',value:'DedicatedSvc',enabled:false,policy:'DIRECT'}])).toEqual([{id:'1',kind:'app',value:'app.exe',enabled:true,policy:'VPN'},{id:'2',kind:'service',value:'DedicatedSvc',enabled:false,policy:'DIRECT'}]);
  });
  it('keeps distinct absolute paths and rejects overlapping name/path opposite policies', () => {
    let rules = insertRule([], 'app', 'C:\\A\\app.exe', 'VPN', '1');
    rules = insertRule(rules, 'app', 'D:\\B\\app.exe', 'DIRECT', '2');
    expect(rules).toHaveLength(2);
    expect(() => insertRule(rules, 'app', 'APP.EXE', 'DIRECT', '3')).toThrow('RULE_CONFLICT');
    expect(() => insertRule(rules, 'app', 'c:/a/APP.EXE', 'DIRECT', '4')).toThrow('RULE_CONFLICT');
  });
  it('ignores command arguments and rejects folder/wildcard/relative/injected rules', () => {
    expect(normalizeRuleValue('app', '"C:\\Program Files\\A\\a.exe" --flag')).toBe('C:/Program Files/A/a.exe');
    for (const v of ['C:/A/', '*.exe', '../app.exe', 'app.exe\nanything', 'C:/A/../app.exe', 'self/']) expect(() => normalizeRuleValue('app', v)).toThrow();
    expect(() => normalizeRuleValue('service', "Svc'; Stop-Process xray")).toThrow();
  });
  it('blocks conflicting, corrupt or oversized stored intent rather than dropping DIRECT rules', () => {
    const conflicted = normalizeStoredRules([{kind:'app',value:'a.exe',enabled:true},{kind:'app',value:'A.EXE',enabled:true,policy:'DIRECT'}]);
    expect(conflicted).toHaveLength(2);
    expect(() => normalizeRuleValue('app', conflicted[1].value)).toThrow();
    for (const stored of [Array.from({length:300},(_,i)=>({kind:'app',value:`a${i}.exe`,enabled:true})), [{kind:'app',value:'a.exe',enabled:true,policy:'NEVER'}], [{kind:'app',value:'../a.exe',enabled:true,policy:'DIRECT'}]]) {
      const blocked = normalizeStoredRules(stored);
      expect(blocked[0].enabled).toBe(true);
      expect(() => normalizeRuleValue('app', blocked[0].value)).toThrow();
    }
    expect(rulesOverlap({kind:'service',value:'ServiceA'},{kind:'app',value:'ServiceA.exe'})).toBe(false);
  });
});
