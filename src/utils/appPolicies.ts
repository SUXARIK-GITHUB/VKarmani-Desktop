import type { SplitTunnelEntry, SplitTunnelEntryKind, RoutingPolicy } from '../types/vpn';

export const MAX_APP_RULES = 256;
export function normalizeRuleValue(kind: SplitTunnelEntryKind, value: string): string {
  let result = value.trim();
  if (!result || result.length > 1024 || /[\u0000-\u001f]/u.test(result)) throw new Error('RULE_INVALID');
  if (kind === 'service') {
    if (!/^[\p{L}\p{N}_. -]{1,256}$/u.test(result)) throw new Error('RULE_INVALID');
    return result;
  }
  if (result.startsWith('"')) {
    const end = result.indexOf('"', 1);
    if (end < 0) throw new Error('RULE_INVALID');
    result = result.slice(1, end);
  } else {
    const end = result.toLowerCase().indexOf('.exe');
    if (end >= 0) result = result.slice(0, end + 4);
  }
  result = result.replace(/\\/g, '/');
  if (!result.includes('/') && /^[\p{L}\p{N}_ -]+$/u.test(result)) result += '.exe';
  if (!/\.exe$/i.test(result) || /[?*<>|"%]/u.test(result) || (!result.includes('/') && result.includes(':')) || result.split('/').some(v => v === '.' || v === '..')) throw new Error('RULE_INVALID');
  if (result.includes('/') && (!/^[a-z]:\/[^:]+$/i.test(result) || result.includes('//'))) throw new Error('RULE_INVALID');
  return result;
}
export function ruleIdentity(kind: SplitTunnelEntryKind, value: string): string {
  return `${kind}:${normalizeRuleValue(kind, value).toLowerCase()}`;
}
export function rulesOverlap(a: Pick<SplitTunnelEntry, 'kind' | 'value'>, b: Pick<SplitTunnelEntry, 'kind' | 'value'>): boolean {
  if (a.kind !== b.kind) return false;
  const left = normalizeRuleValue(a.kind, a.value).toLowerCase();
  const right = normalizeRuleValue(b.kind, b.value).toLowerCase();
  if (left === right) return true;
  return a.kind === 'app' && (!left.includes('/') || !right.includes('/')) && left.slice(left.lastIndexOf('/') + 1) === right.slice(right.lastIndexOf('/') + 1);
}
export function insertRule(entries: SplitTunnelEntry[], kind: SplitTunnelEntryKind, rawValue: string, policy: RoutingPolicy, id: string): SplitTunnelEntry[] {
  if (entries.length >= MAX_APP_RULES) throw new Error('RULE_LIMIT');
  const value = normalizeRuleValue(kind, rawValue);
  if (entries.some(entry => rulesOverlap(entry, { kind, value }))) throw new Error('RULE_CONFLICT');
  return [...entries, { id, kind, value, policy, enabled: true }];
}
export function normalizeStoredRules(value: unknown): SplitTunnelEntry[] {
  if (!Array.isArray(value)) return [];
  // Preserve executable intent. Invalid/oversized state must fail native
  // preflight rather than silently dropping a DIRECT rule or widening VPN.
  const invalid = (index: number): SplitTunnelEntry => ({ id: `invalid-${index}`, kind: 'app', value: '<invalid stored policy>', enabled: true, policy: 'VPN' });
  if (value.length > MAX_APP_RULES) return [invalid(0)];
  const result: SplitTunnelEntry[] = [];
  for (const raw of value) {
    if (!raw || typeof raw !== 'object' || typeof raw.value !== 'string' || !['app', 'service'].includes(raw.kind) || typeof raw.enabled !== 'boolean' || (raw.policy !== undefined && raw.policy !== 'VPN' && raw.policy !== 'DIRECT')) { result.push(invalid(result.length)); continue; }
    try {
      const normalized = normalizeRuleValue(raw.kind, raw.value);
      const id = String(raw.id || `legacy-${result.length}`);
      if (result.some(entry => entry.id === id || rulesOverlap(entry, { kind: raw.kind, value: normalized }))) { result.push(invalid(result.length)); continue; }
      result.push({ id, kind: raw.kind, value: normalized, enabled: raw.enabled, policy: raw.policy ?? 'VPN' });
    } catch { result.push(invalid(result.length)); }
  }
  return result;
}
