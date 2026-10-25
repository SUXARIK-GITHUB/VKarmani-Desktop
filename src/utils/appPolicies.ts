import type { SplitTunnelEntry, SplitTunnelEntryKind, RoutingPolicy, TunRoutingMode } from '../types/vpn';

export const MAX_APP_RULES = 256;
export function normalizeRuleValue(kind: SplitTunnelEntryKind, value: string, legacy = false): string {
  if (typeof value !== 'string' || new TextEncoder().encode(value).length > 1024 || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error('RULE_INVALID');
  let result = value.trim();
  if (!result) throw new Error('RULE_INVALID');
  if (kind === 'service') {
    if (!/^[\p{L}\p{N}_. -]{1,256}$/u.test(result) || /\.(exe|bat|jar)$/i.test(result)) throw new Error('RULE_INVALID');
    return result;
  }
  if (result.startsWith('"')) {
    const end = result.indexOf('"', 1);
    if (end < 0 || (result.slice(end + 1) && !/^\s/.test(result.slice(end + 1)))) throw new Error('RULE_INVALID');
    result = result.slice(1, end);
  } else {
    const match = /\.exe(?=\s|$)/i.exec(result);
    if (match) result = result.slice(0, match.index + 4);
  }
  result = result.replace(/\\/g, '/');
  if (legacy && !result.includes('/') && /^[\p{L}\p{N}_-]+$/u.test(result)) result += '.exe';
  if (!/\.exe$/i.test(result) || /[?*<>|"%]/u.test(result) || (!result.includes('/') && result.includes(':')) || result.split('/').some(v => !v || v === '.' || v === '..' || /[. ]$/.test(v))) throw new Error('RULE_INVALID');
  if (result.includes('/') && !/^[a-z]:\/[^:]+$/i.test(result)) throw new Error('RULE_INVALID');
  return result;
}
export function ruleIdentity(kind: SplitTunnelEntryKind, value: string): string {
  return `${kind}:${normalizeRuleValue(kind, value).toLowerCase()}`;
}
export function rulesOverlap(a: Pick<SplitTunnelEntry, 'kind' | 'value'>, b: Pick<SplitTunnelEntry, 'kind' | 'value'>): boolean {
  if (a.kind !== b.kind) return false;
  const left = normalizeRuleValue(a.kind, a.value).toLowerCase();
  const right = normalizeRuleValue(b.kind, b.value).toLowerCase();
  return left === right || a.kind === 'app' && (!left.includes('/') || !right.includes('/')) && left.slice(left.lastIndexOf('/') + 1) === right.slice(right.lastIndexOf('/') + 1);
}
export function insertRule(entries: SplitTunnelEntry[], kind: SplitTunnelEntryKind, rawValue: string, policy: RoutingPolicy, id: string): SplitTunnelEntry[] {
  if (entries.length >= MAX_APP_RULES) throw new Error('RULE_LIMIT');
  const value = normalizeRuleValue(kind, rawValue);
  if (entries.some(entry => !entry.invalidReason && rulesOverlap(entry, { kind, value }))) throw new Error('RULE_CONFLICT');
  return [...entries, { id, kind, value, policy, enabled: true, schemaVersion: 2 }];
}
export function normalizeStoredRules(value: unknown): SplitTunnelEntry[] {
  if (value === null || value === undefined) return [];
  if (!Array.isArray(value)) return [{ id: 'corrupt-state', kind: 'app', value: JSON.stringify(value), enabled: false, policy: 'VPN', schemaVersion: 2, invalidReason: 'RULE_SCHEMA_INVALID' }];
  const result: SplitTunnelEntry[] = [];
  for (const [index, item] of value.entries()) {
    const raw = item && typeof item === 'object' ? item as Record<string, unknown> : {};
    const legacy = raw.schemaVersion !== 2;
    let kind: SplitTunnelEntryKind = raw.kind === 'service' ? 'service' : 'app';
    const originalValue = typeof raw.value === 'string' ? raw.value : JSON.stringify(raw.value ?? item ?? null);
    // Before the service-inventory schema, "service" was an executable picker category.
    // Only an unversioned executable representation may migrate to an app target.
    if (legacy && kind === 'service' && /\.exe(?:"?\s.*)?$/i.test(originalValue.trim())) kind = 'app';
    let id = typeof raw.id === 'string' && raw.id ? raw.id : `legacy-${index}`;
    if (result.some(entry => entry.id === id)) id = `${id}-duplicate-${index}`;
    const entry: SplitTunnelEntry = { id, kind, value: originalValue, enabled: raw.enabled === true, policy: raw.policy === 'DIRECT' ? 'DIRECT' : 'VPN', schemaVersion: 2 };
    try {
      if (!['app','service'].includes(String(raw.kind)) || typeof raw.value !== 'string' || typeof raw.enabled !== 'boolean' || (raw.policy !== undefined && raw.policy !== 'VPN' && raw.policy !== 'DIRECT')) throw new Error('RULE_SCHEMA_INVALID');
      if (value.length > MAX_APP_RULES) throw new Error('RULE_LIMIT');
      if (typeof raw.invalidReason === 'string') throw new Error(['RULE_INVALID','RULE_SCHEMA_INVALID','RULE_LIMIT','RULE_CONFLICT'].includes(raw.invalidReason) ? raw.invalidReason : 'RULE_INVALID');
      entry.value = normalizeRuleValue(kind, originalValue, legacy);
      if (result.some(other => !other.invalidReason && rulesOverlap(other, entry))) throw new Error('RULE_CONFLICT');
    } catch (error) {
      // Keep the actual value and identity for local review. Never replace it with
      // an enabled sentinel or silently throw away a DIRECT exclusion.
      entry.value = originalValue;
      entry.enabled = false;
      entry.invalidReason = error instanceof Error ? error.message : 'RULE_INVALID';
    }
    result.push(entry);
  }
  return result;
}
export function activePolicyEntries(entries: SplitTunnelEntry[], mode: TunRoutingMode): SplitTunnelEntry[] {
  return entries.filter(entry => entry.enabled && (mode === 'selected' || (entry.policy ?? 'VPN') === 'DIRECT'));
}

export function isSelectedTunPolicyEmpty(entries: SplitTunnelEntry[], mode: TunRoutingMode): boolean {
  return mode === 'selected' && !entries.some(entry => entry.enabled && (entry.policy ?? 'VPN') === 'VPN');
}
