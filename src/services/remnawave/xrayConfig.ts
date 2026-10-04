import { canonicalJson, sha256Text } from '../../utils/canonicalJson';

export class XrayConfigError extends Error {
  constructor(public readonly code: 'INVALID_JSON' | 'LIMIT' | 'GRAPH' | 'UNSUPPORTED', public readonly path: string) {
    // Never put provider values, credentials or complete configs into errors.
    super(`Xray config ${code}: ${path}`);
    this.name = 'XrayConfigError';
  }
}

export function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function validateJsonBounds(root: unknown, maxDepth = 64, maxNodes = 100000) {
  const stack = [{ value: root, depth: 0 }];
  let nodes = 0;
  while (stack.length) {
    const { value, depth } = stack.pop()!;
    if (++nodes > maxNodes || depth > maxDepth) throw new XrayConfigError('LIMIT', 'document complexity');
    if (value !== null && typeof value === 'object') {
      for (const child of Object.values(value)) stack.push({ value: child, depth: depth + 1 });
    }
  }
}

function arrayField(object: Record<string, unknown>, key: string, path: string): unknown[] {
  const value = object[key];
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new XrayConfigError('GRAPH', `${path}.${key}`);
  return value;
}

function optionalTag(value: unknown, path: string): string | undefined {
  if (value === undefined || value === '') return undefined;
  if (typeof value !== 'string' || !value.trim() || /[\u0000-\u001f\u007f]/.test(value)) throw new XrayConfigError('GRAPH', path);
  return value;
}

export interface XrayConfigGraph {
  config: Record<string, unknown>;
  identity: string;
  outbounds: Record<string, unknown>[];
  balancers: Record<string, unknown>[];
  primaryBalancerTag?: string;
  memberTags: string[];
  connected: boolean;
}

export function readXrayConfigGraph(input: Record<string, unknown>): XrayConfigGraph {
  validateJsonBounds(input);
  // JSON cloning deliberately preserves null, empty strings/arrays and all unknown fields.
  const config = JSON.parse(JSON.stringify(input)) as Record<string, unknown>;
  const outbounds = arrayField(config, 'outbounds', 'config');
  if (!outbounds.length || outbounds.length > 1000) throw new XrayConfigError('LIMIT', 'outbounds');
  const tags = new Set<string>();
  for (let i = 0; i < outbounds.length; i++) {
    const outbound = outbounds[i];
    if (!isJsonObject(outbound) || typeof outbound.protocol !== 'string' || !outbound.protocol) throw new XrayConfigError('GRAPH', `outbounds[${i}]`);
    const tag = optionalTag(outbound.tag, `outbounds[${i}].tag`);
    if (tag && tags.has(tag)) throw new XrayConfigError('GRAPH', `outbounds[${i}].tag duplicate`);
    if (tag) tags.add(tag);
  }
  const reference = (value: unknown, path: string, validTags = tags) => {
    const tag = optionalTag(value, path);
    if (tag && !validTags.has(tag)) throw new XrayConfigError('GRAPH', `${path} missing target`);
    return tag;
  };
  const edges = new Map<string, string[]>();
  for (let i = 0; i < outbounds.length; i++) {
    const outbound = outbounds[i] as Record<string, unknown>;
    const stream = isJsonObject(outbound.streamSettings) ? outbound.streamSettings : {};
    const sockopt = isJsonObject(stream.sockopt) ? stream.sockopt : {};
    const proxy = isJsonObject(outbound.proxySettings) ? outbound.proxySettings : {};
    const targets = [reference(sockopt.dialerProxy, `outbounds[${i}].streamSettings.sockopt.dialerProxy`), reference(proxy.tag, `outbounds[${i}].proxySettings.tag`)].filter((tag): tag is string => Boolean(tag));
    if (typeof outbound.tag === 'string') edges.set(outbound.tag, targets);
  }
  const done = new Set<string>(), visiting = new Set<string>();
  const visit = (tag: string) => {
    if (visiting.has(tag)) throw new XrayConfigError('GRAPH', 'outbound dialer cycle');
    if (done.has(tag)) return;
    visiting.add(tag); for (const target of edges.get(tag) ?? []) visit(target); visiting.delete(tag); done.add(tag);
  };
  for (const tag of edges.keys()) visit(tag);
  if (config.routing !== undefined && !isJsonObject(config.routing)) throw new XrayConfigError('GRAPH', 'routing');
  const routing = (config.routing ?? {}) as Record<string, unknown>;
  const balancers = arrayField(routing, 'balancers', 'routing');
  const balancerTags = new Set<string>();
  const members = new Map<string, string[]>();
  for (let i = 0; i < balancers.length; i++) {
    const balancer = balancers[i];
    if (!isJsonObject(balancer)) throw new XrayConfigError('GRAPH', `routing.balancers[${i}]`);
    const tag = optionalTag(balancer.tag, `routing.balancers[${i}].tag`);
    if (!tag || balancerTags.has(tag)) throw new XrayConfigError('GRAPH', `routing.balancers[${i}].tag missing/duplicate`);
    balancerTags.add(tag);
    const selectors = arrayField(balancer, 'selector', `routing.balancers[${i}]`);
    // Xray HandlerSelector matches case-sensitive prefixes, not exact tags or regexes.
    if (!selectors.length || selectors.some((value) => typeof value !== 'string')) throw new XrayConfigError('GRAPH', `routing.balancers[${i}].selector`);
    const selected = [...tags].filter((candidate) => selectors.some((prefix) => candidate.startsWith(prefix as string)));
    const fallback = reference(balancer.fallbackTag, `routing.balancers[${i}].fallbackTag`);
    if (!selected.length && !fallback) throw new XrayConfigError('GRAPH', `routing.balancers[${i}].selector matches nothing`);
    members.set(tag, [...new Set([...selected, ...(fallback ? [fallback] : [])])]);
  }
  const ruleTargets = new Set(tags);
  if (isJsonObject(config.api)) {
    const apiTag = optionalTag(config.api.tag, 'api.tag');
    if (apiTag) {
      if (tags.has(apiTag)) throw new XrayConfigError('GRAPH', 'api.tag duplicate outbound');
      ruleTargets.add(apiTag);
    }
  }
  const rules = arrayField(routing, 'rules', 'routing');
  let primaryBalancerTag: string | undefined;
  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i];
    if (!isJsonObject(rule)) throw new XrayConfigError('GRAPH', `routing.rules[${i}]`);
    const outbound = reference(rule.outboundTag, `routing.rules[${i}].outboundTag`, ruleTargets);
    const balancer = reference(rule.balancerTag, `routing.rules[${i}].balancerTag`, balancerTags);
    if (Boolean(outbound) === Boolean(balancer)) throw new XrayConfigError('GRAPH', `routing.rules[${i}] ambiguous/missing target`);
    primaryBalancerTag ??= balancer;
  }
  return {
    config, identity: sha256Text(canonicalJson(config)), outbounds: outbounds as Record<string, unknown>[],
    balancers: balancers as Record<string, unknown>[], primaryBalancerTag,
    memberTags: primaryBalancerTag ? members.get(primaryBalancerTag) ?? [] : [],
    connected: rules.length > 0 || balancers.length > 0 || edges.size > 0 && [...edges.values()].some((targets) => targets.length > 0)
  };
}
