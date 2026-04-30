import type { RoutingExclusionSettings } from '../types/vpn';

export const ROUTING_EXCLUSION_LIMIT = 300;

export const defaultRoutingExclusions: RoutingExclusionSettings = {
  enabled: false,
  bypassRuDomains: true,
  bypassSuDomains: true,
  bypassRfDomains: true,
  domains: [],
  ips: []
};

const DOMAIN_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function uniqueLimited(values: string[], limit = ROUTING_EXCLUSION_LIMIT): string[] {
  const seen = new Set<string>();
  const result: string[] = [];

  for (const value of values) {
    const normalized = value.trim().toLowerCase();
    if (!normalized || seen.has(normalized)) {
      continue;
    }

    seen.add(normalized);
    result.push(normalized);
    if (result.length >= limit) {
      break;
    }
  }

  return result;
}

function stripDomainDecorations(rawValue: string): string {
  let value = rawValue.trim().toLowerCase();
  value = value.replace(/^https?:\/\//, '').replace(/^socks[45]?:\/\//, '');
  value = value.split(/[/?#]/)[0] ?? value;
  value = value.replace(/:\d+$/, '');
  value = value.replace(/^\*\./, '.');
  value = value.replace(/\.+$/g, '');
  return value;
}

function toAsciiDomain(value: string): string {
  if (!value) {
    return '';
  }

  if (value.startsWith('.')) {
    const converted = toAsciiDomain(value.slice(1));
    return converted ? `.${converted}` : '';
  }

  try {
    return new URL(`http://${value}`).hostname.toLowerCase().replace(/\.+$/g, '');
  } catch {
    return value.toLowerCase();
  }
}

function isValidDomain(value: string): boolean {
  const clean = value.startsWith('.') ? value.slice(1) : value;
  if (!clean || clean.length > 253 || clean.includes('..')) {
    return false;
  }

  const labels = clean.split('.');
  if (labels.length < 1 || labels.some((label) => !DOMAIN_LABEL_RE.test(label))) {
    return false;
  }

  return true;
}

export function normalizeRoutingDomainInput(rawValue: string): string | null {
  const decorated = stripDomainDecorations(rawValue);
  const ascii = toAsciiDomain(decorated);
  if (!ascii || !isValidDomain(ascii)) {
    return null;
  }

  return ascii;
}

export function normalizeRoutingIpInput(rawValue: string): string | null {
  const value = rawValue.trim().toLowerCase();
  if (!value) {
    return null;
  }

  const [ip, prefix] = value.split('/');
  if (!ip || !IPV4_RE.test(ip)) {
    return null;
  }

  if (prefix === undefined) {
    return ip;
  }

  if (!/^\d{1,2}$/.test(prefix)) {
    return null;
  }

  const prefixNumber = Number(prefix);
  if (!Number.isInteger(prefixNumber) || prefixNumber < 0 || prefixNumber > 32) {
    return null;
  }

  return `${ip}/${prefixNumber}`;
}

export function sanitizeRoutingExclusions(value: unknown): RoutingExclusionSettings {
  if (!value || typeof value !== 'object') {
    return { ...defaultRoutingExclusions, domains: [], ips: [] };
  }

  const candidate = value as Partial<RoutingExclusionSettings>;
  const domains = uniqueLimited(
    Array.isArray(candidate.domains)
      ? candidate.domains.map((item) => normalizeRoutingDomainInput(String(item))).filter((item): item is string => Boolean(item))
      : []
  );
  const ips = uniqueLimited(
    Array.isArray(candidate.ips)
      ? candidate.ips.map((item) => normalizeRoutingIpInput(String(item))).filter((item): item is string => Boolean(item))
      : []
  );

  return {
    enabled: typeof candidate.enabled === 'boolean' ? candidate.enabled : defaultRoutingExclusions.enabled,
    bypassRuDomains: typeof candidate.bypassRuDomains === 'boolean' ? candidate.bypassRuDomains : defaultRoutingExclusions.bypassRuDomains,
    bypassSuDomains: typeof candidate.bypassSuDomains === 'boolean' ? candidate.bypassSuDomains : defaultRoutingExclusions.bypassSuDomains,
    bypassRfDomains: typeof candidate.bypassRfDomains === 'boolean' ? candidate.bypassRfDomains : defaultRoutingExclusions.bypassRfDomains,
    domains,
    ips
  };
}

export function countActiveRoutingExclusions(settings: RoutingExclusionSettings): number {
  if (!settings.enabled) {
    return 0;
  }

  return Number(settings.bypassRuDomains)
    + Number(settings.bypassSuDomains)
    + Number(settings.bypassRfDomains)
    + settings.domains.length
    + settings.ips.length;
}
