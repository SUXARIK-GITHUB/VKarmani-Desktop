import type { VpnServer } from '../types/vpn';

function stableStringify(value: unknown): string {
  if (value === null || value === undefined) {
    return 'null';
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }

  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
      .join(',')}}`;
  }

  return JSON.stringify(value);
}

function fnv1aHex(value: string) {
  let hash = 0x811c9dc5;

  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }

  return (hash >>> 0).toString(16).padStart(8, '0');
}

export function buildServerRuntimeFingerprint(server: VpnServer | null | undefined) {
  if (!server) {
    return '';
  }

  return fnv1aHex(stableStringify({
    rawUri: server.rawUri?.trim() ?? '',
    host: server.host ?? '',
    port: server.port ?? 0,
    protocol: server.protocol,
    transportLabel: server.transportLabel ?? '',
    runtimeTemplate: server.runtimeTemplate ?? null
  }));
}

export function isVpnServerLike(value: unknown): value is VpnServer {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const candidate = value as Partial<VpnServer>;
  return typeof candidate.id === 'string'
    && typeof candidate.country === 'string'
    && typeof candidate.city === 'string'
    && typeof candidate.protocol === 'string';
}
