import type { VpnServer } from '../types/vpn';

import { canonicalJson, sha256Text } from './canonicalJson';

export function resolveServerReference(servers: VpnServer[], id: string): VpnServer | null {
  const exact = servers.find((server) => server.id === id);
  if (exact) return exact;
  const candidates = servers.filter((server) => server.legacyIds?.includes(id));
  return candidates.length === 1 ? candidates[0] : null;
}

export function migrateServerReferences(servers: VpnServer[], ids: string[]): string[] {
  return [...new Set(ids.map((id) => resolveServerReference(servers, id)?.id ?? id))];
}

export function buildServerRuntimeFingerprint(server: VpnServer | null | undefined) {
  if (!server) {
    return '';
  }

  return sha256Text(canonicalJson(server.runtimeTemplate ?? null));
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

// A catalog refresh must not replace or drop the graph owned by a live runtime.
export function resolveConnectedProfile(servers: VpnServer[], serverId: string, fingerprint: string | undefined, retained: VpnServer | null): VpnServer | null {
  const current = resolveServerReference(servers, serverId);
  if (current && (!fingerprint || buildServerRuntimeFingerprint(current) === fingerprint)) return current;
  return retained?.id === serverId ? retained : null;
}
