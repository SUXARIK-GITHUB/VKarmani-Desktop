import type { VpnServer } from '../types/vpn';
import { canonicalJson, sha256Text } from './canonicalJson';
import { readRuntimeEndpoint } from './serverPing';

// Only the hash is persisted publicly. Node identities deliberately exclude
// unrelated subscription nodes; Auto measurements depend on the complete graph.
export function serverMeasurementIdentity(server: VpnServer): string {
  const template = server.runtimeTemplate;
  if (!template && server.latencyIdentity) return server.latencyIdentity;
  return sha256Text(canonicalJson({
    endpoint: readRuntimeEndpoint(server), protocol: server.protocol,
    transport: template?.transport ?? server.transportLabel ?? null,
    outbound: template?.outbound ?? null,
    graph: template?.profileKind === 'auto' ? template.fullConfig : null
  }));
}

export function mergeServerMeasurements(catalog: VpnServer[], previous: VpnServer[], now = Date.now()): VpnServer[] {
  const old = new Map(previous.map(server => [server.id, server]));
  return catalog.map(server => {
    const identity = serverMeasurementIdentity(server);
    const candidates = [server, old.get(server.id)].filter((value): value is VpnServer => Boolean(value))
      .filter(value => {
        const at = Date.parse(value.latencyCheckedAt ?? '');
        return (value.latencyStatus === 'ok' || value.latencyStatus === 'failed')
          && Number.isFinite(at) && at <= now
          && (value.latencyStatus !== 'ok' || (typeof value.latency === 'number' && Number.isFinite(value.latency) && value.latency > 0))
          && (value.latencyIdentity ?? serverMeasurementIdentity(value)) === identity;
      }).sort((a, b) => Date.parse(b.latencyCheckedAt!) - Date.parse(a.latencyCheckedAt!));
    const measured = candidates[0];
    if (!measured) return { ...server, latency: null, latencyStatus: 'unchecked', latencyCheckedAt: undefined, latencyIdentity: undefined, latencySource: undefined };
    return { ...server, latency: measured.latencyStatus === 'ok' ? measured.latency : null,
      latencyStatus: measured.latencyStatus, latencyCheckedAt: measured.latencyCheckedAt,
      latencyIdentity: identity, latencySource: measured.latencySource };
  });
}
