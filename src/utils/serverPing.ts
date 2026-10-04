import type { VpnServer } from '../types/vpn';
import { readXrayConfigGraph } from '../services/remnawave/xrayConfig';

export function readRuntimeEndpoint(server: VpnServer): { host: string; port: number } | null {
  const hostFromServer = server.host?.trim();
  const portFromServer = Number(server.port ?? 0);
  if (hostFromServer && Number.isFinite(portFromServer) && portFromServer > 0 && portFromServer <= 65535) {
    return { host: hostFromServer, port: Math.round(portFromServer) };
  }

  const settings = server.runtimeTemplate?.outbound?.settings as
    | { vnext?: Array<{ address?: string; port?: number }>; servers?: Array<{ address?: string; port?: number }> }
    | undefined;
  const runtimeEndpoint = settings?.vnext?.[0] ?? settings?.servers?.[0];
  const runtimeHost = runtimeEndpoint?.address?.trim();
  const runtimePort = Number(runtimeEndpoint?.port ?? 443);

  if (!runtimeHost || !Number.isFinite(runtimePort) || runtimePort <= 0 || runtimePort > 65535) {
    return null;
  }

  return { host: runtimeHost, port: Math.round(runtimePort) };
}


// A logical Auto has no single endpoint. Its measurement jobs remain internal.
export function getServerPingEndpoint(server: VpnServer) {
  return server.runtimeTemplate?.profileKind === 'auto' ? null : readRuntimeEndpoint(server);
}

export function getServerPingTargets(server: VpnServer): VpnServer[] {
  if (server.runtimeTemplate?.profileKind !== 'auto') return getServerPingEndpoint(server) ? [server] : [];
  const template = server.runtimeTemplate;
  if (!template.fullConfig) return [];
  try {
    const graph = readXrayConfigGraph(template.fullConfig);
    if (!graph.primaryBalancerTag) return [];
    const members = new Set(graph.memberTags);
    const seen = new Set<string>();
    return graph.outbounds.flatMap(outbound => {
      if (typeof outbound.tag !== 'string' || !members.has(outbound.tag)) return [];
      const target: VpnServer = { ...server, host: undefined, port: undefined,
        runtimeTemplate: { ...template, outbound, profileKind: 'node' } };
      // Unknown/unsupported endpoints cannot escape graph validation or invent RTTs.
      let endpoint: { host: string; port: number } | null;
      try { endpoint = readRuntimeEndpoint(target); } catch { return []; }
      if (!endpoint) return [];
      const key = JSON.stringify([endpoint.host.toLowerCase(), endpoint.port]);
      if (seen.has(key)) return [];
      seen.add(key);
      return [{ ...target, host: endpoint.host, port: endpoint.port }];
    });
  } catch { return []; }
}
