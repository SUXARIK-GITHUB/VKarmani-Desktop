import type { AppSettings, VpnServer } from '../types/vpn';

export function isRealityPreferredServer(server: VpnServer) {
  const haystack = [server.protocol, server.transportLabel, ...(server.tags ?? []), server.rawLabel]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();

  return haystack.includes('reality');
}

export function rankServers(servers: VpnServer[], strategy: AppSettings['protocolStrategy']) {
  const scopedServers = strategy === 'xray-only'
    ? (() => {
      const runtimeReady = servers.filter((server: VpnServer) => Boolean(server.runtimeTemplate));
      return runtimeReady.length ? runtimeReady : servers;
    })()
    : servers;

  return [...scopedServers].sort((left: VpnServer, right: VpnServer) => {
    const leftScore = Number(Boolean(left.runtimeTemplate)) * 100
      + Number(Boolean(left.isRecommended)) * 10
      + (strategy === 'reality-first' && isRealityPreferredServer(left) ? 30 : 0);
    const rightScore = Number(Boolean(right.runtimeTemplate)) * 100
      + Number(Boolean(right.isRecommended)) * 10
      + (strategy === 'reality-first' && isRealityPreferredServer(right) ? 30 : 0);

    if (rightScore !== leftScore) {
      return rightScore - leftScore;
    }

    return `${left.country} ${left.city}`.localeCompare(`${right.country} ${right.city}`, 'ru');
  });
}

export function pickPreferredServer(servers: VpnServer[], strategy: AppSettings['protocolStrategy']) {
  return rankServers(servers, strategy)[0] ?? null;
}
