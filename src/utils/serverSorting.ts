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

function readValidLatency(server: VpnServer) {
  const latency = Number(server.latency);
  return server.latency !== null
    && server.latency !== undefined
    && Number.isFinite(latency)
    && latency > 0
    ? Math.max(1, Math.round(latency))
    : null;
}

function getLatencyBucket(server: VpnServer) {
  const latency = readValidLatency(server);

  // Сначала показываем реально отвечающие TCP-серверы: именно они подходят
  // для выбора лучшего VPN-узла пользователем.
  if (latency !== null && server.latencyStatus === 'ok') {
    return 0;
  }

  // Старые сохранённые состояния могли иметь latency без явного status.
  // Их учитываем как измеренные, но ниже свежего ok-результата.
  if (latency !== null && server.latencyStatus !== 'failed') {
    return 1;
  }

  if (server.latencyStatus === 'checking') {
    return 2;
  }

  if (server.latencyStatus === 'failed') {
    return 4;
  }

  return 3;
}

function compareServersByLatency(left: VpnServer, right: VpnServer) {
  const leftBucket = getLatencyBucket(left);
  const rightBucket = getLatencyBucket(right);

  if (leftBucket !== rightBucket) {
    return leftBucket - rightBucket;
  }

  const leftLatency = readValidLatency(left);
  const rightLatency = readValidLatency(right);
  if (leftLatency !== null && rightLatency !== null && leftLatency !== rightLatency) {
    return leftLatency - rightLatency;
  }

  return 0;
}

export function rankServersForDisplay(
  servers: VpnServer[],
  strategy: AppSettings['protocolStrategy'],
  favoriteServerIds: string[] = []
) {
  const favoriteRank = new Map(
    favoriteServerIds
      .map((id) => id.trim())
      .filter(Boolean)
      .map((id, index): [string, number] => [id, index])
  );

  return rankServers(servers, strategy)
    .map((server, index) => ({ server, index }))
    .sort((left, right) => {
      const leftFavoriteRank = favoriteRank.get(left.server.id);
      const rightFavoriteRank = favoriteRank.get(right.server.id);

      if (leftFavoriteRank !== undefined || rightFavoriteRank !== undefined) {
        if (leftFavoriteRank === undefined) return 1;
        if (rightFavoriteRank === undefined) return -1;
        return leftFavoriteRank - rightFavoriteRank;
      }

      const latencyOrder = compareServersByLatency(left.server, right.server);
      if (latencyOrder !== 0) {
        return latencyOrder;
      }

      // После избранного и пинга оставляем прежний production-порядок:
      // runtime-ready/recommended/reality strategy/country-city.
      return left.index - right.index;
    })
    .map((item) => item.server);
}

export function pickPreferredServer(servers: VpnServer[], strategy: AppSettings['protocolStrategy']) {
  return rankServers(servers, strategy)[0] ?? null;
}
