import type { VpnServer, XrayRuntimeTemplate } from '../../types/vpn';
import { inferCountryCode, resolveServerFlag } from '../../utils/serverDisplay';
import { decodeBase64Compat, maybeDecodeBase64, parsePort, splitHostPort } from './parserCore';

const MAX_SUBSCRIPTION_BYTES = 2 * 1024 * 1024;
const MAX_IMPORTED_SERVERS = 1000;
const MAX_URI_LENGTH = 8192;
const MAX_JSON_WALK_DEPTH = 12;
const MAX_JSON_WALK_NODES = 5000;
const MAX_LABEL_LENGTH = 160;

function trimLabel(value: string) {
  const normalized = value.replace(/\s+/g, ' ').trim();
  return normalized.length > MAX_LABEL_LENGTH ? normalized.slice(0, MAX_LABEL_LENGTH).trimEnd() : normalized;
}

function deepFindString(
  source: unknown,
  keys: string[],
  depth = 0,
  visited: { count: number } = { count: 0 }
): string | undefined {
  if (!source || typeof source !== 'object' || depth > MAX_JSON_WALK_DEPTH || visited.count > MAX_JSON_WALK_NODES) {
    return undefined;
  }

  visited.count += 1;
  const record = source as Record<string, unknown>;
  for (const key of keys) {
    if (typeof record[key] === 'string' && record[key]) {
      return record[key] as string;
    }
  }

  for (const value of Object.values(record)) {
    const nested = deepFindString(value, keys, depth + 1, visited);
    if (nested) {
      return nested;
    }
  }

  return undefined;
}

function deepCollectUris(
  source: unknown,
  collected: string[] = [],
  depth = 0,
  visited: { count: number } = { count: 0 }
): string[] {
  if (collected.length >= MAX_IMPORTED_SERVERS || depth > MAX_JSON_WALK_DEPTH || visited.count > MAX_JSON_WALK_NODES) {
    return collected;
  }

  visited.count += 1;

  if (typeof source === 'string') {
    const matches = source.match(/(?:vless|vmess|trojan|ss|hy2|hysteria2):\/\/[^\s"'<>`]+/gi) ?? [];
    for (const match of matches) {
      const candidate = match.trim();
      if (candidate.length <= MAX_URI_LENGTH && !collected.includes(candidate)) {
        collected.push(candidate);
      }
      if (collected.length >= MAX_IMPORTED_SERVERS) {
        break;
      }
    }
    return collected;
  }

  if (Array.isArray(source)) {
    for (const item of source) {
      deepCollectUris(item, collected, depth + 1, visited);
      if (collected.length >= MAX_IMPORTED_SERVERS) break;
    }
    return collected;
  }

  if (source && typeof source === 'object') {
    for (const value of Object.values(source as Record<string, unknown>)) {
      deepCollectUris(value, collected, depth + 1, visited);
      if (collected.length >= MAX_IMPORTED_SERVERS) break;
    }
  }

  return collected;
}

function decodeHtmlEntities(value: string) {
  return value
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
}

function extractUrisFromHtml(value: string) {
  const decoded = decodeHtmlEntities(value);
  const matches = decoded.match(/(?:vless|vmess|trojan|ss|hy2|hysteria2):\/\/[^\s"'<>`]+/gi) ?? [];
  return [...new Set(matches.map((item) => item.trim()).filter((item) => item.length <= MAX_URI_LENGTH))].slice(0, MAX_IMPORTED_SERVERS);
}

function extractRawText(body: string) {
  const trimmed = body.trim();
  if (!trimmed) {
    return '';
  }

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      const inlineUris = deepCollectUris(parsed);
      if (inlineUris.length) {
        return inlineUris.join('\n');
      }
      return deepFindString(parsed, ['raw', 'subscription', 'content', 'body', 'link']) ?? trimmed;
    } catch {
      return trimmed;
    }
  }

  if (/<!doctype html|<html[\s>]/i.test(trimmed)) {
    const inlineUris = extractUrisFromHtml(trimmed);
    if (inlineUris.length) {
      return inlineUris.join('\n');
    }
  }

  return decodeHtmlEntities(trimmed);
}

function fnv1aHex(value: string) {
  let hash = 0x811c9dc5;

  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }

  return (hash >>> 0).toString(16).padStart(8, '0');
}

function stableSubscriptionId(uri: string) {
  const identity = uri.trim().replace(/#.*$/u, '');
  return `subscription-${fnv1aHex(identity)}`;
}

function runtimeIdentityFallback(server: VpnServer) {
  return JSON.stringify({
    host: server.host ?? '',
    port: server.port ?? 0,
    runtimeTemplate: server.runtimeTemplate ?? null,
    rawLabel: server.rawLabel ?? ''
  });
}

function withUniqueSubscriptionIds(items: VpnServer[]) {
  const baseCounts = new Map<string, number>();
  for (const item of items) {
    baseCounts.set(item.id, (baseCounts.get(item.id) ?? 0) + 1);
  }

  const assignedCounts = new Map<string, number>();
  return items.map((item) => {
    if ((baseCounts.get(item.id) ?? 0) <= 1) {
      return item;
    }

    // Некоторые подписки могут отдавать несколько строк с одинаковым URI без fragment
    // или с одинаковым transport endpoint, но с разными названиями стран/нод. React key
    // и selectedServerId должны быть уникальными, иначе пользователь кликает один ряд,
    // а connect может взять первый сервер с таким же id. Для обычных серверов id остаётся
    // прежним; suffix добавляется только при реальной коллизии.
    const suffixSeed = item.rawUri?.trim() || runtimeIdentityFallback(item);
    const candidateId = `${item.id}-${fnv1aHex(suffixSeed)}`;
    const collisionIndex = assignedCounts.get(candidateId) ?? 0;
    assignedCounts.set(candidateId, collisionIndex + 1);

    return {
      ...item,
      id: collisionIndex === 0 ? candidateId : `${candidateId}-${collisionIndex + 1}`
    };
  });
}

function parseStrictPort(value: string | number | null | undefined, fallback = 443): number | null {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  const parsed = typeof value === 'number' ? value : Number(String(value).trim());
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65535) {
    return null;
  }

  return parsed;
}

function looksLikeUuid(value: string | null | undefined) {
  return Boolean(value && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value));
}

function parseProtocol(protocol: string): VpnServer['protocol'] {
  switch (protocol.toLowerCase()) {
    case 'reality':
      return 'Reality';
    case 'vless':
      return 'VLESS';
    case 'hy2':
    case 'hysteria2':
      return 'Hysteria2';
    case 'tuic':
    case 'sing-box':
      return 'Sing-box';
    default:
      return 'Xray';
  }
}

function parseCountryLabel(label: string, host: string) {
  const withSpaces = label.replace(/[_-]+/g, ' ').trim();
  const cleaned = withSpaces.replace(/[\u{1F1E6}-\u{1F1FF}]{2}/gu, ' ').trim();
  if (!cleaned) {
    return {
      country: 'Импортированный узел',
      city: '',
      countryCode: undefined as string | undefined
    };
  }

  const firstSegment = cleaned.split(/[|/]/)[0]?.trim() || cleaned;
  const codeMatch = firstSegment.match(/^([A-Z]{2})\s+(.+)$/);
  const explicitCode = codeMatch?.[1];
  const countryForCode = (codeMatch?.[2] ?? firstSegment).trim();
  const countryCode = inferCountryCode({
    country: countryForCode,
    rawLabel: label,
    host,
    explicitCode
  });
  const country = explicitCode
    ? cleaned.replace(new RegExp(`^${explicitCode}\\s+`, 'i'), '').trim()
    : cleaned;

  return {
    country,
    city: '',
    countryCode
  };
}

function compactObject<T>(value: T): T {
  if (Array.isArray(value)) {
    return value
      .map((item) => compactObject(item))
      .filter((item) => item !== undefined && item !== null && item !== '' && !(Array.isArray(item) && item.length === 0)) as T;
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .map(([key, nested]) => [key, compactObject(nested)])
        .filter(([, nested]) => nested !== undefined && nested !== null && nested !== '' && !(Array.isArray(nested) && nested.length === 0))
    ) as T;
  }

  return value;
}

function splitCsv(value: string | null) {
  return (value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function getFirstParam(searchParams: URLSearchParams, names: string[]) {
  for (const name of names) {
    const value = searchParams.get(name);
    if (value !== null && value !== '') {
      return value;
    }
  }
  return undefined;
}

function normalizeTransportName(value: string | null | undefined) {
  const normalized = (value || 'raw').trim().toLowerCase();
  if (normalized === 'tcp') return 'raw';
  if (normalized === 'splithttp') return 'xhttp';
  return normalized;
}

function normalizeUrlHostname(hostname: string) {
  return hostname.replace(/^\[/, '').replace(/\]$/, '');
}

function parseJsonParam(value: string | null | undefined): unknown {
  if (!value) {
    return undefined;
  }

  const candidates = [value];
  try {
    candidates.push(decodeURIComponent(value));
  } catch {
    // Keep the original candidate only.
  }

  try {
    candidates.push(decodeBase64Compat(value));
  } catch {
    // Not a base64/base64url encoded JSON payload.
  }

  for (const candidate of candidates) {
    const trimmed = candidate.trim();
    if (!trimmed || (!trimmed.startsWith('{') && !trimmed.startsWith('['))) {
      continue;
    }

    try {
      return JSON.parse(trimmed);
    } catch {
      // Try the next representation.
    }
  }

  return undefined;
}

function buildTlsSettings(searchParams: URLSearchParams, fallbackServerName?: string) {
  const serverName = getFirstParam(searchParams, ['sni', 'peer', 'serverName', 'servername', 'host']) || fallbackServerName;
  return compactObject({
    serverName,
    fingerprint: getFirstParam(searchParams, ['fp', 'fingerprint']) ?? undefined,
    alpn: splitCsv(searchParams.get('alpn')),
    allowInsecure: searchParams.get('allowInsecure') === '1' || searchParams.get('insecure') === '1'
  });
}

function buildRealitySettings(searchParams: URLSearchParams, fallbackServerName?: string) {
  return compactObject({
    serverName: getFirstParam(searchParams, ['sni', 'peer', 'serverName', 'servername', 'host']) || fallbackServerName,
    fingerprint: getFirstParam(searchParams, ['fp', 'fingerprint']) ?? undefined,
    publicKey: getFirstParam(searchParams, ['pbk', 'publicKey', 'public_key']) ?? undefined,
    shortId: getFirstParam(searchParams, ['sid', 'shortId', 'short_id']) ?? undefined,
    spiderX: getFirstParam(searchParams, ['spx', 'spiderX', 'spider_x']) ?? undefined
  });
}

function buildStreamSettings(base: {
  network?: string;
  security?: string;
  host?: string;
  path?: string;
  serviceName?: string;
  searchParams: URLSearchParams;
}) {
  const requestedNetwork = base.network || base.searchParams.get('type') || base.searchParams.get('net') || 'raw';
  const network = normalizeTransportName(requestedNetwork);
  const security = base.security || base.searchParams.get('security') || (base.searchParams.get('tls') === 'tls' ? 'tls' : 'none');
  const host = base.host || getFirstParam(base.searchParams, ['host', 'authority']) || undefined;
  const path = base.path || getFirstParam(base.searchParams, ['path', 'pathPrefix']) || undefined;
  const serviceName = base.serviceName || getFirstParam(base.searchParams, ['serviceName', 'service_name']) || undefined;

  const settings: Record<string, unknown> = {
    network,
    security
  };

  if (security === 'tls') {
    settings.tlsSettings = buildTlsSettings(base.searchParams, host);
  } else if (security === 'reality') {
    settings.realitySettings = buildRealitySettings(base.searchParams, host);
  }

  if (network === 'ws') {
    settings.wsSettings = compactObject({
      path,
      headers: host ? { Host: host } : undefined
    });
  }

  if (network === 'grpc') {
    settings.grpcSettings = compactObject({
      serviceName,
      multiMode: base.searchParams.get('mode') === 'multi'
    });
  }

  if (network === 'httpupgrade') {
    settings.httpupgradeSettings = compactObject({
      path,
      host
    });
  }

  if (network === 'xhttp') {
    settings.xhttpSettings = compactObject({
      host,
      path,
      mode: base.searchParams.get('mode') || 'auto',
      extra: parseJsonParam(getFirstParam(base.searchParams, ['extra', 'xhttpExtra', 'xhttp_extra']))
    });
  }

  if (network === 'raw') {
    const headerType = base.searchParams.get('headerType') || base.searchParams.get('obfs');
    if (headerType && headerType !== 'raw') {
      settings.rawSettings = compactObject({
        header: {
          type: headerType,
          request: path ? { path: [path] } : undefined,
          headers: host ? { Host: [host] } : undefined
        }
      });
    }
  }

  return compactObject(settings);
}

function parseVlessRuntime(uri: string, url: URL, label: string): XrayRuntimeTemplate | null {
  const searchParams = url.searchParams;
  const userId = decodeURIComponent(url.username || '').trim();
  const host = normalizeUrlHostname(url.hostname);
  const port = parseStrictPort(url.port, 443);
  const security = searchParams.get('security') || (searchParams.get('tls') === 'tls' ? 'tls' : 'none');

  if (!looksLikeUuid(userId) || !host || port === null) {
    return null;
  }

  if (security === 'reality' && !getFirstParam(searchParams, ['pbk', 'publicKey', 'public_key'])) {
    return null;
  }

  const user = compactObject({
    id: userId,
    encryption: searchParams.get('encryption') || 'none',
    flow: searchParams.get('flow') || undefined
  });

  return {
    family: 'xray',
    protocol: 'vless',
    remarks: label,
    transport: normalizeTransportName(searchParams.get('type') || searchParams.get('net')) as XrayRuntimeTemplate['transport'],
    outbound: compactObject({
      tag: 'proxy',
      protocol: 'vless',
      settings: {
        vnext: [
          {
            address: host,
            port,
            users: [user]
          }
        ]
      },
      streamSettings: buildStreamSettings({
        searchParams,
        host: getFirstParam(searchParams, ['host', 'authority']) || host,
        security
      })
    })
  };
}

function parseVmessRuntime(uri: string, label: string): XrayRuntimeTemplate | null {
  const encoded = uri.replace(/^vmess:\/\//i, '');
  try {
    const decoded = JSON.parse(decodeBase64Compat(encoded)) as Record<string, string>;
    const host = String(decoded.add ?? '').trim();
    const userId = String(decoded.id ?? '').trim();
    const port = parseStrictPort(decoded.port, 443);
    if (!host || !looksLikeUuid(userId) || port === null) {
      return null;
    }
    const searchParams = new URLSearchParams();
    if (decoded.path) searchParams.set('path', decoded.path);
    if (decoded.host) searchParams.set('host', decoded.host);
    if (decoded.sni) searchParams.set('sni', decoded.sni);
    if (decoded.alpn) searchParams.set('alpn', decoded.alpn);
    if (decoded.fp) searchParams.set('fp', decoded.fp);
    if (decoded.security) searchParams.set('security', decoded.security);
    if (decoded.tls === 'tls' && !searchParams.get('security')) searchParams.set('security', 'tls');
    if (decoded.net) searchParams.set('type', decoded.net);
    if (decoded.type) searchParams.set('headerType', decoded.type);

    return {
      family: 'xray',
      protocol: 'vmess',
      remarks: decoded.ps || label,
      transport: normalizeTransportName(decoded.net) as XrayRuntimeTemplate['transport'],
      outbound: compactObject({
        tag: 'proxy',
        protocol: 'vmess',
        settings: {
          vnext: [
            {
              address: host,
              port,
              users: [
                {
                  id: userId,
                  alterId: parsePort(decoded.aid, 0),
                  security: decoded.scy || 'auto'
                }
              ]
            }
          ]
        },
        streamSettings: buildStreamSettings({
          searchParams,
          host: decoded.host || decoded.sni || decoded.add,
          path: decoded.path,
          security: searchParams.get('security') || (decoded.tls === 'tls' ? 'tls' : 'none'),
          network: decoded.net || 'tcp'
        })
      })
    };
  } catch {
    return null;
  }
}

function parseTrojanRuntime(url: URL, label: string): XrayRuntimeTemplate | null {
  const searchParams = url.searchParams;
  const password = decodeURIComponent(url.username || '').trim();
  const host = normalizeUrlHostname(url.hostname);
  const port = parseStrictPort(url.port, 443);

  if (!password || !host || port === null) {
    return null;
  }

  return {
    family: 'xray',
    protocol: 'trojan',
    remarks: label,
    transport: normalizeTransportName(searchParams.get('type') || searchParams.get('net')) as XrayRuntimeTemplate['transport'],
    outbound: compactObject({
      tag: 'proxy',
      protocol: 'trojan',
      settings: {
        servers: [
          {
            address: host,
            port,
            password,
            level: 0
          }
        ]
      },
      streamSettings: buildStreamSettings({
        searchParams,
        host: getFirstParam(searchParams, ['host', 'authority']) || host,
        security: searchParams.get('security') || 'tls'
      })
    })
  };
}

function decodeShadowsocksCredentials(value: string) {
  const raw = value.includes(':') ? value : (() => {
    try {
      return decodeBase64Compat(value);
    } catch {
      return value;
    }
  })();

  const separatorIndex = raw.indexOf(':');
  if (separatorIndex === -1) {
    return null;
  }

  return {
    method: raw.slice(0, separatorIndex),
    password: raw.slice(separatorIndex + 1)
  };
}

function parseShadowsocksRuntime(uri: string, label: string): XrayRuntimeTemplate | null {
  const withoutScheme = uri.replace(/^ss:\/\//i, '');
  const [mainPartWithQuery] = withoutScheme.split('#');
  const [mainPart] = mainPartWithQuery.split('?');

  let credentialsPart = mainPart;
  let hostPart = '';

  if (mainPart.includes('@')) {
    [credentialsPart, hostPart] = mainPart.split('@');
  } else {
    try {
      const decoded = decodeBase64Compat(mainPart);
      if (decoded.includes('@')) {
        [credentialsPart, hostPart] = decoded.split('@');
      }
    } catch {
      return null;
    }
  }

  const credentials = decodeShadowsocksCredentials(credentialsPart);
  if (!credentials || !hostPart || !credentials.method.trim() || !credentials.password.trim()) {
    return null;
  }

  const { address, portRaw } = splitHostPort(hostPart);
  const port = parseStrictPort(portRaw, 443);

  if (!address || port === null) {
    return null;
  }

  return {
    family: 'xray',
    protocol: 'shadowsocks',
    remarks: label,
    transport: 'raw',
    outbound: compactObject({
      tag: 'proxy',
      protocol: 'shadowsocks',
      settings: {
        servers: [
          {
            address,
            port,
            method: credentials.method,
            password: credentials.password
          }
        ]
      }
    })
  };
}

function parseHysteria2Runtime(url: URL, label: string): XrayRuntimeTemplate | null {
  const searchParams = url.searchParams;
  const password = decodeURIComponent(url.username || getFirstParam(searchParams, ['password', 'auth']) || '').trim();
  const host = normalizeUrlHostname(url.hostname);
  const port = parseStrictPort(url.port, 443);
  const obfsType = getFirstParam(searchParams, ['obfs', 'obfs-type', 'obfs_type']) || undefined;
  const obfsPassword = getFirstParam(searchParams, ['obfs-password', 'obfs_password', 'obfsPassword']) || undefined;
  const sni = getFirstParam(searchParams, ['sni', 'peer', 'serverName', 'servername']) || host;
  const insecure = searchParams.get('insecure') === '1' || searchParams.get('allowInsecure') === '1';
  const alpn = splitCsv(searchParams.get('alpn'));

  if (!password || !host || port === null) {
    return null;
  }

  // Xray-core exposes Hysteria2 through the hysteria outbound with version: 2.
  // Keeping the display/runtime protocol as hysteria2 is fine for VKarmani UI,
  // but the generated outbound itself must use Xray's real config schema.
  return {
    family: 'xray',
    protocol: 'hysteria2',
    remarks: label,
    transport: 'udp',
    outbound: compactObject({
      tag: 'proxy',
      protocol: 'hysteria',
      settings: {
        version: 2,
        address: host,
        port
      },
      streamSettings: compactObject({
        network: 'hysteria',
        security: 'tls',
        tlsSettings: compactObject({
          serverName: sni,
          fingerprint: getFirstParam(searchParams, ['fp', 'fingerprint']) ?? undefined,
          alpn: alpn.length > 0 ? alpn : ['h3'],
          allowInsecure: insecure
        }),
        hysteriaSettings: compactObject({
          version: 2,
          auth: password
        }),
        udpmasks: obfsType && obfsPassword
          ? [
              {
                type: obfsType,
                settings: {
                  password: obfsPassword
                }
              }
            ]
          : undefined
      })
    })
  };
}

function buildRuntimeTemplateFromUri(uri: string, label: string): XrayRuntimeTemplate | null {
  const scheme = uri.split('://')[0]?.toLowerCase();
  if (!scheme) {
    return null;
  }

  if (scheme === 'vmess') {
    return parseVmessRuntime(uri, label);
  }

  if (scheme === 'ss') {
    return parseShadowsocksRuntime(uri, label);
  }

  try {
    const url = new URL(uri);
    if (scheme === 'hy2' || scheme === 'hysteria2') {
      return parseHysteria2Runtime(url, label);
    }

    if (scheme === 'vless') {
      return parseVlessRuntime(uri, url, label);
    }

    if (scheme === 'trojan') {
      return parseTrojanRuntime(url, label);
    }
  } catch {
    return null;
  }

  return null;
}


function extractRuntimeEndpoint(runtimeTemplate: XrayRuntimeTemplate | null) {
  const settings = runtimeTemplate?.outbound?.settings as
    | {
        address?: string;
        server?: string;
        port?: number | string;
        server_port?: number | string;
        serverPort?: number | string;
        vnext?: Array<{ address?: string; port?: number | string }>;
        servers?: Array<{ address?: string; port?: number | string }>;
      }
    | undefined;

  const vnext = settings?.vnext?.[0];
  if (vnext?.address) {
    return {
      host: vnext.address,
      port: parseStrictPort(vnext.port, 443) ?? 443
    };
  }

  const server = settings?.servers?.[0];
  if (server?.address) {
    return {
      host: server.address,
      port: parseStrictPort(server.port, 443) ?? 443
    };
  }

  const directHost = typeof settings?.address === 'string' && settings.address.trim()
    ? settings.address.trim()
    : typeof settings?.server === 'string' && settings.server.trim()
      ? settings.server.trim()
      : undefined;

  if (directHost) {
    return {
      host: directHost,
      port: parseStrictPort(settings?.port ?? settings?.server_port ?? settings?.serverPort, 443) ?? 443
    };
  }

  return {
    host: undefined,
    port: 443
  };
}

function buildImportedServer(line: string, index: number): VpnServer | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#')) {
    return null;
  }

  const runtimeTemplate = buildRuntimeTemplateFromUri(trimmed, `subscription-${index}`);
  const scheme = trimmed.split("://")[0]?.toLowerCase();
  if (!runtimeTemplate && ['vless', 'vmess', 'trojan', 'ss', 'hy2', 'hysteria2'].includes(scheme)) {
    return null;
  }

  const runtimeEndpoint = extractRuntimeEndpoint(runtimeTemplate);
  const transportLabel = runtimeTemplate?.transport ? runtimeTemplate.transport.toUpperCase() : undefined;
  const protocol = runtimeTemplate
    ? parseProtocol(runtimeTemplate.protocol)
    : parseProtocol(trimmed.split('://')[0]?.replace(':', '') ?? 'unknown');

  try {
    const url = new URL(trimmed);
    const label = trimLabel(decodeURIComponent(url.hash.replace(/^#/, '')) || runtimeTemplate?.remarks || '');
    const host = runtimeEndpoint.host || normalizeUrlHostname(url.hostname) || 'remote-host';
    const port = runtimeEndpoint.port || (url.port ? Number(url.port) : 443);
    const location = parseCountryLabel(label, host);
    const flag = resolveServerFlag({ country: location.country, rawLabel: label, host, explicitCode: location.countryCode });
    const runtimeReady = Boolean(runtimeTemplate);

    return {
      id: stableSubscriptionId(trimmed),
      country: location.country,
      city: location.city,
      countryCode: location.countryCode,
      flag,
      latency: null,
      latencyStatus: 'unchecked',
      load: 0,
      protocol,
      isRecommended: index === 0,
      tags: [
        'Live',
        protocol,
        ...(transportLabel ? [transportLabel] : []),
        runtimeReady ? 'Готов к подключению' : 'Ограниченный импорт'
      ],
      ipPool: `${host}:${port}`,
      description: runtimeReady
        ? (label || `Узел из подписки Remnawave: ${host}`)
        : `Узел импортирован, но его транспорт пока не превращён в полноценный Xray runtime.`,
      source: 'subscription',
      host,
      port,
      rawLabel: label || undefined,
      rawUri: trimmed,
      transportLabel,
      runtimeTemplate: runtimeTemplate ?? undefined
    };
  } catch {
    if (!runtimeTemplate || !runtimeEndpoint.host) {
      return null;
    }

    const label = trimLabel(runtimeTemplate.remarks ?? '');
    const host = runtimeEndpoint.host;
    const port = runtimeEndpoint.port || 443;
    const location = parseCountryLabel(label, host);
    const flag = resolveServerFlag({ country: location.country, rawLabel: label, host, explicitCode: location.countryCode });
    const runtimeReady = Boolean(runtimeTemplate);

    return {
      id: stableSubscriptionId(trimmed),
      country: location.country,
      city: location.city,
      countryCode: location.countryCode,
      flag,
      latency: null,
      latencyStatus: 'unchecked',
      load: 0,
      protocol,
      isRecommended: index === 0,
      tags: [
        'Live',
        protocol,
        ...(transportLabel ? [transportLabel] : []),
        runtimeReady ? 'Готов к подключению' : 'Ограниченный импорт'
      ],
      ipPool: `${host}:${port}`,
      description: runtimeReady
        ? (label || `Узел из подписки Remnawave: ${host}`)
        : `Узел импортирован, но его транспорт пока не превращён в полноценный Xray runtime.`,
      source: 'subscription',
      host,
      port,
      rawLabel: label || undefined,
      rawUri: trimmed,
      transportLabel,
      runtimeTemplate: runtimeTemplate ?? undefined
    };
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string | undefined {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed ? trimmed : undefined;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return String(value);
  }
  return undefined;
}

function asBoolean(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value === 1 ? true : value === 0 ? false : undefined;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['true', 'yes', 'on', '1'].includes(normalized)) return true;
    if (['false', 'no', 'off', '0'].includes(normalized)) return false;
  }
  return undefined;
}

function readFirst(source: Record<string, unknown> | undefined, names: string[]): unknown {
  if (!source) return undefined;
  for (const name of names) {
    const value = source[name];
    if (value !== undefined && value !== null && value !== '') return value;
  }
  return undefined;
}

function readString(source: Record<string, unknown> | undefined, names: string[]): string | undefined {
  return asString(readFirst(source, names));
}

function readRecord(source: Record<string, unknown> | undefined, names: string[]): Record<string, unknown> | undefined {
  return asRecord(readFirst(source, names));
}

function readBoolean(source: Record<string, unknown> | undefined, names: string[]): boolean | undefined {
  return asBoolean(readFirst(source, names));
}

function readPort(source: Record<string, unknown> | undefined, names: string[], fallback = 443): number | null {
  return parseStrictPort(readFirst(source, names) as string | number | null | undefined, fallback);
}

function readStringArray(source: Record<string, unknown> | undefined, names: string[]): string[] {
  const value = readFirst(source, names);
  if (Array.isArray(value)) {
    return value.map((item) => asString(item)).filter((item): item is string => Boolean(item));
  }
  const stringValue = asString(value);
  return stringValue ? splitCsv(stringValue) : [];
}

function toXrayProtocol(value: string | undefined): XrayRuntimeTemplate['protocol'] | null {
  const normalized = (value || '').trim().toLowerCase();
  if (normalized === 'hysteria' || normalized === 'hy2' || normalized === 'hysteria2') return 'hysteria2';
  if (normalized === 'ss' || normalized === 'shadowsocks') return 'shadowsocks';
  if (normalized === 'vless' || normalized === 'vmess' || normalized === 'trojan') return normalized;
  return null;
}

type RuntimeTransport = NonNullable<XrayRuntimeTemplate['transport']>;

function normalizeTemplateTransport(value: string | undefined, fallback: RuntimeTransport = 'raw'): RuntimeTransport {
  const normalized = normalizeTransportName(value || fallback);
  if (normalized === 'tcp') return 'raw';
  if (normalized === 'raw' || normalized === 'ws' || normalized === 'grpc' || normalized === 'httpupgrade' || normalized === 'xhttp' || normalized === 'udp') {
    return normalized;
  }
  return fallback;
}

function buildServerFromRuntimeTemplate(
  runtimeTemplate: XrayRuntimeTemplate,
  index: number,
  identitySeed: string,
  labelOverride?: string
): VpnServer | null {
  const runtimeEndpoint = extractRuntimeEndpoint(runtimeTemplate);
  if (!runtimeEndpoint.host) return null;

  const protocol = parseProtocol(runtimeTemplate.protocol);
  const label = trimLabel(labelOverride || runtimeTemplate.remarks || `${protocol} ${runtimeEndpoint.host}`);
  const host = runtimeEndpoint.host;
  const port = runtimeEndpoint.port || 443;
  const location = parseCountryLabel(label, host);
  const flag = resolveServerFlag({ country: location.country, rawLabel: label, host, explicitCode: location.countryCode });
  const transportLabel = runtimeTemplate.transport ? runtimeTemplate.transport.toUpperCase() : undefined;

  return {
    id: `subscription-${fnv1aHex(identitySeed)}`,
    country: location.country,
    city: location.city,
    countryCode: location.countryCode,
    flag,
    latency: null,
    latencyStatus: 'unchecked',
    load: 0,
    protocol,
    isRecommended: index === 0,
    tags: ['Live', protocol, ...(transportLabel ? [transportLabel] : []), 'Готов к подключению'],
    ipPool: `${host}:${port}`,
    description: label || `Узел из шаблона Remnawave: ${host}`,
    source: 'subscription',
    host,
    port,
    rawLabel: label || undefined,
    transportLabel,
    runtimeTemplate
  };
}

function xrayOutboundToRuntimeTemplate(outbound: Record<string, unknown>, index: number): XrayRuntimeTemplate | null {
  const protocol = toXrayProtocol(readString(outbound, ['protocol', 'type']));
  if (!protocol) return null;
  const streamSettings = asRecord(outbound.streamSettings);
  const transport = normalizeTemplateTransport(readString(streamSettings, ['network']), protocol === 'hysteria2' ? 'udp' : 'raw');
  const endpoint = extractRuntimeEndpoint({ family: 'xray', protocol, outbound, transport });
  if (!endpoint.host) return null;
  const remarks = trimLabel(readString(outbound, ['remarks', 'name', 'ps', 'tag']) || `${protocol}-${index + 1}`);

  return {
    family: 'xray',
    protocol,
    remarks,
    transport,
    outbound: compactObject({ ...outbound, tag: 'proxy' })
  };
}

function writeTransportParams(searchParams: URLSearchParams, transport: Record<string, unknown> | undefined, fallbackHost?: string) {
  if (!transport) return;
  const type = readString(transport, ['type', 'network', 'net']);
  if (type) searchParams.set('type', normalizeTransportName(type));
  const path = readString(transport, ['path', 'path_prefix', 'pathPrefix']);
  if (path) searchParams.set('path', path);
  const serviceName = readString(transport, ['service_name', 'serviceName', 'grpc-service-name', 'grpcServiceName']);
  if (serviceName) searchParams.set('serviceName', serviceName);
  const headers = readRecord(transport, ['headers']);
  const host = readString(headers, ['Host', 'host', ':authority', 'authority']) || fallbackHost;
  if (host) searchParams.set('host', host);
}

function writeTlsParams(searchParams: URLSearchParams, tls: Record<string, unknown> | undefined, defaultServerName?: string, explicitReality?: Record<string, unknown>) {
  const reality = explicitReality || readRecord(tls, ['reality', 'reality_opts', 'reality-opts']);
  const realityEnabled = readBoolean(reality, ['enabled']) === true || Boolean(readString(reality, ['public_key', 'publicKey', 'public-key']));
  const tlsEnabled = readBoolean(tls, ['enabled']) !== false && Boolean(tls || realityEnabled);
  searchParams.set('security', realityEnabled ? 'reality' : (tlsEnabled ? 'tls' : 'none'));

  const serverName = readString(tls, ['server_name', 'serverName', 'servername', 'sni']) || defaultServerName;
  if (serverName) searchParams.set('sni', serverName);
  const utls = readRecord(tls, ['utls']);
  const fingerprint = readString(utls, ['fingerprint']) || readString(tls, ['fingerprint', 'client-fingerprint', 'clientFingerprint']);
  if (fingerprint) searchParams.set('fp', fingerprint);
  const alpn = readStringArray(tls, ['alpn']);
  if (alpn.length) searchParams.set('alpn', alpn.join(','));
  const publicKey = readString(reality, ['public_key', 'publicKey', 'public-key']);
  if (publicKey) searchParams.set('pbk', publicKey);
  const shortId = readString(reality, ['short_id', 'shortId', 'short-id']);
  if (shortId) searchParams.set('sid', shortId);
  const spiderX = readString(reality, ['spider_x', 'spiderX', 'spider-x']);
  if (spiderX) searchParams.set('spx', spiderX);
}

function singBoxOutboundToRuntimeTemplate(outbound: Record<string, unknown>, index: number): XrayRuntimeTemplate | null {
  const protocol = toXrayProtocol(readString(outbound, ['type', 'protocol']));
  if (!protocol) return null;
  const host = readString(outbound, ['server', 'address']);
  const port = readPort(outbound, ['server_port', 'serverPort', 'port'], 443);
  const tag = trimLabel(readString(outbound, ['tag', 'name', 'remarks']) || `${protocol}-${index + 1}`);
  if (!host || port === null) return null;

  const tls = readRecord(outbound, ['tls']);
  const transport = readRecord(outbound, ['transport']);
  const searchParams = new URLSearchParams();
  writeTransportParams(searchParams, transport);
  writeTlsParams(searchParams, tls, host);
  const network = normalizeTemplateTransport(searchParams.get('type') || undefined, protocol === 'hysteria2' ? 'udp' : 'raw');

  if (protocol === 'vless' || protocol === 'vmess') {
    const userId = readString(outbound, ['uuid', 'id']);
    if (!looksLikeUuid(userId)) return null;
    return {
      family: 'xray',
      protocol,
      remarks: tag,
      transport: network,
      outbound: compactObject({
        tag: 'proxy',
        protocol,
        settings: {
          vnext: [{
            address: host,
            port,
            users: [{
              id: userId,
              ...(protocol === 'vless'
                ? { encryption: readString(outbound, ['encryption']) || 'none', flow: readString(outbound, ['flow']) }
                : { alterId: parsePort(readString(outbound, ['alter_id', 'alterId']), 0), security: readString(outbound, ['security']) || 'auto' })
            }]
          }]
        },
        streamSettings: buildStreamSettings({ searchParams, host, security: searchParams.get('security') || 'none' })
      })
    };
  }

  if (protocol === 'trojan') {
    const password = readString(outbound, ['password']);
    if (!password) return null;
    return {
      family: 'xray',
      protocol,
      remarks: tag,
      transport: network,
      outbound: compactObject({
        tag: 'proxy',
        protocol: 'trojan',
        settings: { servers: [{ address: host, port, password, level: 0 }] },
        streamSettings: buildStreamSettings({ searchParams, host, security: searchParams.get('security') || 'tls' })
      })
    };
  }

  if (protocol === 'shadowsocks') {
    const method = readString(outbound, ['method', 'cipher']);
    const password = readString(outbound, ['password']);
    if (!method || !password) return null;
    return {
      family: 'xray',
      protocol,
      remarks: tag,
      transport: 'raw',
      outbound: { tag: 'proxy', protocol: 'shadowsocks', settings: { servers: [{ address: host, port, method, password }] } }
    };
  }

  if (protocol === 'hysteria2') {
    const password = readString(outbound, ['password', 'auth']);
    if (!password) return null;
    const obfs = readRecord(outbound, ['obfs']);
    const obfsType = readString(obfs, ['type']) || readString(outbound, ['obfs']);
    const obfsPassword = readString(obfs, ['password']) || readString(outbound, ['obfs_password', 'obfsPassword', 'obfs-password']);
    return {
      family: 'xray',
      protocol,
      remarks: tag,
      transport: 'udp',
      outbound: compactObject({
        tag: 'proxy',
        protocol: 'hysteria',
        settings: { version: 2, address: host, port },
        streamSettings: {
          network: 'hysteria',
          security: 'tls',
          tlsSettings: compactObject({
            serverName: readString(tls, ['server_name', 'serverName', 'servername', 'sni']) || host,
            alpn: readStringArray(tls, ['alpn']).length ? readStringArray(tls, ['alpn']) : ['h3'],
            allowInsecure: readBoolean(tls, ['insecure', 'allowInsecure']) === true
          }),
          hysteriaSettings: { version: 2, auth: password },
          udpmasks: obfsType && obfsPassword ? [{ type: obfsType, settings: { password: obfsPassword } }] : undefined
        }
      })
    };
  }

  return null;
}

function clashProxyToRuntimeTemplate(proxy: Record<string, unknown>, index: number): XrayRuntimeTemplate | null {
  const protocol = toXrayProtocol(readString(proxy, ['type', 'protocol']));
  if (!protocol) return null;
  const host = readString(proxy, ['server', 'address']);
  const port = readPort(proxy, ['port', 'server_port', 'serverPort'], 443);
  const name = trimLabel(readString(proxy, ['name', 'remarks', 'tag']) || `${protocol}-${index + 1}`);
  if (!host || port === null) return null;

  const network = normalizeTemplateTransport(readString(proxy, ['network', 'net']), protocol === 'hysteria2' ? 'udp' : 'raw');
  const searchParams = new URLSearchParams();
  searchParams.set('type', network);
  const wsOpts = readRecord(proxy, ['ws-opts', 'ws_opts', 'wsOpts']);
  const grpcOpts = readRecord(proxy, ['grpc-opts', 'grpc_opts', 'grpcOpts']);
  const realityOpts = readRecord(proxy, ['reality-opts', 'reality_opts', 'realityOpts']);
  if (wsOpts) {
    const wsHeaders = readRecord(wsOpts, ['headers']);
    const path = readString(wsOpts, ['path']);
    const wsHost = readString(wsHeaders, ['Host', 'host']) || readString(wsOpts, ['host']);
    if (path) searchParams.set('path', path);
    if (wsHost) searchParams.set('host', wsHost);
  }
  if (grpcOpts) {
    const serviceName = readString(grpcOpts, ['grpc-service-name', 'serviceName', 'service_name']);
    if (serviceName) searchParams.set('serviceName', serviceName);
  }
  writeTlsParams(searchParams, {
    enabled: readBoolean(proxy, ['tls']) === true || Boolean(realityOpts),
    server_name: readString(proxy, ['servername', 'server_name', 'sni']),
    fingerprint: readString(proxy, ['client-fingerprint', 'clientFingerprint', 'fingerprint']),
    alpn: readFirst(proxy, ['alpn']),
    insecure: readBoolean(proxy, ['skip-cert-verify', 'skipCertVerify', 'allowInsecure', 'insecure']) === true
  }, host, realityOpts);

  if (protocol === 'vless' || protocol === 'vmess') {
    const userId = readString(proxy, ['uuid', 'id']);
    if (!looksLikeUuid(userId)) return null;
    return {
      family: 'xray',
      protocol,
      remarks: name,
      transport: network,
      outbound: compactObject({
        tag: 'proxy',
        protocol,
        settings: { vnext: [{ address: host, port, users: [{ id: userId, ...(protocol === 'vless' ? { encryption: 'none', flow: readString(proxy, ['flow']) } : { alterId: parsePort(readString(proxy, ['alterId', 'alter-id', 'alter_id']), 0), security: readString(proxy, ['cipher']) || 'auto' }) }] }] },
        streamSettings: buildStreamSettings({ searchParams, host, security: searchParams.get('security') || 'none' })
      })
    };
  }

  if (protocol === 'trojan') {
    const password = readString(proxy, ['password']);
    if (!password) return null;
    return { family: 'xray', protocol, remarks: name, transport: network, outbound: compactObject({ tag: 'proxy', protocol: 'trojan', settings: { servers: [{ address: host, port, password, level: 0 }] }, streamSettings: buildStreamSettings({ searchParams, host, security: searchParams.get('security') || 'tls' }) }) };
  }

  if (protocol === 'shadowsocks') {
    const method = readString(proxy, ['cipher', 'method']);
    const password = readString(proxy, ['password']);
    if (!method || !password) return null;
    return { family: 'xray', protocol, remarks: name, transport: 'raw', outbound: { tag: 'proxy', protocol: 'shadowsocks', settings: { servers: [{ address: host, port, method, password }] } } };
  }

  if (protocol === 'hysteria2') {
    const password = readString(proxy, ['password', 'auth']);
    if (!password) return null;
    const obfsType = readString(proxy, ['obfs', 'obfs-type', 'obfs_type']);
    const obfsPassword = readString(proxy, ['obfs-password', 'obfs_password', 'obfsPassword']);
    return { family: 'xray', protocol, remarks: name, transport: 'udp', outbound: compactObject({ tag: 'proxy', protocol: 'hysteria', settings: { version: 2, address: host, port }, streamSettings: { network: 'hysteria', security: 'tls', tlsSettings: compactObject({ serverName: readString(proxy, ['sni', 'servername', 'server_name']) || host, alpn: readStringArray(proxy, ['alpn']).length ? readStringArray(proxy, ['alpn']) : ['h3'], allowInsecure: readBoolean(proxy, ['skip-cert-verify', 'allowInsecure', 'insecure']) === true }), hysteriaSettings: { version: 2, auth: password }, udpmasks: obfsType && obfsPassword ? [{ type: obfsType, settings: { password: obfsPassword } }] : undefined } }) };
  }

  return null;
}

function stripYamlInlineComment(value: string) {
  let quote: string | null = null;
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if ((char === '"' || char === "'") && value[index - 1] !== '\\') quote = quote === char ? null : (quote ? quote : char);
    if (char === '#' && !quote && (index === 0 || /\s/.test(value[index - 1]))) return value.slice(0, index).trimEnd();
  }
  return value.trimEnd();
}

function splitInlineYaml(value: string) {
  const items: string[] = [];
  let quote: string | null = null;
  let depth = 0;
  let current = '';
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if ((char === '"' || char === "'") && value[index - 1] !== '\\') quote = quote === char ? null : (quote ? quote : char);
    else if (!quote && (char === '{' || char === '[')) depth += 1;
    else if (!quote && (char === '}' || char === ']')) depth = Math.max(0, depth - 1);
    if (char === ',' && !quote && depth === 0) {
      items.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  if (current.trim()) items.push(current.trim());
  return items;
}

function parseYamlScalar(rawValue: string): unknown {
  const value = stripYamlInlineComment(rawValue).trim();
  if (!value) return '';
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) return value.slice(1, -1);
  if (value.startsWith('{') && value.endsWith('}')) {
    const record: Record<string, unknown> = {};
    for (const item of splitInlineYaml(value.slice(1, -1))) {
      const separator = item.indexOf(':');
      if (separator > 0) record[item.slice(0, separator).trim()] = parseYamlScalar(item.slice(separator + 1));
    }
    return record;
  }
  if (value.startsWith('[') && value.endsWith(']')) return splitInlineYaml(value.slice(1, -1)).map(parseYamlScalar);
  if (/^(true|false)$/i.test(value)) return value.toLowerCase() === 'true';
  if (/^null$/i.test(value)) return null;
  if (/^-?\d+(?:\.\d+)?$/.test(value)) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return numeric;
  }
  return value;
}

function parseYamlKeyValue(value: string): { key: string; value: string } | null {
  const match = value.match(/^([A-Za-z0-9_.:-]+)\s*:\s*(.*)$/);
  return match ? { key: match[1], value: match[2] ?? '' } : null;
}

function parseClashYamlProxyObjects(text: string): Record<string, unknown>[] {
  const lines = text.replace(/\r/g, '').split('\n');
  const proxiesStart = lines.findIndex((line) => /^\s*proxies\s*:/i.test(line));
  if (proxiesStart === -1) return [];
  const proxiesIndent = lines[proxiesStart].match(/^\s*/)?.[0].length ?? 0;
  const proxies: Record<string, unknown>[] = [];
  let current: Record<string, unknown> | null = null;
  let stack: Array<{ indent: number; target: Record<string, unknown> }> = [];
  const pushCurrent = () => { if (current && Object.keys(current).length) proxies.push(current); };

  for (let index = proxiesStart + 1; index < lines.length; index += 1) {
    const rawLine = lines[index];
    if (!rawLine.trim() || rawLine.trim().startsWith('#')) continue;
    const indent = rawLine.match(/^\s*/)?.[0].length ?? 0;
    const trimmed = rawLine.trim();
    if (indent <= proxiesIndent && !trimmed.startsWith('-')) break;
    if (trimmed.startsWith('- ')) {
      pushCurrent();
      current = {};
      stack = [];
      const parsed = parseYamlKeyValue(trimmed.slice(2).trim());
      if (parsed) current[parsed.key] = parseYamlScalar(parsed.value);
      continue;
    }
    if (!current) continue;
    while (stack.length && indent <= stack[stack.length - 1].indent) stack.pop();
    const parsed = parseYamlKeyValue(trimmed);
    if (!parsed) continue;
    const target = stack.length ? stack[stack.length - 1].target : current;
    if (parsed.value.trim() === '') {
      const nested: Record<string, unknown> = {};
      target[parsed.key] = nested;
      stack.push({ indent, target: nested });
    } else {
      target[parsed.key] = parseYamlScalar(parsed.value);
    }
  }
  pushCurrent();
  return proxies.slice(0, MAX_IMPORTED_SERVERS);
}

function parseJsonTemplateToServers(text: string): VpnServer[] {
  const trimmed = text.trim();
  if (!trimmed || (!trimmed.startsWith('{') && !trimmed.startsWith('['))) return [];
  let parsed: unknown;
  try { parsed = JSON.parse(trimmed); } catch { return []; }
  const servers: VpnServer[] = [];
  const roots = Array.isArray(parsed) ? parsed : [parsed];
  for (const root of roots) {
    const record = asRecord(root);
    if (!record) continue;
    for (const outbound of asArray(record.outbounds).map(asRecord).filter((item): item is Record<string, unknown> => Boolean(item))) {
      const runtimeTemplate = xrayOutboundToRuntimeTemplate(outbound, servers.length) || singBoxOutboundToRuntimeTemplate(outbound, servers.length);
      const server = runtimeTemplate ? buildServerFromRuntimeTemplate(runtimeTemplate, servers.length, JSON.stringify(outbound), runtimeTemplate.remarks) : null;
      if (server) servers.push(server);
      if (servers.length >= MAX_IMPORTED_SERVERS) return withUniqueSubscriptionIds(servers);
    }
    for (const proxy of asArray(record.proxies).map(asRecord).filter((item): item is Record<string, unknown> => Boolean(item))) {
      const runtimeTemplate = clashProxyToRuntimeTemplate(proxy, servers.length);
      const server = runtimeTemplate ? buildServerFromRuntimeTemplate(runtimeTemplate, servers.length, JSON.stringify(proxy), runtimeTemplate.remarks) : null;
      if (server) servers.push(server);
      if (servers.length >= MAX_IMPORTED_SERVERS) return withUniqueSubscriptionIds(servers);
    }
    const singleRuntime = xrayOutboundToRuntimeTemplate(record, servers.length) || singBoxOutboundToRuntimeTemplate(record, servers.length) || clashProxyToRuntimeTemplate(record, servers.length);
    const singleServer = singleRuntime ? buildServerFromRuntimeTemplate(singleRuntime, servers.length, JSON.stringify(record), singleRuntime.remarks) : null;
    if (singleServer) servers.push(singleServer);
  }
  return withUniqueSubscriptionIds(servers.slice(0, MAX_IMPORTED_SERVERS));
}

function parseYamlTemplateToServers(text: string): VpnServer[] {
  const servers: VpnServer[] = [];
  for (const proxy of parseClashYamlProxyObjects(text)) {
    const runtimeTemplate = clashProxyToRuntimeTemplate(proxy, servers.length);
    const server = runtimeTemplate ? buildServerFromRuntimeTemplate(runtimeTemplate, servers.length, JSON.stringify(proxy), runtimeTemplate.remarks) : null;
    if (server) servers.push(server);
    if (servers.length >= MAX_IMPORTED_SERVERS) break;
  }
  return withUniqueSubscriptionIds(servers);
}

function parseUriSubscriptionToServers(text: string): VpnServer[] {
  const uriMatches = deepCollectUris(text).filter((line) => line.length <= MAX_URI_LENGTH).slice(0, MAX_IMPORTED_SERVERS);
  const lines = uriMatches.length ? uriMatches : text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /^(?:vless|vmess|trojan|ss|hy2|hysteria2):\/\//i.test(line) && line.length <= MAX_URI_LENGTH)
    .slice(0, MAX_IMPORTED_SERVERS);
  const importedServers = lines
    .map((line, index) => buildImportedServer(line, index))
    .filter((item): item is VpnServer => Boolean(item))
    .slice(0, MAX_IMPORTED_SERVERS);
  return withUniqueSubscriptionIds(importedServers);
}

export function parseSubscriptionToServers(rawText: string): VpnServer[] {
  const safeRawText = rawText.length > MAX_SUBSCRIPTION_BYTES ? rawText.slice(0, MAX_SUBSCRIPTION_BYTES) : rawText;
  const extracted = maybeDecodeBase64(extractRawText(safeRawText)).replace(/^\uFEFF/u, '').trim();
  const uriServers = parseUriSubscriptionToServers(extracted);
  if (uriServers.length) return uriServers;
  const jsonServers = parseJsonTemplateToServers(extracted);
  if (jsonServers.length) return jsonServers;
  return parseYamlTemplateToServers(extracted);
}
