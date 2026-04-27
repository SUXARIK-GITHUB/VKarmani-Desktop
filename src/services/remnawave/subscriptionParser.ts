import type { VpnServer, XrayRuntimeTemplate } from '../../types/vpn';
import { inferCountryCode, resolveServerFlag } from '../../utils/serverDisplay';
import { decodeBase64Compat, maybeDecodeBase64, parsePort, splitHostPort } from './parserCore';

function deepFindString(source: unknown, keys: string[]): string | undefined {
  if (!source || typeof source !== 'object') {
    return undefined;
  }

  const record = source as Record<string, unknown>;
  for (const key of keys) {
    if (typeof record[key] === 'string' && record[key]) {
      return record[key] as string;
    }
  }

  for (const value of Object.values(record)) {
    const nested = deepFindString(value, keys);
    if (nested) {
      return nested;
    }
  }

  return undefined;
}

function deepCollectUris(source: unknown, collected: string[] = []): string[] {
  if (typeof source === 'string') {
    const matches = source.match(/(?:vless|vmess|trojan|ss|hy2|hysteria2):\/\/[^\s"'<>`]+/gi) ?? [];
    for (const match of matches) {
      if (!collected.includes(match.trim())) {
        collected.push(match.trim());
      }
    }
    return collected;
  }

  if (Array.isArray(source)) {
    for (const item of source) deepCollectUris(item, collected);
    return collected;
  }

  if (source && typeof source === 'object') {
    for (const value of Object.values(source as Record<string, unknown>)) deepCollectUris(value, collected);
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
  return [...new Set(matches.map((item) => item.trim()))];
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

  const parts = cleaned.split(/[|/]/).map((item) => item.trim()).filter(Boolean);
  const countryPart = parts[0] ?? cleaned;
  const codeMatch = countryPart.match(/^([A-Z]{2})\s+(.+)$/);
  const explicitCode = codeMatch?.[1];
  const country = (codeMatch?.[2] ?? countryPart).trim();
  const countryCode = inferCountryCode({
    country,
    rawLabel: label,
    host,
    explicitCode
  });

  const cityPart = parts.length >= 2 ? parts[1] : '';

  return {
    country,
    city: cityPart && cityPart !== host ? cityPart : '',
    countryCode
  };
}

function compactObject<T>(value: T): T {
  if (Array.isArray(value)) {
    return value
      .map((item) => compactObject(item))
      .filter((item) => item !== undefined && item !== null && item !== '') as T;
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .map(([key, nested]) => [key, compactObject(nested)])
        .filter(([, nested]) => nested !== undefined && nested !== null && nested !== '')
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

function parseVlessRuntime(uri: string, url: URL, label: string): XrayRuntimeTemplate {
  const searchParams = url.searchParams;
  const user = compactObject({
    id: decodeURIComponent(url.username),
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
            address: normalizeUrlHostname(url.hostname),
            port: parsePort(url.port, 443),
            users: [user]
          }
        ]
      },
      streamSettings: buildStreamSettings({
        searchParams,
        host: getFirstParam(searchParams, ['host', 'authority']) || normalizeUrlHostname(url.hostname)
      })
    })
  };
}

function parseVmessRuntime(uri: string, label: string): XrayRuntimeTemplate | null {
  const encoded = uri.replace(/^vmess:\/\//i, '');
  try {
    const decoded = JSON.parse(decodeBase64Compat(encoded)) as Record<string, string>;
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
              address: decoded.add,
              port: parsePort(decoded.port, 443),
              users: [
                {
                  id: decoded.id,
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

function parseTrojanRuntime(url: URL, label: string): XrayRuntimeTemplate {
  const searchParams = url.searchParams;
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
            address: normalizeUrlHostname(url.hostname),
            port: parsePort(url.port, 443),
            password: decodeURIComponent(url.username),
            level: 0
          }
        ]
      },
      streamSettings: buildStreamSettings({
        searchParams,
        host: getFirstParam(searchParams, ['host', 'authority']) || normalizeUrlHostname(url.hostname),
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
  if (!credentials || !hostPart) {
    return null;
  }

  const { address, portRaw } = splitHostPort(hostPart);

  if (!address) {
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
            port: parsePort(portRaw, 443),
            method: credentials.method,
            password: credentials.password
          }
        ]
      }
    })
  };
}

function parseHysteria2Runtime(url: URL, label: string): XrayRuntimeTemplate {
  const searchParams = url.searchParams;
  const password = decodeURIComponent(url.username || getFirstParam(searchParams, ['password', 'auth']) || '');
  const obfsType = getFirstParam(searchParams, ['obfs', 'obfs-type', 'obfs_type']) || undefined;
  const obfsPassword = getFirstParam(searchParams, ['obfs-password', 'obfs_password', 'obfsPassword']) || undefined;
  const sni = getFirstParam(searchParams, ['sni', 'peer', 'serverName', 'servername']) || normalizeUrlHostname(url.hostname);
  const insecure = searchParams.get('insecure') === '1' || searchParams.get('allowInsecure') === '1';

  return {
    family: 'xray',
    protocol: 'hysteria2',
    remarks: label,
    transport: 'udp',
    outbound: compactObject({
      tag: 'proxy',
      protocol: 'hysteria2',
      settings: {
        servers: [
          compactObject({
            address: normalizeUrlHostname(url.hostname),
            port: parsePort(url.port, 443),
            password,
            obfs: obfsType ? { type: obfsType, password: obfsPassword } : undefined
          })
        ]
      },
      streamSettings: compactObject({
        network: 'udp',
        security: 'tls',
        tlsSettings: compactObject({
          serverName: sni,
          fingerprint: getFirstParam(searchParams, ['fp', 'fingerprint']) ?? undefined,
          alpn: splitCsv(searchParams.get('alpn')),
          allowInsecure: insecure
        })
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
    | { vnext?: Array<{ address?: string; port?: number }>; servers?: Array<{ address?: string; port?: number }> }
    | undefined;

  const vnext = settings?.vnext?.[0];
  if (vnext?.address) {
    return {
      host: vnext.address,
      port: typeof vnext.port === 'number' ? vnext.port : 443
    };
  }

  const server = settings?.servers?.[0];
  if (server?.address) {
    return {
      host: server.address,
      port: typeof server.port === 'number' ? server.port : 443
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
  const runtimeEndpoint = extractRuntimeEndpoint(runtimeTemplate);
  const transportLabel = runtimeTemplate?.transport ? runtimeTemplate.transport.toUpperCase() : undefined;
  const protocol = runtimeTemplate
    ? parseProtocol(runtimeTemplate.protocol)
    : parseProtocol(trimmed.split('://')[0]?.replace(':', '') ?? 'unknown');

  try {
    const url = new URL(trimmed);
    const label = decodeURIComponent(url.hash.replace(/^#/, '')).trim() || runtimeTemplate?.remarks?.trim() || '';
    const host = runtimeEndpoint.host || normalizeUrlHostname(url.hostname) || 'remote-host';
    const port = runtimeEndpoint.port || (url.port ? Number(url.port) : 443);
    const location = parseCountryLabel(label, host);
    const flag = resolveServerFlag({ country: location.country, rawLabel: label, host, explicitCode: location.countryCode });
    const runtimeReady = Boolean(runtimeTemplate);

    return {
      id: `subscription-${index}-${host}-${port}`,
      country: location.country,
      city: location.city,
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

    const label = runtimeTemplate.remarks?.trim() || '';
    const host = runtimeEndpoint.host;
    const port = runtimeEndpoint.port || 443;
    const location = parseCountryLabel(label, host);
    const flag = resolveServerFlag({ country: location.country, rawLabel: label, host, explicitCode: location.countryCode });
    const runtimeReady = Boolean(runtimeTemplate);

    return {
      id: `subscription-${index}-${host}-${port}`,
      country: location.country,
      city: location.city,
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

export function parseSubscriptionToServers(rawText: string): VpnServer[] {
  const extracted = maybeDecodeBase64(extractRawText(rawText));
  const lines = extracted
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  return lines
    .map((line, index) => buildImportedServer(line, index))
    .filter((item): item is VpnServer => Boolean(item));
}
