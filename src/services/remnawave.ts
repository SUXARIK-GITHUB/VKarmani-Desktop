import { demoDiagnostics } from '../data/diagnostics';
import { demoSessionHistory } from '../data/sessions';
import type {
  AccessKeyKind,
  ConnectResult,
  ConnectivityProbe,
  DeviceRecord,
  DiagnosticsSnapshot,
  ProxyStatus,
  ProfileSyncInfo,
  RemnawaveSession,
  RemnawaveSource,
  RuntimeStatus,
  SessionRecord,
  SplitTunnelEntry,
  TunnelMode,
  VpnServer,
  XrayRuntimeTemplate
} from '../types/vpn';
import {
  allowDemoFallbackByEnv,
  appVersion,
  cacheNativeProfileSync,
  fetchRemoteJson,
  fetchRemoteText,
  getIntegrationMeta,
  getNativeProxyStatus,
  getNativeRuntimeStatus,
  isTauriRuntime,
  readNativeRuntimeLog,
  remnawavePanelUrl,
  remnawaveSubscriptionUrl,
  requestNativeConnect,
  requestNativeDisconnect,
  runNativeConnectivityProbe,
  setNativeSystemProxy
} from './runtime';
import { inferCountryCode, resolveServerFlag } from '../utils/serverDisplay';

const delay = (value: number) => new Promise<void>((resolve) => window.setTimeout(resolve, value));
const REQUEST_TIMEOUT_MS = 4500;

interface ResolvedAccessKey {
  rawInput: string;
  normalized: string;
  identifier: string;
  shortUuid?: string;
  kind: AccessKeyKind;
}

interface CandidateResult<T> {
  value: T;
  url: string;
}

function trimSlashes(value: string) {
  return value.replace(/\/+$/g, '');
}

function normalizeBaseUrl(value?: string) {
  return value ? trimSlashes(value.trim()) : '';
}

function maybeString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function maybeNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string') {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }

  return undefined;
}

function readPath(source: unknown, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = source;

  for (const part of parts) {
    if (!current || typeof current !== 'object' || !(part in (current as Record<string, unknown>))) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }

  return current;
}

function pickValue(source: unknown, paths: string[]) {
  for (const path of paths) {
    const value = readPath(source, path);
    if (value !== undefined && value !== null && value !== '') {
      return value;
    }
  }
  return undefined;
}

function formatDate(value: unknown) {
  if (!value) {
    return '—';
  }

  const format = (date: Date, withTime = false) =>
    withTime ? date.toLocaleString('ru-RU') : date.toLocaleDateString('ru-RU');

  if (typeof value === 'number') {
    const date = new Date(value > 10_000_000_000 ? value : value * 1000);
    return Number.isNaN(date.getTime()) ? 'Неизвестно' : format(date, true);
  }

  if (typeof value === 'string') {
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) {
      const withTime = /[tT]\d{2}:\d{2}|\d{2}:\d{2}/.test(value);
      return format(date, withTime);
    }

    return value;
  }

  return 'Неизвестно';
}


function detectCurrentPlatform() {
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('windows')) return 'Windows';
  if (ua.includes('mac os')) return 'macOS';
  if (ua.includes('android')) return 'Android';
  if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ios')) return 'iOS';
  if (ua.includes('linux')) return 'Linux';
  return navigator.platform || 'Desktop';
}

function detectCurrentDeviceName() {
  const platform = detectCurrentPlatform();
  if (platform === 'Android' || platform === 'iOS') return 'VKarmani Mobile';
  if (platform === 'Windows' || platform === 'macOS' || platform === 'Linux') return 'VKarmani Desktop';
  return 'VKarmani Device';
}

function detectCurrentLocationLabel() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'Локально';
  } catch {
    return 'Локально';
  }
}

function mapDeviceRecord(payload: unknown, index: number): DeviceRecord | null {
  if (!payload || typeof payload !== 'object') {
    return null;
  }

  const id = maybeString(pickValue(payload, ['id', 'hwid', 'deviceId', 'uuid'])) ?? `panel-device-${index}`;
  const name = maybeString(pickValue(payload, ['name', 'deviceName', 'deviceModel', 'model'])) ?? `Устройство ${index + 1}`;
  const platform = maybeString(pickValue(payload, ['platform', 'os', 'deviceOs', 'deviceOS'])) ?? 'Не указано';
  const location = maybeString(pickValue(payload, ['location', 'region', 'country'])) ?? 'Панель Remnawave';
  const lastSeen = formatDate(pickValue(payload, ['lastSeenAt', 'updatedAt', 'createdAt', 'lastSeen']));
  const isCurrent = Boolean(pickValue(payload, ['isCurrent', 'current']));
  const isOnline = Boolean(pickValue(payload, ['isOnline', 'online', 'active']));

  return {
    id,
    name,
    platform,
    location,
    lastSeen,
    status: isOnline || isCurrent ? 'online' : 'offline',
    isCurrent,
    reportedByPanel: true
  };
}

function extractDevicesFromPayload(payload: unknown): DeviceRecord[] {
  const candidates = [
    pickValue(payload, ['response.devices', 'response.user.devices', 'response.hwidDevices', 'response.user.hwidDevices']),
    readPath(payload, 'devices'),
    readPath(payload, 'user.devices')
  ];

  for (const candidate of candidates) {
    if (Array.isArray(candidate)) {
      const mapped = candidate.map((item, index) => mapDeviceRecord(item, index)).filter((item): item is DeviceRecord => Boolean(item));
      if (mapped.length) {
        return mapped;
      }
    }
  }

  return [];
}

function buildLocalDeviceRecord(): DeviceRecord {
  return {
    id: 'current-device',
    name: detectCurrentDeviceName(),
    platform: detectCurrentPlatform(),
    location: detectCurrentLocationLabel(),
    lastSeen: 'Только что',
    status: 'online',
    isCurrent: true,
    reportedByPanel: false,
    note: 'Локально подтверждённое устройство VKarmani.'
  };
}

function bytesToGb(value: unknown, fallback: number) {
  const bytes = maybeNumber(value);
  if (bytes === undefined) {
    return fallback;
  }

  return Math.max(0, Math.round((bytes / 1024 / 1024 / 1024) * 10) / 10);
}

function makeDemoSession(accessKey: string): RemnawaveSession {
  const suffix = accessKey.trim().slice(-4).toUpperCase() || 'USER';

  return {
    accessKey,
    userId: `vk-${suffix}`,
    displayName: 'VKarmani',
    loginHint: '',
    deviceLimit: 3,
    source: 'demo',
    plan: {
      title: 'Персональный доступ',
      expiresAt: '31.12.2026',
      trafficUsedGb: 124,
      trafficLimitGb: 500,
      devices: 3
    }
  };
}

function makeProvisionalSession(accessKey: string, key: ResolvedAccessKey): RemnawaveSession {
  return {
    accessKey,
    userId: key.identifier,
    displayName: 'VKarmani',
    loginHint: '',
    deviceLimit: 3,
    source: 'public-api',
    shortUuid: key.shortUuid,
    subscriptionUrl: key.kind === 'url' ? key.normalized : undefined,
    rawSubscriptionUrl: key.kind === 'url' ? `${key.normalized.replace(/\/+$/g, '')}/raw` : undefined,
    plan: {
      title: 'Подписка VKarmani',
      expiresAt: '—',
      trafficUsedGb: 0,
      trafficLimitGb: 0,
      devices: 3
    }
  };
}

function looksLikeUuid(value: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function looksLikeShortUuid(value: string) {
  return /^[A-Za-z0-9_-]{5,64}$/.test(value);
}

function resolveAccessKey(rawInput: string): ResolvedAccessKey {
  const normalized = rawInput.trim();
  if (!normalized) {
    throw new Error('Введите ключ доступа.');
  }

  try {
    const url = new URL(normalized);
    const pathname = url.pathname.replace(/\/+$/g, '');
    const parts = pathname.split('/').filter(Boolean);
    const identifier = parts[parts.length - 1] ?? '';
    if (!identifier) {
      throw new Error();
    }

    return {
      rawInput,
      normalized,
      identifier,
      shortUuid: looksLikeUuid(identifier) ? undefined : identifier,
      kind: 'url'
    };
  } catch {
    if (looksLikeUuid(normalized)) {
      return {
        rawInput,
        normalized,
        identifier: normalized,
        kind: 'uuid'
      };
    }

    if (looksLikeShortUuid(normalized)) {
      return {
        rawInput,
        normalized,
        identifier: normalized,
        shortUuid: normalized,
        kind: 'short-uuid'
      };
    }
  }

  return {
    rawInput,
    normalized,
    identifier: normalized,
    shortUuid: normalized,
    kind: 'raw'
  };
}

function buildUrlDerivedCandidates(rawUrl: string, shortUuid?: string) {
  const candidates: string[] = [];

  try {
    const url = new URL(rawUrl);
    const base = `${url.origin}${url.pathname.replace(/\/+$/g, '')}`;
    const origin = url.origin;

    candidates.push(base);
    if (!base.endsWith('/info')) {
      candidates.push(`${base}/info`);
    }
    if (!base.endsWith('/raw')) {
      candidates.push(`${base}/raw`);
    }

    if (shortUuid) {
      candidates.push(`${origin}/api/sub/${shortUuid}/info`);
      candidates.push(`${origin}/api/sub/${shortUuid}/raw`);
      candidates.push(`${origin}/api/subscriptions/by-short-uuid/${shortUuid}`);
      candidates.push(`${origin}/api/subscriptions/by-short-uuid/${shortUuid}/raw`);
    }
  } catch {
    // ignore malformed URL here; resolver handles validation separately.
  }

  return candidates;
}

function buildInfoCandidates(key: ResolvedAccessKey) {
  const panel = normalizeBaseUrl(remnawavePanelUrl);
  const subscription = normalizeBaseUrl(remnawaveSubscriptionUrl);
  const candidates: string[] = [];
  const shortUuid = key.shortUuid ?? key.identifier;

  if (key.kind === 'url') {
    candidates.push(...buildUrlDerivedCandidates(key.normalized, shortUuid));
  }

  if (subscription && shortUuid) {
    candidates.push(`${subscription}/api/sub/${shortUuid}/info`);
  }

  if (panel && shortUuid) {
    candidates.push(`${panel}/api/sub/${shortUuid}/info`);
    candidates.push(`${panel}/api/subscriptions/by-short-uuid/${shortUuid}`);
  }

  if (panel && looksLikeUuid(key.identifier)) {
    candidates.push(`${panel}/api/subscriptions/by-uuid/${key.identifier}`);
  }

  return [...new Set(candidates)];
}

function buildRawCandidates(key: ResolvedAccessKey, session?: RemnawaveSession | null) {
  const panel = normalizeBaseUrl(remnawavePanelUrl);
  const subscription = normalizeBaseUrl(remnawaveSubscriptionUrl);
  const candidates: string[] = [];
  const shortUuid = session?.shortUuid ?? key.shortUuid ?? key.identifier;

  if (key.kind === 'url') {
    candidates.push(...buildUrlDerivedCandidates(key.normalized, shortUuid));
  }

  if (session?.rawSubscriptionUrl) {
    candidates.push(session.rawSubscriptionUrl);
  }

  if (session?.subscriptionUrl) {
    candidates.push(session.subscriptionUrl);
    candidates.push(...buildUrlDerivedCandidates(session.subscriptionUrl, shortUuid));
  }

  if (subscription && shortUuid) {
    candidates.push(`${subscription}/api/sub/${shortUuid}/raw`);
  }

  if (panel && shortUuid) {
    candidates.push(`${panel}/api/subscriptions/by-short-uuid/${shortUuid}/raw`);
    candidates.push(`${panel}/api/sub/${shortUuid}/raw`);
  }

  return [...new Set(candidates)];
}

async function fetchJsonCandidates(urls: string[]): Promise<CandidateResult<unknown>> {
  let lastError = 'Нет ответа от Remnawave.';

  for (const url of urls) {
    try {
      return {
        value: await fetchRemoteJson(url),
        url
      };
    } catch (error) {
      lastError = error instanceof Error ? error.message : 'Ошибка сети.';
    }
  }

  throw new Error(lastError);
}

async function fetchTextCandidates(urls: string[]): Promise<CandidateResult<string>> {
  let lastError = 'Не удалось получить raw subscription.';

  for (const url of urls) {
    try {
      return {
        value: await fetchRemoteText(url),
        url
      };
    } catch (error) {
      lastError = error instanceof Error ? error.message : 'Ошибка сети.';
    }
  }

  throw new Error(lastError);
}

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
    const matches = source.match(/(?:vless|vmess|trojan|ss):\/\/[^\s"'<>`]+/gi) ?? [];
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
  const matches = decoded.match(/(?:vless|vmess|trojan|ss):\/\/[^\s"'<>`]+/gi) ?? [];
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

function maybeDecodeBase64(value: string) {
  const compact = value.replace(/\s+/g, '');
  const looksLikeBase64 = /^[A-Za-z0-9+/=]+$/.test(compact) && compact.length % 4 === 0;
  if (!looksLikeBase64 || compact.includes('://')) {
    return value;
  }

  try {
    const decoded = atob(compact);
    return decoded.includes('://') || decoded.includes('\n') ? decoded : value;
  } catch {
    return value;
  }
}

function parseProtocol(protocol: string): VpnServer['protocol'] {
  switch (protocol.toLowerCase()) {
    case 'reality':
      return 'Reality';
    case 'vless':
      return 'VLESS';
    case 'hy2':
    case 'hysteria2':
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

function parsePort(value: string | null, fallback: number) {
  const parsed = Number(value ?? '');
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function buildTlsSettings(searchParams: URLSearchParams, fallbackServerName?: string) {
  const serverName = searchParams.get('sni') || searchParams.get('host') || fallbackServerName;
  return compactObject({
    serverName,
    fingerprint: searchParams.get('fp') ?? undefined,
    alpn: splitCsv(searchParams.get('alpn')),
    allowInsecure: searchParams.get('allowInsecure') === '1' || searchParams.get('insecure') === '1'
  });
}

function buildRealitySettings(searchParams: URLSearchParams, fallbackServerName?: string) {
  return compactObject({
    serverName: searchParams.get('sni') || searchParams.get('host') || fallbackServerName,
    fingerprint: searchParams.get('fp') ?? undefined,
    publicKey: searchParams.get('pbk') ?? undefined,
    shortId: searchParams.get('sid') ?? undefined,
    spiderX: searchParams.get('spx') ?? undefined
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
  const network = requestedNetwork === 'tcp' ? 'raw' : requestedNetwork;
  const security = base.security || base.searchParams.get('security') || (base.searchParams.get('tls') === 'tls' ? 'tls' : 'none');
  const host = base.host || base.searchParams.get('host') || undefined;
  const path = base.path || base.searchParams.get('path') || undefined;
  const serviceName = base.serviceName || base.searchParams.get('serviceName') || base.searchParams.get('service_name') || undefined;

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
      mode: base.searchParams.get('mode') || 'auto'
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
    transport: (searchParams.get('type') || searchParams.get('net') || 'raw') as XrayRuntimeTemplate['transport'],
    outbound: compactObject({
      tag: 'proxy',
      protocol: 'vless',
      settings: {
        vnext: [
          {
            address: url.hostname,
            port: parsePort(url.port, 443),
            users: [user]
          }
        ]
      },
      streamSettings: buildStreamSettings({
        searchParams,
        host: searchParams.get('host') || url.hostname
      })
    })
  };
}

function parseVmessRuntime(uri: string, label: string): XrayRuntimeTemplate | null {
  const encoded = uri.replace(/^vmess:\/\//i, '');
  try {
    const decoded = JSON.parse(atob(encoded)) as Record<string, string>;
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
      transport: (decoded.net || 'raw') as XrayRuntimeTemplate['transport'],
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
    transport: (searchParams.get('type') || searchParams.get('net') || 'raw') as XrayRuntimeTemplate['transport'],
    outbound: compactObject({
      tag: 'proxy',
      protocol: 'trojan',
      settings: {
        servers: [
          {
            address: url.hostname,
            port: parsePort(url.port, 443),
            password: decodeURIComponent(url.username),
            level: 0
          }
        ]
      },
      streamSettings: buildStreamSettings({
        searchParams,
        host: searchParams.get('host') || url.hostname,
        security: searchParams.get('security') || 'tls'
      })
    })
  };
}

function decodeShadowsocksCredentials(value: string) {
  const raw = value.includes(':') ? value : (() => {
    try {
      return atob(value);
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
  const [mainPart] = withoutScheme.split('#');

  let credentialsPart = mainPart;
  let hostPart = '';

  if (mainPart.includes('@')) {
    [credentialsPart, hostPart] = mainPart.split('@');
  } else {
    try {
      const decoded = atob(mainPart);
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

  const [address, portRaw] = hostPart.split(':');

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
    const host = runtimeEndpoint.host || url.hostname || 'remote-host';
    const port = runtimeEndpoint.port || (url.port ? Number(url.port) : 443);
    const location = parseCountryLabel(label, host);
    const flag = resolveServerFlag({ country: location.country, rawLabel: label, host, explicitCode: location.countryCode });
    const runtimeReady = Boolean(runtimeTemplate);

    return {
      id: `subscription-${index}-${host}-${port}`,
      country: location.country,
      city: location.city,
      flag,
      latency: 18 + (index % 5) * 7,
      load: 26 + (index % 4) * 11,
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
      latency: 18 + (index % 5) * 7,
      load: 26 + (index % 4) * 11,
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

function parseSubscriptionToServers(rawText: string): VpnServer[] {
  const extracted = maybeDecodeBase64(extractRawText(rawText));
  const lines = extracted
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  return lines
    .map((line, index) => buildImportedServer(line, index))
    .filter((item): item is VpnServer => Boolean(item));
}

function mapSessionFromPayload(
  accessKey: string,
  key: ResolvedAccessKey,
  payload: unknown,
  source: RemnawaveSource,
  infoUrl: string
): RemnawaveSession {
  const displayName = maybeString(pickValue(payload, [
    'response.user.username',
    'response.username',
    'response.user.email',
    'response.user.telegramUsername',
    'user.username',
    'username'
  ])) ?? 'VKarmani';

  const userId = maybeString(pickValue(payload, [
    'response.user.uuid',
    'response.uuid',
    'user.uuid',
    'uuid'
  ])) ?? key.identifier;

  const shortUuid = maybeString(pickValue(payload, [
    'response.shortUuid',
    'response.user.shortUuid',
    'shortUuid'
  ])) ?? key.shortUuid;

  const trafficLimitGb = bytesToGb(pickValue(payload, [
    'response.trafficLimitBytes',
    'response.user.trafficLimitBytes',
    'response.subscription.trafficLimitBytes',
    'response.trafficLimit',
    'response.user.trafficLimit'
  ]), 500);

  const trafficUsedGb = bytesToGb(pickValue(payload, [
    'response.usedTrafficBytes',
    'response.user.usedTrafficBytes',
    'response.subscription.usedTrafficBytes',
    'response.usedTraffic',
    'response.user.usedTraffic'
  ]), 0);

  const deviceLimit = maybeNumber(pickValue(payload, [
    'response.hwidDeviceLimit',
    'response.user.hwidDeviceLimit',
    'response.deviceLimit',
    'response.user.deviceLimit'
  ])) ?? 3;

  const usedDeviceCount = maybeNumber(pickValue(payload, [
    'response.hwidDevicesCount',
    'response.user.hwidDevicesCount',
    'response.devicesCount',
    'response.user.devicesCount',
    'response.usedDevices',
    'response.user.usedDevices',
    'response.connectedDevices',
    'response.user.connectedDevices'
  ])) ?? (() => {
    const devices = extractDevicesFromPayload(payload);
    return devices.length ? devices.length : 0;
  })();

  const subscriptionUrl = maybeString(pickValue(payload, [
    'response.subscriptionUrl',
    'response.user.subscriptionUrl',
    'subscriptionUrl'
  ]));

  const baseForRaw = normalizeBaseUrl(remnawaveSubscriptionUrl || remnawavePanelUrl);

  return {
    accessKey,
    userId,
    displayName,
    deviceLimit,
    source,
    shortUuid,
    subscriptionUrl,
    rawSubscriptionUrl: shortUuid && baseForRaw ? `${baseForRaw}/api/sub/${shortUuid}/raw` : undefined,
    loginHint:
      source === 'public-api'
        ? `Профиль получен через публичный subscription-endpoint: ${infoUrl}`
        : 'Профиль получен через панель Remnawave.',
    plan: {
      title: maybeString(pickValue(payload, [
        'response.planName',
        'response.plan.name',
        'response.user.planName',
        'response.subscription.profileTitle'
      ])) ?? 'Активная подписка',
      expiresAt: formatDate(pickValue(payload, [
        'response.expireAt',
        'response.expiresAt',
        'response.expiryAt',
        'response.expiryDate',
        'response.expire',
        'response.expiredAt',
        'response.expirationDate',
        'response.subscription.expireAt',
        'response.subscription.expiresAt',
        'response.subscription.expiryAt',
        'response.subscription.expiryDate',
        'response.subscription.expire',
        'response.subscription.expiredAt',
        'response.subscription.expirationDate',
        'response.user.expireAt',
        'response.user.expiresAt',
        'response.user.expiryAt',
        'response.user.expiryDate',
        'response.user.expire',
        'response.user.expiredAt',
        'response.user.expirationDate',
        'response.user.subscription.expireAt',
        'response.user.subscription.expiresAt',
        'response.user.subscription.expiryAt',
        'response.user.subscription.expiryDate',
        'response.user.subscription.expire',
        'response.user.subscription.expiredAt',
        'response.user.subscription.expirationDate',
        'expireAt',
        'expiresAt',
        'expiryAt',
        'expiryDate',
        'expiredAt',
        'expirationDate'
      ])),
      trafficUsedGb,
      trafficLimitGb,
      devices: usedDeviceCount
    }
  };
}

export class RemnawaveClient {
  private cachedServers: VpnServer[] = [];
  private cachedSession: RemnawaveSession | null = null;
  private cachedDevices: DeviceRecord[] = [buildLocalDeviceRecord()];
  private profileSyncInfo: ProfileSyncInfo = {
    status: 'idle',
    source: 'demo',
    sourceLabel: 'Ожидание live sync',
    configCount: 0,
    message: 'Серверы появятся после синхронизации вашего профиля Remnawave.'
  };
  private lastProbe: ConnectivityProbe | null = null;

  constructor(
    private readonly options: {
      panelUrl?: string;
      apiToken?: string;
    } = {}
  ) {}

  getConfig() {
    const meta = getIntegrationMeta();
    return {
      ...this.options,
      ...meta,
      panelUrl: this.options.panelUrl ?? meta.panelUrl,
      subscriptionUrl: meta.subscriptionUrl
    };
  }

  getProfileSyncInfo() {
    return this.profileSyncInfo;
  }

  getCachedSession() {
    return this.cachedSession;
  }

  async authorizeByAccessKey(accessKey: string, allowDemoFallback = allowDemoFallbackByEnv): Promise<RemnawaveSession> {
    const key = resolveAccessKey(accessKey);
    const provisionalSession = makeProvisionalSession(accessKey, key);
    const candidates = buildInfoCandidates(key);

    if (!candidates.length) {
      if (!allowDemoFallback) {
        throw new Error('Remnawave URL не настроен. Укажите VITE_REMNAWAVE_PANEL_URL или VITE_REMNAWAVE_SUBSCRIPTION_URL.');
      }

      const demoSession = makeDemoSession(accessKey);
      this.cachedSession = demoSession;
      this.cachedDevices = [buildLocalDeviceRecord()];
      return demoSession;
    }

    if (key.kind === 'url') {
      try {
        const rawProbe = await fetchTextCandidates(buildRawCandidates(key, provisionalSession));
        const importedServers = parseSubscriptionToServers(rawProbe.value);
        if (importedServers.length) {
          this.cachedServers = importedServers;
          this.cachedSession = provisionalSession;
          this.cachedDevices = [buildLocalDeviceRecord()];
          return provisionalSession;
        }
      } catch {
        // Fallback to JSON-based profile resolution below.
      }
    }

    try {
      const result = await fetchJsonCandidates(candidates.slice(0, 4));
      const source: RemnawaveSource = result.url.includes('/api/sub/') ? 'public-api' : 'panel-api';
      const session = mapSessionFromPayload(accessKey, key, result.value, source, result.url);
      this.cachedSession = session;
      this.cachedDevices = extractDevicesFromPayload(result.value);
      if (!this.cachedDevices.length) {
        this.cachedDevices = [buildLocalDeviceRecord()];
      }
      return session;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Не удалось получить профиль из Remnawave.';

      if (!allowDemoFallback) {
        throw new Error(message);
      }

      this.cachedSession = provisionalSession;
      this.cachedDevices = [buildLocalDeviceRecord()];
      return provisionalSession;
    }
  }

  async syncProfile(accessKey: string, allowDemoFallback = allowDemoFallbackByEnv) {
    const key = resolveAccessKey(accessKey);
    const candidates = buildRawCandidates(key, this.cachedSession);
    const previousServers = [...this.cachedServers];
    const previousProfile = this.profileSyncInfo;

    this.profileSyncInfo = {
      ...this.profileSyncInfo,
      status: 'syncing',
      accessKeyKind: key.kind,
      message: 'Получаем и парсим subscription-профиль…'
    };

    if (!candidates.length) {
      throw new Error('Для синхронизации профиля не хватает Remnawave URL.');
    }

    try {
      const rawResult = await fetchTextCandidates(candidates);
      const importedServers = parseSubscriptionToServers(rawResult.value);

      if (!importedServers.length) {
        throw new Error('Raw subscription получен, но распознать узлы пока не удалось.');
      }

      this.cachedServers = importedServers;
      const readyCount = importedServers.filter((item) => item.runtimeTemplate).length;
      this.profileSyncInfo = {
        status: 'ready',
        source: rawResult.url.includes('/api/sub/') || rawResult.url.endsWith('/raw') ? 'public-api' : 'panel-api',
        sourceLabel: rawResult.url.includes('/api/sub/') || rawResult.url.endsWith('/raw') ? 'Публичная подписка' : 'Panel API',
        configCount: importedServers.length,
        lastSyncAt: new Date().toLocaleString('ru-RU'),
        rawUrl: rawResult.url,
        message: `Импортировано ${importedServers.length} конфигов из Remnawave. Готово к подключению: ${readyCount}.`,
        accessKeyKind: key.kind
      };

      await cacheNativeProfileSync(importedServers.length, this.profileSyncInfo.sourceLabel);
      return {
        servers: this.cachedServers,
        profile: this.profileSyncInfo
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Не удалось синхронизировать профиль.';
      const restoredCount = previousServers.length;
      this.cachedServers = previousServers;
      this.profileSyncInfo = {
        status: 'error',
        source: restoredCount ? previousProfile.source : 'demo',
        sourceLabel: restoredCount ? previousProfile.sourceLabel : 'Live sync не выполнен',
        configCount: restoredCount,
        lastSyncAt: new Date().toLocaleString('ru-RU'),
        rawUrl: previousProfile.rawUrl,
        message: restoredCount
          ? `${message} Сохранён последний рабочий профиль (${restoredCount} конфигов).`
          : message,
        accessKeyKind: key.kind
      };

      if (!allowDemoFallback) {
        throw new Error(message);
      }

      return {
        servers: this.cachedServers,
        profile: this.profileSyncInfo
      };
    }
  }

  async loadServers(): Promise<VpnServer[]> {
    await delay(120);
    return this.cachedServers;
  }

  async loadProxyStatus(): Promise<ProxyStatus> {
    await delay(80);
    return getNativeProxyStatus();
  }

  async applySystemProxy(enabled: boolean): Promise<ProxyStatus> {
    await delay(80);
    return setNativeSystemProxy(enabled);
  }

  async runConnectivityProbe(): Promise<ConnectivityProbe> {
    const probe = await runNativeConnectivityProbe();
    this.lastProbe = probe;
    return probe;
  }

  async connect(
    server: VpnServer,
    options: {
      useSystemProxy?: boolean;
      probeAfterConnect?: boolean;
      tunnelMode?: TunnelMode;
      splitTunnelEntries?: SplitTunnelEntry[];
    } = {}
  ): Promise<ConnectResult> {
    await delay(250);
    const exists = this.cachedServers.find((item) => item.id === server.id)
      ?? this.cachedServers.find((item) => {
        const sameRuntime = JSON.stringify(item.runtimeTemplate ?? null) === JSON.stringify(server.runtimeTemplate ?? null);
        const sameEndpoint = item.host === server.host && (item.port ?? 443) === (server.port ?? 443);
        const sameLabel = item.country === server.country && item.city === server.city && item.protocol === server.protocol;
        return sameRuntime || sameEndpoint || sameLabel;
      })
      ?? this.cachedServers.find((item) => Boolean(item.runtimeTemplate))
      ?? (server.runtimeTemplate ? server : null);

    if (!exists) {
      throw new Error('Сервер не найден в активном профиле. Сначала обновите профиль или выберите другой узел.');
    }

    if (!this.cachedServers.some((item) => item.id === exists.id)) {
      this.cachedServers = [exists, ...this.cachedServers.filter((item) => item.id !== exists.id)];
    }

    if (isTauriRuntime) {
      const networkMode = options.tunnelMode ?? 'proxy';
      const activeSplitTunnelEntries = (options.splitTunnelEntries ?? []).filter((entry) => entry.enabled && entry.value.trim());
      let runtimeStarted = false;
      let systemProxyEnabled = false;

      try {
        await requestNativeConnect(exists, networkMode, activeSplitTunnelEntries);
        runtimeStarted = true;

        let proxy: ProxyStatus | null = null;
        if (networkMode !== 'tun' && options.useSystemProxy) {
          proxy = await setNativeSystemProxy(true);
          systemProxyEnabled = Boolean(proxy.enabled);
        }

        let probe: ConnectivityProbe | null = null;
        if (options.probeAfterConnect) {
          probe = await this.runConnectivityProbe();
        }

        return {
          externalIp: probe?.publicIp ?? this.lastProbe?.publicIp ?? 'Определяется после проверки маршрута',
          dnsMode: networkMode === 'tun'
            ? activeSplitTunnelEntries.length
              ? 'TUN режим → только выбранные программы и службы идут через VPN, остальное выходит напрямую'
              : 'TUN режим → список маршрутизации пуст, поэтому обычный трафик остаётся прямым'
            : options.useSystemProxy
              ? 'Windows system proxy → локальный Xray HTTP proxy 127.0.0.1:10809'
              : 'Локальный Xray sidecar на 127.0.0.1:10808/10809',
          transport: exists.protocol,
          probe,
          proxy
        };
      } catch (error) {
        if (systemProxyEnabled) {
          try {
            await setNativeSystemProxy(false);
          } catch {
            // ignore cleanup failure here
          }
        }

        if (runtimeStarted) {
          try {
            await requestNativeDisconnect();
          } catch {
            // ignore cleanup failure here
          }
        }

        throw error;
      }
    }

    return {
      externalIp: exists.ipPool?.replace('x', '41') ?? exists.host ?? '185.147.23.41',
      dnsMode: 'DoH поверх защищённого туннеля',
      transport: exists.protocol,
      probe: null,
      proxy: null
    };
  }

  async disconnect(options: { useSystemProxy?: boolean } = {}): Promise<void> {
    await delay(120);
    try {
      if (options.useSystemProxy) {
        await setNativeSystemProxy(false);
      }
      await requestNativeDisconnect();
    } catch {
      // ignore in preview
    }
  }

  async loadDevices(): Promise<DeviceRecord[]> {
    await delay(120);
    return this.cachedDevices.length ? this.cachedDevices : [buildLocalDeviceRecord()];
  }

  async revokeDevice(deviceId: string): Promise<DeviceRecord[]> {
    await delay(220);
    this.cachedDevices = this.cachedDevices.filter((device) => device.id !== deviceId || device.isCurrent);
    if (!this.cachedDevices.length) {
      this.cachedDevices = [buildLocalDeviceRecord()];
    }
    return this.cachedDevices;
  }

  async loadHistory(): Promise<SessionRecord[]> {
    await delay(140);
    return demoSessionHistory;
  }

  async loadRuntimeStatus(): Promise<RuntimeStatus> {
    return getNativeRuntimeStatus();
  }

  async loadDiagnostics(): Promise<DiagnosticsSnapshot> {
    await delay(140);
    const [runtime, proxyStatus, nativeLogLines] = await Promise.all([
      this.loadRuntimeStatus(),
      this.loadProxyStatus(),
      readNativeRuntimeLog(16)
    ]);

    const probeLine = this.lastProbe
      ? this.lastProbe.success
        ? `[probe] OK · IP ${this.lastProbe.publicIp ?? 'не определён'} · ${this.lastProbe.latencyMs ?? 0} мс`
        : `[probe] ${this.lastProbe.message}`
      : '[probe] Проверка соединения ещё не запускалась.';

    const mergedLogLines = [
      `[runtime] ${runtime.message}`,
      runtime.corePath ? `[runtime] core: ${runtime.corePath}` : '[runtime] xray.exe ещё не найден.',
      runtime.configPath ? `[runtime] config: ${runtime.configPath}` : '[runtime] config ещё не собран.',
      runtime.logPath ? `[runtime] log: ${runtime.logPath}` : '[runtime] лог-файл ещё не создан.',
      `[proxy] ${proxyStatus.enabled ? `включён → ${proxyStatus.server}` : 'выключен'}`,
      `[profile] ${this.profileSyncInfo.message ?? 'Синхронизация ещё не запускалась.'}`,
      probeLine,
      ...(nativeLogLines.length ? nativeLogLines : demoDiagnostics.logLines)
    ];

    return {
      ...demoDiagnostics,
      clientVersion: appVersion,
      tunnelStatus: runtime.tunnelActive ? 'ok' : demoDiagnostics.tunnelStatus,
      routeMode: runtime.networkMode === 'tun'
        ? `TUN mode${runtime.tunInterfaceName ? ` (${runtime.tunInterfaceName})` : ''}`
        : runtime.launchMode === 'xray-sidecar'
          ? `Xray sidecar ${runtime.socksPort ? `SOCKS:${runtime.socksPort}` : ''}${runtime.httpPort ? ` / HTTP:${runtime.httpPort}` : ''}`.trim()
          : runtime.bridge === 'tauri'
            ? 'Нативный bridge Tauri'
            : 'Web preview bridge',
      dnsMode: runtime.networkMode === 'tun'
        ? 'Маршруты Windows направляют системный трафик в TUN-интерфейс Xray; system proxy не требуется'
        : proxyStatus.enabled
          ? 'Windows system proxy направляет HTTP/HTTPS трафик в локальный Xray HTTP inbound'
          : runtime.launchMode === 'xray-sidecar'
            ? 'DNS трафик следует через локальный Xray proxy-profile'
            : demoDiagnostics.dnsMode,
      lastConfigSync: this.profileSyncInfo.lastSyncAt ?? demoDiagnostics.lastConfigSync,
      logLines: mergedLogLines
    };
  }
}

export const remnawaveClient = new RemnawaveClient();
