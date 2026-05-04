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
  RoutingExclusionSettings,
  TunnelMode,
  IpStack,
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
  revokeNativeHwidDevice,
  remnawavePanelUrl,
  remnawaveSubscriptionUrl,
  requestNativeConnect,
  requestNativeDisconnect,
  runNativeConnectivityProbe,
  setNativeSystemProxy
} from './runtime';
import { parseXrayJsonSubscriptionToServers } from './remnawave/subscriptionParser';
import { assertNativeRuntimeServerMatches } from './connectionGuards';
import { buildServerRuntimeFingerprint } from '../utils/serverIdentity';

const delay = (value: number) => new Promise<void>((resolve) => window.setTimeout(resolve, value));
const previewDelay = (value: number) => isTauriRuntime ? Promise.resolve() : delay(value);
const REQUEST_TIMEOUT_MS = 6500;
const VKARMANI_SUBSCRIPTION_PREFIX = 'https://sub.vkarmani.com/';

function withRequestTimeout<T>(operation: Promise<T>, url: string): Promise<T> {
  let timer: number | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = window.setTimeout(() => {
      reject(new Error(`Remnawave endpoint не ответил за ${Math.round(REQUEST_TIMEOUT_MS / 1000)} секунд: ${url}`));
    }, REQUEST_TIMEOUT_MS);
  });

  return Promise.race([operation, timeoutPromise]).finally(() => {
    if (timer !== undefined) {
      window.clearTimeout(timer);
    }
  }) as Promise<T>;
}

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

function maybeBoolean(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'number') {
    return value === 1 ? true : value === 0 ? false : undefined;
  }

  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['true', '1', 'yes', 'active', 'enabled'].includes(normalized)) return true;
    if (['false', '0', 'no', 'inactive', 'disabled', 'blocked', 'expired'].includes(normalized)) return false;
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

function parseExpiryTimestamp(value: unknown): number | null {
  if (!value) {
    return null;
  }

  if (typeof value === 'number' && Number.isFinite(value)) {
    const millis = value > 10_000_000_000 ? value : value * 1000;
    return Number.isFinite(millis) ? millis : null;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const numeric = Number(trimmed);
    if (Number.isFinite(numeric)) {
      return numeric > 10_000_000_000 ? numeric : numeric * 1000;
    }
    const date = new Date(trimmed);
    return Number.isNaN(date.getTime()) ? null : date.getTime();
  }

  return null;
}

function assertUsableSubscriptionPayload(payload: unknown) {
  const status = maybeString(pickValue(payload, [
    'response.status',
    'response.user.status',
    'response.subscription.status',
    'status',
    'user.status'
  ]))?.toLowerCase();

  if (status && ['disabled', 'blocked', 'expired', 'limited', 'inactive'].some((item) => status.includes(item))) {
    throw new Error('Ключ найден, но подписка не активна. Проверьте оплату/статус в личном кабинете.');
  }

  const disabled = maybeBoolean(pickValue(payload, [
    'response.disabled',
    'response.isDisabled',
    'response.user.disabled',
    'response.user.isDisabled',
    'response.subscription.disabled',
    'disabled',
    'isDisabled'
  ]));
  if (disabled === true) {
    throw new Error('Ключ найден, но подписка отключена в Remnawave.');
  }

  const active = maybeBoolean(pickValue(payload, [
    'response.active',
    'response.isActive',
    'response.user.active',
    'response.user.isActive',
    'response.subscription.active',
    'active',
    'isActive'
  ]));
  if (active === false) {
    throw new Error('Ключ найден, но профиль Remnawave не активен.');
  }

  const expiryMs = parseExpiryTimestamp(pickValue(payload, [
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
    'expireAt',
    'expiresAt',
    'expiryAt',
    'expiryDate',
    'expiredAt',
    'expirationDate'
  ]));

  if (expiryMs !== null && expiryMs <= Date.now()) {
    throw new Error('Срок действия ключа истёк. Обновите подписку и войдите снова.');
  }
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

function mapDeviceRecord(payload: unknown, index: number, fallbackUserUuid?: string): DeviceRecord | null {
  if (!payload || typeof payload !== 'object') {
    return null;
  }

  const remoteUuid = maybeString(pickValue(payload, ['uuid', 'id']));
  const hwid = maybeString(pickValue(payload, ['hwid', 'deviceHwid', 'deviceId']));
  const userUuid = maybeString(pickValue(payload, ['userUuid', 'user.uuid', 'userId', 'userUUID'])) ?? fallbackUserUuid;
  const id = remoteUuid ?? hwid ?? `panel-device-${index}`;
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
    reportedByPanel: true,
    remoteUuid,
    hwid,
    userUuid
  };
}

function extractDevicesFromPayload(payload: unknown, fallbackUserUuid?: string): DeviceRecord[] {
  const candidates = [
    pickValue(payload, ['response.devices', 'response.user.devices', 'response.hwidDevices', 'response.user.hwidDevices']),
    readPath(payload, 'devices'),
    readPath(payload, 'user.devices')
  ];

  for (const candidate of candidates) {
    if (Array.isArray(candidate)) {
      const mapped = candidate.map((item, index) => mapDeviceRecord(item, index, fallbackUserUuid)).filter((item): item is DeviceRecord => Boolean(item));
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

  if (!normalized.startsWith(VKARMANI_SUBSCRIPTION_PREFIX)) {
    throw new Error('Ключ доступа должен начинаться с https://sub.vkarmani.com/. Используйте только ключ VKarmani.');
  }

  let url: URL;
  try {
    url = new URL(normalized);
  } catch {
    throw new Error('Некорректная ссылка ключа доступа VKarmani.');
  }

  if (url.protocol !== 'https:' || url.hostname.toLowerCase() !== 'sub.vkarmani.com') {
    throw new Error('Ключ доступа должен быть ссылкой VKarmani: https://sub.vkarmani.com/...');
  }

  const pathname = url.pathname.replace(/\/+$/g, '');
  const parts = pathname.split('/').filter(Boolean);
  const identifier = parts[parts.length - 1] ?? '';
  if (!identifier || identifier.length < 5) {
    throw new Error('В ссылке VKarmani не найден идентификатор подписки.');
  }

  return {
    rawInput,
    normalized,
    identifier,
    shortUuid: looksLikeUuid(identifier) ? undefined : identifier,
    kind: 'url'
  };
}

function buildXrayJsonUrlCandidates(rawUrl: string, shortUuid?: string) {
  const candidates: string[] = [];

  try {
    const url = new URL(rawUrl);
    const base = `${url.origin}${url.pathname.replace(/\/+$/g, '')}`;
    const origin = url.origin;
    const encodedShortUuid = shortUuid ? encodeURIComponent(shortUuid) : '';

    if (!base.endsWith('/json')) {
      candidates.push(`${base}/json`);
    }

    if (encodedShortUuid) {
      candidates.push(`${origin}/api/sub/${encodedShortUuid}/json`);
      candidates.push(`${origin}/api/subscriptions/by-short-uuid/${encodedShortUuid}/json`);
    }

    if (base.endsWith('/json')) {
      candidates.push(base);
    }
  } catch {
    // ignore malformed URL here; resolver handles validation separately.
  }

  return candidates;
}

function buildUrlInfoCandidates(rawUrl: string, shortUuid?: string) {
  const candidates: string[] = [];

  try {
    const url = new URL(rawUrl);
    const base = `${url.origin}${url.pathname.replace(/\/+$/g, '')}`;
    const origin = url.origin;
    const encodedShortUuid = shortUuid ? encodeURIComponent(shortUuid) : '';

    // Для подтверждения ключа сначала проверяем именно info/profile endpoint.
    // Публичный info endpoint проверяет ключ отдельно от Xray JSON профиля.
    if (!base.endsWith('/info')) {
      candidates.push(`${base}/info`);
    }

    if (encodedShortUuid) {
      candidates.push(`${origin}/api/sub/${encodedShortUuid}/info`);
    }

    // Оставляем исходную ссылку последней: у некоторых установок VKarmani она может сразу отдавать JSON-профиль.
    candidates.push(base);
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
    candidates.push(...buildUrlInfoCandidates(key.normalized, shortUuid));
  }

  if (subscription && shortUuid) {
    candidates.push(`${subscription}/api/sub/${encodeURIComponent(shortUuid)}/info`);
  }

  if (panel && shortUuid) {
    candidates.push(`${panel}/api/sub/${encodeURIComponent(shortUuid)}/info`);
    candidates.push(`${panel}/api/subscriptions/by-short-uuid/${encodeURIComponent(shortUuid)}`);
  }

  if (panel && looksLikeUuid(key.identifier)) {
    candidates.push(`${panel}/api/subscriptions/by-uuid/${key.identifier}`);
  }

  return [...new Set(candidates)];
}

function buildXrayJsonProfileCandidates(key: ResolvedAccessKey, session?: RemnawaveSession | null) {
  const panel = normalizeBaseUrl(remnawavePanelUrl);
  const subscription = normalizeBaseUrl(remnawaveSubscriptionUrl);
  const candidates: string[] = [];
  const shortUuid = session?.shortUuid ?? key.shortUuid ?? key.identifier;

  if (key.kind === 'url') {
    candidates.push(...buildXrayJsonUrlCandidates(key.normalized, shortUuid));
  }

  if (session?.subscriptionUrl) {
    candidates.push(...buildXrayJsonUrlCandidates(session.subscriptionUrl, shortUuid));
  }

  if (subscription && shortUuid) {
    candidates.push(`${subscription}/api/sub/${encodeURIComponent(shortUuid)}/json`);
    candidates.push(`${subscription}/api/subscriptions/by-short-uuid/${encodeURIComponent(shortUuid)}/json`);
  }

  if (panel && shortUuid) {
    candidates.push(`${panel}/api/sub/${encodeURIComponent(shortUuid)}/json`);
    candidates.push(`${panel}/api/subscriptions/by-short-uuid/${encodeURIComponent(shortUuid)}/json`);
  }

  return [...new Set(candidates)];
}

async function fetchJsonCandidates(urls: string[]): Promise<CandidateResult<unknown>> {
  let lastError = 'Нет ответа от Remnawave.';

  for (const url of urls) {
    try {
      return {
        value: await withRequestTimeout(fetchRemoteJson(url), url),
        url
      };
    } catch (error) {
      lastError = error instanceof Error ? error.message : 'Ошибка сети.';
    }
  }

  throw new Error(lastError);
}


interface ParsedXrayJsonProfileResult {
  servers: VpnServer[];
  rawText: string;
  url: string;
}

const XRAY_JSON_SUBSCRIPTION_PROFILE = {
  name: 'Xray JSON',
  accept: 'application/json, text/json, application/x-json, */*;q=0.1',
  userAgent: `Xray/${appVersion} VKarmani-Desktop`
} as const;

function isGenericImportedServerLabel(label: string | undefined) {
  const normalized = (label ?? '').replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim().toLowerCase();
  return !normalized || ['proxy', 'direct', 'block', 'dns', 'outbound'].includes(normalized) || /^xray \d+$/.test(normalized) || /^remnawave \d+$/.test(normalized);
}

function xrayJsonProfileHasRemnawaveStructuredLabels(rawText: string) {
  const text = rawText.slice(0, 200_000);
  return /resolvedProxyConfigs|rawHosts|clientOverrides|serverDescription|server_description/i.test(text);
}

function parsedXrayJsonProfileQuality(result: ParsedXrayJsonProfileResult & { profileName?: string }) {
  const genericPenalty = result.servers.reduce((score, server) => score + (isGenericImportedServerLabel(server.rawLabel || server.country) ? 60 : 0), 0);
  const namedBonus = result.servers.reduce((score, server) => score + (isGenericImportedServerLabel(server.rawLabel || server.country) ? 0 : 12), 0);
  const rawUriBonus = result.servers.reduce((score, server) => score + (server.rawUri ? 10 : 0), 0);
  const structuredLabelBonus = xrayJsonProfileHasRemnawaveStructuredLabels(result.rawText) ? 180 : 0;
  const xrayJsonProfileBonus = /xray json/i.test(result.profileName ?? '') ? 80 : 0;
  return result.servers.length * 1000 + namedBonus + rawUriBonus + structuredLabelBonus + xrayJsonProfileBonus - genericPenalty;
}

async function fetchXrayJsonSubscriptionCandidate(
  url: string
): Promise<ParsedXrayJsonProfileResult & { score: number; profileName: string }> {
  const rawText = await withRequestTimeout(
    fetchRemoteText(url, XRAY_JSON_SUBSCRIPTION_PROFILE.accept, XRAY_JSON_SUBSCRIPTION_PROFILE.userAgent),
    url
  );
  const servers = parseXrayJsonSubscriptionToServers(rawText);

  if (!servers.length) {
    throw new Error(`Endpoint ответил, но Xray JSON серверы в ответе не распознаны: ${url}`);
  }

  const candidate = { servers, rawText, url, profileName: XRAY_JSON_SUBSCRIPTION_PROFILE.name };
  return { ...candidate, score: parsedXrayJsonProfileQuality(candidate) };
}

function isRealMultiNodeSubscription(servers: VpnServer[]) {
  return servers.length > 1 && !servers.every((server) => isGenericImportedServerLabel(server.rawLabel || server.country));
}

function isPreferredUserFacingSubscription(result: ParsedXrayJsonProfileResult & { profileName?: string }) {
  if (!isRealMultiNodeSubscription(result.servers)) {
    return false;
  }

  return xrayJsonProfileHasRemnawaveStructuredLabels(result.rawText) || /^\s*proxies\s*:/im.test(result.rawText);
}

async function fetchParsableXrayJsonProfileCandidates(urls: string[]): Promise<ParsedXrayJsonProfileResult> {
  let lastError = 'Не удалось получить Xray JSON subscription.';
  let sawUnrecognizedPayload = false;
  let best: (ParsedXrayJsonProfileResult & { score: number; profileName?: string }) | null = null;

  for (const url of urls) {
    try {
      const item = await fetchXrayJsonSubscriptionCandidate(url);
      if (!best || item.score > best.score) {
        best = item;
      }

      if (isPreferredUserFacingSubscription(item)) {
        return { servers: item.servers, rawText: item.rawText, url: item.url };
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Ошибка сети.';
      lastError = message;
      if (message.includes('Xray JSON серверы в ответе не распознаны')) {
        sawUnrecognizedPayload = true;
      }
    }
  }

  if (best) {
    return { servers: best.servers, rawText: best.rawText, url: best.url };
  }

  if (sawUnrecognizedPayload) {
    throw new Error('Xray JSON subscription получен, но распознать узлы не удалось. Проверьте, что в Remnawave для VKarmani Desktop включён именно профиль Xray JSON.');
  }

  throw new Error(lastError);
}

function mapSessionFromPayload(
  accessKey: string,
  key: ResolvedAccessKey,
  payload: unknown,
  source: RemnawaveSource,
  infoUrl: string
): RemnawaveSession {
  assertUsableSubscriptionPayload(payload);

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
    const devices = extractDevicesFromPayload(payload, key.identifier);
    return devices.length ? devices.length : 0;
  })();

  const subscriptionUrl = maybeString(pickValue(payload, [
    'response.subscriptionUrl',
    'response.user.subscriptionUrl',
    'subscriptionUrl'
  ]));


  return {
    accessKey,
    userId,
    displayName,
    deviceLimit,
    source,
    shortUuid,
    subscriptionUrl,
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

function proxyStatusFromRuntime(runtime: RuntimeStatus): ProxyStatus {
  return {
    enabled: Boolean(runtime.systemProxyEnabled),
    server: runtime.proxyServer,
    bypass: runtime.proxyBypass,
    method: runtime.bridge === 'tauri' ? 'wininet-registry' : 'mock',
    scope: 'current-user',
    checkedAt: new Date().toLocaleString('ru-RU')
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
  private runtimeSnapshotInFlight: Promise<{ runtime: RuntimeStatus; proxyStatus: ProxyStatus; diagnostics: DiagnosticsSnapshot }> | null = null;

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

    const xrayJsonCandidates = buildXrayJsonProfileCandidates(key, provisionalSession);
    let xrayJsonFirstError = '';

    // Для ключей VKarmani основной полезный результат — рабочий Xray JSON профиль со списком серверов.
    try {
      const xrayJsonResult = await fetchParsableXrayJsonProfileCandidates(xrayJsonCandidates);
      const importedServers = xrayJsonResult.servers;

      this.cachedSession = provisionalSession;
      this.cachedDevices = [buildLocalDeviceRecord()];
      this.cachedServers = importedServers;
      this.profileSyncInfo = {
        status: 'ready',
        source: xrayJsonResult.url.includes('/api/sub/') ? 'public-api' : 'panel-api',
        sourceLabel: xrayJsonResult.url.includes('/api/sub/') ? 'Публичная Xray JSON подписка' : 'Panel API',
        configCount: importedServers.length,
        readyCount: importedServers.filter((item) => item.runtimeTemplate).length,
        lastSyncAt: new Date().toLocaleString('ru-RU'),
        rawUrl: xrayJsonResult.url,
        updatedAt: new Date().toISOString(),
        accessKeyKind: key.kind,
        message: `Ключ принят. Импортировано ${importedServers.length} серверов из Xray JSON подписки Remnawave.`
      };
      return provisionalSession;
    } catch (error) {
      xrayJsonFirstError = error instanceof Error ? error.message : 'Не удалось получить Xray JSON profile.';
    }

    try {
      const result = await fetchJsonCandidates(candidates);
      const source: RemnawaveSource = result.url.includes('/api/sub/') ? 'public-api' : 'panel-api';
      const session = mapSessionFromPayload(accessKey, key, result.value, source, result.url);
      this.cachedSession = session;
      this.cachedDevices = extractDevicesFromPayload(result.value, session.userId);
      if (!this.cachedDevices.length) {
        this.cachedDevices = [buildLocalDeviceRecord()];
      }
      return session;
    } catch (error) {
      const infoError = error instanceof Error ? error.message : 'Не удалось получить профиль из Remnawave.';

      if (!allowDemoFallback) {
        throw new Error(`${xrayJsonFirstError} Info-проверка тоже не прошла: ${infoError}`);
      }

      this.cachedSession = provisionalSession;
      this.cachedDevices = [buildLocalDeviceRecord()];
      return provisionalSession;
    }
  }

  async syncProfile(accessKey: string, allowDemoFallback = allowDemoFallbackByEnv) {
    const key = resolveAccessKey(accessKey);
    const candidates = buildXrayJsonProfileCandidates(key, this.cachedSession);
    const previousServers = [...this.cachedServers];
    const previousProfile = this.profileSyncInfo;

    this.profileSyncInfo = {
      ...this.profileSyncInfo,
      status: 'syncing',
      accessKeyKind: key.kind,
      message: 'Получаем и парсим Xray JSON профиль…'
    };

    if (!candidates.length) {
      throw new Error('Для синхронизации профиля не хватает Remnawave URL.');
    }

    try {
      const xrayJsonResult = await fetchParsableXrayJsonProfileCandidates(candidates);
      const importedServers = xrayJsonResult.servers;

      this.cachedServers = importedServers;
      const readyCount = importedServers.filter((item) => item.runtimeTemplate).length;
      this.profileSyncInfo = {
        status: 'ready',
        source: xrayJsonResult.url.includes('/api/sub/') ? 'public-api' : 'panel-api',
        sourceLabel: xrayJsonResult.url.includes('/api/sub/') ? 'Публичная Xray JSON подписка' : 'Panel API',
        configCount: importedServers.length,
        lastSyncAt: new Date().toLocaleString('ru-RU'),
        rawUrl: xrayJsonResult.url,
        message: `Импортировано ${importedServers.length} Xray JSON конфигов из Remnawave. Готово к подключению: ${readyCount}.`,
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
    await previewDelay(120);
    return this.cachedServers;
  }

  async loadProxyStatus(): Promise<ProxyStatus> {
    await previewDelay(80);
    return getNativeProxyStatus();
  }

  async applySystemProxy(enabled: boolean): Promise<ProxyStatus> {
    await previewDelay(80);
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
      routingExclusions?: RoutingExclusionSettings;
      ipStack?: IpStack;
      reconnect?: boolean;
    } = {}
  ): Promise<ConnectResult> {
    await previewDelay(250);
    this.lastProbe = null;
    const cachedExactServer = this.cachedServers.find((item) => item.id === server.id) ?? null;

    // Ручной выбор пользователя должен запускать именно тот runtimeTemplate,
    // который пришёл из выбранной строки UI. Раньше cachedServers имел приоритет,
    // поэтому при устаревшем кэше или повторной синхронизации можно было стартовать
    // похожий/старый config с тем же id. Это выглядело как подключение к
    // "рандомному" серверу.
    const exists = server.runtimeTemplate ? server : cachedExactServer;

    if (!exists) {
      throw new Error('Сервер не найден в активном профиле. Сначала обновите профиль или выберите другой узел.');
    }

    this.cachedServers = [exists, ...this.cachedServers.filter((item) => item.id !== exists.id)];

    if (isTauriRuntime) {
      const networkMode = options.tunnelMode ?? 'proxy';
      const ipStack = options.ipStack ?? 'ipv4';
      const activeSplitTunnelEntries = (options.splitTunnelEntries ?? []).filter((entry) => entry.enabled && entry.value.trim());
      let runtimeStarted = false;
      let systemProxyEnabled = false;

      try {
        const runtime = await requestNativeConnect(exists, networkMode, activeSplitTunnelEntries, ipStack, Boolean(options.reconnect), options.routingExclusions);
        runtimeStarted = true;

        assertNativeRuntimeServerMatches(
          runtime.lastPreparedServerId,
          exists.id,
          runtime.lastPreparedServerFingerprint,
          buildServerRuntimeFingerprint(exists)
        );

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
          externalIp: probe?.publicIp ?? 'Определяется после проверки маршрута',
          dnsMode: networkMode === 'tun'
            ? activeSplitTunnelEntries.length
              ? `TUN режим → ${ipStack.toUpperCase()} → только выбранные программы и службы идут через VPN, остальное выходит напрямую`
              : `TUN режим → ${ipStack.toUpperCase()} → список маршрутизации пуст, поэтому обычный трафик остаётся прямым`
            : options.useSystemProxy
              ? `Windows system proxy → ${ipStack.toUpperCase()} → локальный Xray HTTP proxy 127.0.0.1:10809`
              : `Локальный Xray sidecar → ${ipStack.toUpperCase()} → 127.0.0.1:10808/10809`,
          transport: exists.protocol,
          probe,
          proxy,
          runtime
        };
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error ?? '');
        const nativeConnectStillRunning = errorMessage.includes('Подключение заняло больше')
          || errorMessage.includes('UI разблокирован');
        const runtimeTemporarilyBusy = errorMessage.includes('Runtime уже выполняет другое действие');

        // Если frontend timeout сработал раньше, чем Rust реально закончил request_connect,
        // нельзя тут же отправлять request_disconnect: он попадёт в тот же operation_lock
        // и может усилить зависание/гонку при переключении сервера. Короткая занятость
        // runtime-lock тоже не означает, что новый сервер окончательно не стартовал:
        // App.tsx повторит старт выбранного сервера без rollback на случайный/старый узел.
        if (nativeConnectStillRunning || runtimeTemporarilyBusy) {
          throw error;
        }

        // Даже если native connect упал до ответа, пробуем остановить Xray,
        // чтобы не оставить сиротский процесс и включённый proxy/TUN после ошибки.
        try {
          await requestNativeDisconnect();
        } catch {
          window.setTimeout(() => {
            void requestNativeDisconnect().catch(() => undefined);
          }, 1200);
        }

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
    await previewDelay(120);
    let firstError: unknown = null;

    if (options.useSystemProxy) {
      try {
        await setNativeSystemProxy(false);
      } catch (error) {
        firstError = firstError ?? error;
      }
    }

    try {
      await requestNativeDisconnect();
    } catch (error) {
      firstError = firstError ?? error;
    }

    if (firstError && isTauriRuntime) {
      throw firstError;
    }
  }

  async loadDevices(): Promise<DeviceRecord[]> {
    await previewDelay(120);
    return this.cachedDevices.length ? this.cachedDevices : [buildLocalDeviceRecord()];
  }

  async revokeDevice(deviceId: string): Promise<DeviceRecord[]> {
    await previewDelay(120);
    const current = this.cachedDevices.length ? this.cachedDevices : [buildLocalDeviceRecord()];
    const device = current.find((item) => item.id === deviceId);

    if (!device || device.isCurrent) {
      return current;
    }

    const panelUrl = normalizeBaseUrl(this.getConfig().panelUrl || remnawavePanelUrl);
    const remoteUuid = device.remoteUuid ?? (device.reportedByPanel ? device.id : undefined);
    const hwid = device.hwid?.trim();
    const userUuid = device.userUuid?.trim();

    if (!panelUrl) {
      throw new Error('Для удалённого отзыва устройства нужен VITE_REMNAWAVE_PANEL_URL.');
    }

    if (!remoteUuid && !(hwid && userUuid)) {
      throw new Error('Remnawave не вернул UUID или пару userUuid/HWID выбранного устройства, поэтому безопасно отозвать его нельзя. Обновите профиль и попробуйте снова.');
    }

    await revokeNativeHwidDevice(panelUrl, { uuid: remoteUuid, hwid, userUuid });

    this.cachedDevices = current.filter((item) => item.id !== deviceId);
    return this.cachedDevices.length ? this.cachedDevices : [buildLocalDeviceRecord()];
  }

  async loadHistory(): Promise<SessionRecord[]> {
    await previewDelay(80);
    return [];
  }

  async loadRuntimeStatus(): Promise<RuntimeStatus> {
    return getNativeRuntimeStatus();
  }
  private buildDiagnosticsSnapshot(
    runtime: RuntimeStatus,
    proxyStatus: ProxyStatus,
    nativeLogLines: string[]
  ): DiagnosticsSnapshot {
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
      ...(nativeLogLines.length ? nativeLogLines : ['[runtime] Нативный runtime-log пока пуст. Демо-строки больше не подмешиваются.'])
    ];

    const routeMode = runtime.networkMode === 'tun'
      ? `TUN selective${runtime.tunInterfaceName ? ` (${runtime.tunInterfaceName})` : ''}`
      : runtime.launchMode === 'xray-sidecar'
        ? `Xray sidecar ${runtime.socksPort ? `SOCKS:${runtime.socksPort}` : ''}${runtime.httpPort ? ` / HTTP:${runtime.httpPort}` : ''}`.trim()
        : runtime.bridge === 'tauri'
          ? 'Нативный bridge Tauri'
          : 'Web preview bridge';

    const dnsMode = runtime.networkMode === 'tun'
      ? 'Маршруты Windows направляют выбранный трафик в TUN-интерфейс Xray; system proxy не требуется'
      : proxyStatus.enabled
        ? 'Windows system proxy направляет HTTP/HTTPS трафик в локальный Xray HTTP inbound'
        : runtime.launchMode === 'xray-sidecar'
          ? 'Локальный Xray sidecar активен; системный proxy выключен'
          : 'Маршрут ещё не активен';

    return {
      serviceStatus: runtime.coreInstalled ? 'ok' : 'offline',
      tunnelStatus: runtime.tunnelActive ? 'ok' : 'offline',
      routeMode,
      dnsMode,
      clientVersion: appVersion,
      lastConfigSync: this.profileSyncInfo.lastSyncAt ?? 'Синхронизация ещё не запускалась',
      logLines: mergedLogLines
    };
  }

  async loadRuntimeSnapshot(): Promise<{ runtime: RuntimeStatus; proxyStatus: ProxyStatus; diagnostics: DiagnosticsSnapshot }> {
    if (this.runtimeSnapshotInFlight) {
      return this.runtimeSnapshotInFlight;
    }

    this.runtimeSnapshotInFlight = (async () => {
      await previewDelay(80);
      const [runtime, nativeLogLines] = await Promise.all([
        this.loadRuntimeStatus(),
        readNativeRuntimeLog(16)
      ]);
      const proxyStatus = proxyStatusFromRuntime(runtime);

      return {
        runtime,
        proxyStatus,
        diagnostics: this.buildDiagnosticsSnapshot(runtime, proxyStatus, nativeLogLines)
      };
    })();

    try {
      return await this.runtimeSnapshotInFlight;
    } finally {
      this.runtimeSnapshotInFlight = null;
    }
  }

  async loadDiagnostics(): Promise<DiagnosticsSnapshot> {
    return (await this.loadRuntimeSnapshot()).diagnostics;
  }
}

export function isVkarmaniAccessKey(value: string) {
  try {
    resolveAccessKey(value);
    return true;
  } catch {
    return false;
  }
}

export const __remnawaveTest = {
  buildXrayJsonUrlCandidates,
  buildXrayJsonProfileCandidates,
  parsedXrayJsonProfileQuality,
  parseXrayJsonSubscriptionToServers,
  XRAY_JSON_SUBSCRIPTION_PROFILE
};

export const remnawaveClient = new RemnawaveClient();
