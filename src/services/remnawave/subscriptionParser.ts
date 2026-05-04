import type { VpnServer, XrayRuntimeTemplate } from '../../types/vpn';
import { inferCountryCode, resolveServerFlag, looksLikeHost } from '../../utils/serverDisplay';

const MAX_SUBSCRIPTION_BYTES = 2 * 1024 * 1024;
const MAX_IMPORTED_SERVERS = 1000;
const MAX_JSON_WALK_DEPTH = 12;
const MAX_JSON_WALK_NODES = 5000;
const MAX_LABEL_LENGTH = 160;

type ServerCandidate = { path: string; servers: VpnServer[]; priority?: number };

function trimLabel(value: string) {
  const normalized = value.replace(/\s+/g, ' ').trim();
  return normalized.length > MAX_LABEL_LENGTH ? normalized.slice(0, MAX_LABEL_LENGTH).trimEnd() : normalized;
}

function stripUtfBom(value: string) {
  return value.replace(/^\uFEFF/, '').trim();
}

function fnv1aHex(value: string) {
  let hash = 0x811c9dc5;

  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }

  return (hash >>> 0).toString(16).padStart(8, '0');
}

function stableXrayJsonId(identity: string) {
  return `xray-json-${fnv1aHex(identity.trim())}`;
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
  return Boolean(value && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value));
}

function parseProtocol(protocol: string): VpnServer['protocol'] {
  switch (protocol.toLowerCase()) {
    case 'reality':
      return 'Reality';
    case 'vless':
      return 'VLESS';
    case 'hy2':
    case 'hysteria2':
    case 'hysteria':
      return 'Hysteria2';
    default:
      return 'Xray';
  }
}

function parseCountryLabel(label: string, host: string) {
  const withSpaces = label.replace(/[_-]+/g, ' ').trim();
  const cleaned = withSpaces.replace(/[\u{1F1E6}-\u{1F1FF}]{2}/gu, ' ').trim();
  if (!cleaned) {
    return {
      country: 'Xray JSON узел',
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function getPathValue(source: unknown, path: string): unknown {
  const parts = path.split('.');
  let current = source;

  for (const part of parts) {
    if (!isRecord(current) || !(part in current)) {
      return undefined;
    }
    current = current[part];
  }

  return current;
}

function pickStructuredValue(source: unknown, paths: string[]): unknown {
  for (const path of paths) {
    const value = getPathValue(source, path);
    if (value !== undefined && value !== null && value !== '') {
      return value;
    }
  }
  return undefined;
}

function pickRecord(source: unknown, paths: string[]): Record<string, unknown> {
  const value = pickStructuredValue(source, paths);
  return isRecord(value) ? value : {};
}

function pickString(source: unknown, paths: string[]): string | undefined {
  const value = pickStructuredValue(source, paths);
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed || undefined;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  return undefined;
}

function pickNumberValue(source: unknown, paths: string[]): number | undefined {
  const value = pickStructuredValue(source, paths);
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value.trim());
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function pickBooleanValue(source: unknown, paths: string[]): boolean | undefined {
  const value = pickStructuredValue(source, paths);
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value === 1 ? true : value === 0 ? false : undefined;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['true', '1', 'yes', 'on', 'enabled', 'tls', 'reality'].includes(normalized)) return true;
    if (['false', '0', 'no', 'off', 'disabled', 'none'].includes(normalized)) return false;
  }
  return undefined;
}

function firstDefinedString(...values: Array<string | undefined>) {
  return values.find((value) => typeof value === 'string' && value.trim());
}

function stringFromStructuredLabelValue(value: unknown, depth = 0): string | undefined {
  if (depth > 4 || value === undefined || value === null || value === '') {
    return undefined;
  }

  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed || undefined;
  }

  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const nested = stringFromStructuredLabelValue(item, depth + 1);
      if (nested) return nested;
    }
    return undefined;
  }

  if (isRecord(value)) {
    for (const key of [
      'serverDescription',
      'server_description',
      'displayName',
      'display_name',
      'title',
      'name',
      'description',
      'remark',
      'remarks',
      'label',
      'value',
      'text',
      'default'
    ]) {
      const nested = stringFromStructuredLabelValue(value[key], depth + 1);
      if (nested) return nested;
    }
  }

  return undefined;
}

function pickDisplayLabelString(source: unknown, paths: string[]): string | undefined {
  for (const path of paths) {
    const value = pickStructuredValue(source, [path]);
    const label = stringFromStructuredLabelValue(value);
    if (label) {
      return label;
    }
  }

  return undefined;
}

function collectArraysByKey(source: unknown, keys: string[], collected: unknown[][] = [], depth = 0, visited: { count: number } = { count: 0 }) {
  if (!source || depth > MAX_JSON_WALK_DEPTH || visited.count > MAX_JSON_WALK_NODES || collected.length > 64) {
    return collected;
  }

  visited.count += 1;

  if (Array.isArray(source)) {
    for (const item of source) {
      collectArraysByKey(item, keys, collected, depth + 1, visited);
    }
    return collected;
  }

  if (!isRecord(source)) {
    return collected;
  }

  for (const [key, value] of Object.entries(source)) {
    if (keys.includes(key) && Array.isArray(value)) {
      collected.push(value);
      if (collected.length > 64) break;
    }
    collectArraysByKey(value, keys, collected, depth + 1, visited);
    if (collected.length > 64) break;
  }

  return collected;
}

function collectArraysAtPaths(source: unknown, paths: string[]): Array<{ path: string; value: unknown[] }> {
  const collected: Array<{ path: string; value: unknown[] }> = [];
  const seen = new Set<unknown[]>();

  for (const path of paths) {
    const value = getPathValue(source, path);
    if (Array.isArray(value) && !seen.has(value)) {
      seen.add(value);
      collected.push({ path, value });
    }
  }

  return collected;
}

function isGenericServerLabel(label: string | undefined) {
  const normalized = (label ?? '').replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim().toLowerCase();
  return !normalized
    || ['proxy', 'direct', 'block', 'dns', 'outbound'].includes(normalized)
    || /^xray \d+$/.test(normalized)
    || /^remnawave \d+$/.test(normalized)
    || /^xray json \d+$/.test(normalized);
}

function isUsefulStructuredDisplayLabel(label: string | undefined, parsedFallback?: VpnServer | null) {
  const normalized = trimLabel(label ?? '');
  if (!normalized || isGenericServerLabel(normalized) || normalized.length < 3) {
    return false;
  }

  const lower = normalized.toLowerCase();
  const parsedLabel = (parsedFallback?.rawLabel || parsedFallback?.country || '').trim().toLowerCase();
  if (parsedLabel && lower === parsedLabel) {
    return false;
  }

  if (looksLikeHost(normalized)) {
    return false;
  }

  return true;
}

function pickStructuredDisplayLabel(source: unknown) {
  return trimLabel(firstDefinedString(
    pickDisplayLabelString(source, [
      'clientOverrides.serverDescription',
      'clientOverrides.server_description',
      'clientOverrides.serverName',
      'clientOverrides.server_name',
      'clientOverrides.displayName',
      'clientOverrides.display_name',
      'clientOverrides.profileName',
      'clientOverrides.profile_name',
      'clientOverrides.label',
      'clientOverrides.name',
      'clientOverrides.title',
      'clientOverrides.description',
      'clientOverrides.remark',
      'clientOverrides.remarks',
      'clientOverrides.tag',
      'client_overrides.serverDescription',
      'client_overrides.server_description',
      'client_overrides.serverName',
      'client_overrides.server_name',
      'client_overrides.displayName',
      'client_overrides.display_name',
      'client_overrides.profileName',
      'client_overrides.profile_name',
      'client_overrides.label',
      'client_overrides.name',
      'client_overrides.title',
      'client_overrides.description',
      'client_overrides.remark',
      'client_overrides.remarks',
      'client_overrides.tag'
    ]),
    pickDisplayLabelString(source, [
      'serverDescription',
      'server_description',
      'serverName',
      'server_name',
      'displayName',
      'display_name',
      'profileName',
      'profile_name',
      'proxyName',
      'proxy_name',
      'label',
      'title',
      'name',
      'description',
      'remark',
      'remarks',
      'tag',
      'ps'
    ]),
    pickDisplayLabelString(source, [
      'metadata.serverDescription',
      'metadata.server_description',
      'metadata.serverName',
      'metadata.server_name',
      'metadata.displayName',
      'metadata.display_name',
      'metadata.profileName',
      'metadata.profile_name',
      'metadata.proxyName',
      'metadata.proxy_name',
      'metadata.label',
      'metadata.name',
      'metadata.title',
      'metadata.description',
      'metadata.remark',
      'metadata.remarks',
      'metadata.tag',
      'rawInbound.serverDescription',
      'rawInbound.server_description',
      'rawInbound.serverName',
      'rawInbound.server_name',
      'rawInbound.displayName',
      'rawInbound.display_name',
      'rawInbound.label',
      'rawInbound.remark',
      'rawInbound.tag'
    ])
  ) || '');
}

function pickStructuredTechnicalLabel(source: unknown) {
  return trimLabel(firstDefinedString(
    pickDisplayLabelString(source, [
      'rawInbound.remark',
      'rawInbound.tag',
      'rawInbound.name',
      'rawInbound.label',
      'metadata.rawInbound.remark',
      'metadata.rawInbound.tag',
      'metadata.rawInbound.name',
      'metadata.rawInbound.label',
      'metadata.remark',
      'metadata.remarks',
      'metadata.tag',
      'metadata.name',
      'metadata.label',
      'remark',
      'remarks',
      'tag'
    ])
  ) || '');
}

function preserveServerLocationFromTechnicalLabel(server: VpnServer, technicalLabel: string | undefined) {
  const cleanTechnicalLabel = trimLabel(technicalLabel ?? '');
  const cleanDisplayLabel = trimLabel(server.rawLabel || server.country);
  if (!cleanTechnicalLabel || !cleanDisplayLabel || cleanTechnicalLabel === cleanDisplayLabel) {
    return server;
  }

  const technicalLocation = parseCountryLabel(cleanTechnicalLabel, server.host ?? '');
  if (!technicalLocation.countryCode || !/^[A-Z]{2}$/.test(technicalLocation.countryCode)) {
    return server;
  }

  return {
    ...server,
    countryCode: technicalLocation.countryCode,
    flag: resolveServerFlag({
      country: technicalLocation.country,
      countryCode: technicalLocation.countryCode,
      rawLabel: cleanTechnicalLabel,
      host: server.host,
      explicitCode: technicalLocation.countryCode
    })
  };
}

function relabelServer(server: VpnServer, label: string): VpnServer {
  const cleanLabel = trimLabel(label);
  const location = parseCountryLabel(cleanLabel, server.host ?? '');
  const preservedCountryCode = server.countryCode && /^[A-Z]{2}$/.test(server.countryCode)
    ? server.countryCode
    : undefined;
  const nextCountryCode = preservedCountryCode || location.countryCode;
  const flag = resolveServerFlag({
    flag: preservedCountryCode ? server.flag : undefined,
    country: location.country,
    countryCode: nextCountryCode,
    rawLabel: cleanLabel,
    host: server.host,
    explicitCode: nextCountryCode
  });

  return {
    ...server,
    country: location.country,
    city: location.city,
    countryCode: nextCountryCode,
    flag,
    rawLabel: cleanLabel,
    description: cleanLabel || server.description,
    runtimeTemplate: server.runtimeTemplate
      ? {
          ...server.runtimeTemplate,
          remarks: cleanLabel || server.runtimeTemplate.remarks
        }
      : server.runtimeTemplate
  };
}

function normalizeCascadeLabel(value: string | undefined) {
  return (value ?? '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[\u{1F1E6}-\u{1F1FF}]{2}/gu, ' ')
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

function splitCascadeLabel(label: string | undefined) {
  const normalized = normalizeCascadeLabel(label);
  const [headRaw, ...tailParts] = normalized.split('|').map((part) => part.trim()).filter(Boolean);
  return {
    head: headRaw ?? '',
    tail: tailParts.join(' | ')
  };
}

function stripCascadeSlotMarker(value: string) {
  return value
    .replace(/\b(?:s|srv|server|node|n)\s*\d+\b/gi, ' ')
    .replace(/\b\d+\s*(?:s|srv|server|node|n)\b/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function cascadeFamilyKey(server: VpnServer) {
  const label = server.rawLabel || server.country;
  const { head } = splitCascadeLabel(label);
  const familyFromLabel = stripCascadeSlotMarker(head);
  const code = server.countryCode?.trim().toUpperCase();

  if (code && /^[A-Z]{2}$/.test(code)) {
    return `code:${code}`;
  }

  if (familyFromLabel) {
    return `label:${familyFromLabel}`;
  }

  return `host:${server.host ?? ''}`;
}

function isLikelyCascadeBackendMember(server: VpnServer) {
  const label = server.rawLabel || server.country;
  const { head, tail } = splitCascadeLabel(label);
  if (!head || !tail) {
    return false;
  }

  const hasSlotMarker = /\b(?:s|srv|server|node|n)\s*\d+\b/i.test(head)
    || /\b\d+\s*(?:s|srv|server|node|n)\b/i.test(head);
  if (!hasSlotMarker) {
    return false;
  }

  const publicTail = /^(?:all|no ads?|adguard|без рекламы|premium|standard|basic|streaming|gaming|4g|5g)$/i.test(tail);
  return !publicTail;
}

function hasPublicCascadeAggregateSibling(server: VpnServer, servers: VpnServer[]) {
  const familyKey = cascadeFamilyKey(server);
  if (!familyKey) {
    return false;
  }

  return servers.some((candidate) => {
    if (candidate === server || cascadeFamilyKey(candidate) !== familyKey || isLikelyCascadeBackendMember(candidate)) {
      return false;
    }

    const label = normalizeCascadeLabel(candidate.rawLabel || candidate.country);
    return Boolean(label && label.includes('|')) || /vkarmani|smart|premium|standard|gaming|streaming/i.test(label);
  });
}

function filterRemnawaveCascadeBackendMembers(servers: VpnServer[]) {
  return servers.filter((server) => !isLikelyCascadeBackendMember(server) || !hasPublicCascadeAggregateSibling(server, servers));
}

function serverEndpointKey(server: VpnServer) {
  const host = (server.host ?? '').trim().toLowerCase();
  const port = server.port ?? 443;
  if (!host) return '';
  return `${host}:${port}`;
}

function isLikelyUserFacingCandidate(path: string, priority = 0) {
  const normalizedPath = path.toLowerCase();
  return priority >= 1000
    || /(?:serverdescription|server_description|clientoverrides|client_overrides|displayname|display_name|profiletitle|profile_title|remarks)/i.test(normalizedPath);
}

function remnawaveLabelOverlayScore(label: string | undefined) {
  const normalized = trimLabel(label ?? '');
  if (!normalized || isGenericServerLabel(normalized) || looksLikeHost(normalized)) {
    return -1000;
  }

  const cascade = splitCascadeLabel(normalized);
  const technicalCascadePenalty = cascade.head && cascade.tail ? -35 : 0;
  const brandBonus = /vkarmani/i.test(normalized) ? 70 : 0;
  const clientNameBonus = /\s\/\s|smart|premium|standard|gaming|streaming|no\s*ads?/i.test(normalized) ? 22 : 0;
  const readableBonus = /[a-zа-яё]{3,}/iu.test(normalized) ? 12 : 0;
  return normalized.length + brandBonus + clientNameBonus + readableBonus + technicalCascadePenalty;
}

function collectDisplayLabelOverlays(candidates: ServerCandidate[]) {
  const overlays = new Map<string, { label: string; score: number }>();

  for (const candidate of candidates) {
    if (!isLikelyUserFacingCandidate(candidate.path, candidate.priority ?? 0)) {
      continue;
    }

    const priorityBonus = candidate.priority ?? 0;
    for (const server of candidate.servers) {
      const key = serverEndpointKey(server);
      const label = trimLabel(server.rawLabel || server.country);
      if (!key || !isUsefulStructuredDisplayLabel(label)) {
        continue;
      }

      const score = priorityBonus + remnawaveLabelOverlayScore(label);
      const existing = overlays.get(key);
      if (!existing || score > existing.score) {
        overlays.set(key, { label, score });
      }
    }
  }

  return overlays;
}

function endpointLocationOverlayScore(candidatePath: string, server: VpnServer, priority = 0) {
  const label = trimLabel(server.rawLabel || server.country);
  const normalizedPath = candidatePath.toLowerCase();
  const technicalRouteBonus = splitCascadeLabel(label).tail ? 180 : 0;
  const structuredSourceBonus = /(?:remnawave-structured|rawhosts|raw_hosts|hosts)/i.test(normalizedPath) ? 65 : 0;
  const userFacingPenalty = isLikelyUserFacingCandidate(candidatePath, priority) ? -35 : 0;
  const genericPenalty = isGenericServerLabel(label) ? -90 : 0;
  return structuredSourceBonus + technicalRouteBonus + userFacingPenalty + genericPenalty + remnawaveLabelOverlayScore(label);
}

function collectEndpointLocationOverlays(candidates: ServerCandidate[]) {
  const overlays = new Map<string, { countryCode: string; flag: string; rawLabel: string; score: number }>();

  for (const candidate of candidates) {
    for (const server of candidate.servers) {
      const key = serverEndpointKey(server);
      const countryCode = server.countryCode?.trim().toUpperCase();
      if (!key || !countryCode || !/^[A-Z]{2}$/.test(countryCode)) {
        continue;
      }

      const rawLabel = trimLabel(server.rawLabel || server.country);
      const score = endpointLocationOverlayScore(candidate.path, server, candidate.priority ?? 0);
      const existing = overlays.get(key);
      if (!existing || score > existing.score) {
        overlays.set(key, {
          countryCode,
          flag: resolveServerFlag({ flag: server.flag, country: server.country, countryCode, rawLabel, host: server.host, explicitCode: countryCode }),
          rawLabel,
          score
        });
      }
    }
  }

  return overlays;
}

function applyEndpointLocationOverlay(server: VpnServer, overlay: { countryCode: string; flag: string; rawLabel: string } | undefined) {
  if (!overlay || server.countryCode === overlay.countryCode) {
    return server;
  }

  return {
    ...server,
    countryCode: overlay.countryCode,
    flag: resolveServerFlag({
      flag: overlay.flag,
      country: server.country,
      countryCode: overlay.countryCode,
      rawLabel: overlay.rawLabel || server.rawLabel,
      host: server.host,
      explicitCode: overlay.countryCode
    })
  };
}

function applyDisplayLabelOverlays(candidates: ServerCandidate[]): ServerCandidate[] {
  const labelOverlays = collectDisplayLabelOverlays(candidates);
  const locationOverlays = collectEndpointLocationOverlays(candidates);
  if (!labelOverlays.size && !locationOverlays.size) {
    return candidates;
  }

  return candidates.map((candidate) => ({
    ...candidate,
    servers: candidate.servers.map((server) => {
      const key = serverEndpointKey(server);
      const labelOverlay = labelOverlays.get(key);
      const locationOverlay = locationOverlays.get(key);
      const labeledServer = labelOverlay && isUsefulStructuredDisplayLabel(labelOverlay.label, server)
        ? relabelServer(server, labelOverlay.label)
        : server;
      return applyEndpointLocationOverlay(labeledServer, locationOverlay);
    })
  }));
}

function structuredServerQuality(servers: VpnServer[], path: string, priority = 0) {
  const normalizedPath = path.toLowerCase();
  const visibleServers = filterRemnawaveCascadeBackendMembers(servers);
  const sourceBonus = normalizedPath.includes('rawhosts') || normalizedPath.includes('hosts') || normalizedPath.includes('remnawave-structured')
    ? 75
    : 0;
  const userFacingBonus = isLikelyUserFacingCandidate(path, priority) ? 220 : 0;
  const labelBonus = visibleServers.reduce((score, server) => score + (isGenericServerLabel(server.rawLabel || server.country) ? -42 : 8), 0);
  const runtimeReadyBonus = visibleServers.reduce((score, server) => score + (server.runtimeTemplate ? 10 : -30), 0);
  const genericOnlyPenalty = visibleServers.length > 0 && visibleServers.every((server) => isGenericServerLabel(server.rawLabel || server.country)) ? -90 : 0;
  const hiddenCascadePenalty = Math.max(0, servers.length - visibleServers.length) * 12;
  return priority + visibleServers.length * 100 + sourceBonus + userFacingBonus + labelBonus + runtimeReadyBonus + genericOnlyPenalty - hiddenCascadePenalty;
}

function chooseBestStructuredServerSet(candidates: ServerCandidate[]) {
  let best: { path: string; servers: VpnServer[]; score: number } | null = null;
  const normalizedCandidates = applyDisplayLabelOverlays(candidates);

  for (const candidate of normalizedCandidates) {
    if (!candidate.servers.length) {
      continue;
    }

    const score = structuredServerQuality(candidate.servers, candidate.path, candidate.priority ?? 0);
    if (!best || score > best.score) {
      best = { ...candidate, score };
    }
  }

  return best?.servers ?? [];
}

function normalizeStructuredProtocol(value: string | undefined) {
  const normalized = (value ?? '').trim().toLowerCase();
  if (normalized === 'ss') return 'shadowsocks';
  if (normalized === 'hy2' || normalized === 'hysteria2' || normalized === 'hysteria') return 'hysteria2';
  return normalized;
}

function normalizeSecurityName(value: string | undefined, source?: unknown) {
  const normalized = (value ?? '').trim().toLowerCase();
  if (normalized && normalized !== 'false' && normalized !== '0') {
    if (normalized === 'xtls') return 'tls';
    return normalized;
  }

  if (pickBooleanValue(source, ['tls', 'securityOptions.tls', 'tlsSettings.enabled']) === true) {
    return 'tls';
  }

  if (pickStructuredValue(source, ['reality-opts', 'realityOpts', 'realitySettings', 'securityOptions.publicKey', 'securityOptions.shortId'])) {
    return 'reality';
  }

  return 'none';
}

function parseMaybeJsonObject(value: unknown): unknown {
  if (isRecord(value) || Array.isArray(value)) {
    return value;
  }

  if (typeof value !== 'string') {
    return undefined;
  }

  const candidates = [value];
  try {
    candidates.push(decodeURIComponent(value));
  } catch {
    // Keep the original candidate only.
  }

  for (const candidate of candidates) {
    const trimmed = candidate.trim();
    if (!trimmed || (!trimmed.startsWith('{') && !trimmed.startsWith('['))) {
      continue;
    }
    try {
      return JSON.parse(trimmed);
    } catch {
      // Try the next JSON representation.
    }
  }

  return undefined;
}

function parseListValue(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean);
  }
  if (typeof value === 'string') {
    return value.split(',').map((item) => item.trim()).filter(Boolean);
  }
  return [];
}

function structuredPort(value: unknown, fallback = 443) {
  if (typeof value === 'number' || typeof value === 'string') {
    return parseStrictPort(value, fallback);
  }
  return fallback;
}

function buildServerFromRuntimeTemplate(
  runtimeTemplate: XrayRuntimeTemplate,
  label: string,
  rawIdentity: string,
  index: number
): VpnServer | null {
  const runtimeEndpoint = extractRuntimeEndpoint(runtimeTemplate);
  const host = runtimeEndpoint.host;
  const port = runtimeEndpoint.port || 443;

  if (!host) {
    return null;
  }

  const cleanLabel = trimLabel(label || runtimeTemplate.remarks || '');
  const location = parseCountryLabel(cleanLabel, host);
  const flag = resolveServerFlag({ country: location.country, rawLabel: cleanLabel, host, explicitCode: location.countryCode });
  const protocol = parseProtocol(runtimeTemplate.protocol);
  const transportLabel = runtimeTemplate.transport ? runtimeTemplate.transport.toUpperCase() : undefined;

  return {
    id: stableXrayJsonId(rawIdentity || `${runtimeTemplate.protocol}:${host}:${port}:${index}`),
    country: location.country,
    city: location.city,
    countryCode: location.countryCode,
    flag,
    latency: null,
    latencyStatus: 'unchecked',
    load: 0,
    protocol,
    isRecommended: index === 0,
    tags: ['Live', 'Xray JSON', protocol, ...(transportLabel ? [transportLabel] : []), 'Готов к подключению'],
    ipPool: `${host}:${port}`,
    description: cleanLabel || `Узел из Xray JSON профиля Remnawave: ${host}`,
    source: 'subscription',
    host,
    port,
    rawLabel: cleanLabel || undefined,
    rawUri: rawIdentity || undefined,
    transportLabel,
    runtimeTemplate
  };
}

function xrayOutboundToRuntime(outboundValue: unknown, label: string): XrayRuntimeTemplate | null {
  if (!isRecord(outboundValue)) {
    return null;
  }

  const protocol = normalizeStructuredProtocol(pickString(outboundValue, ['protocol']));
  if (!['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2'].includes(protocol)) {
    return null;
  }

  const streamSettings = pickRecord(outboundValue, ['streamSettings']);
  const security = normalizeSecurityName(pickString(streamSettings, ['security']), streamSettings);
  const transport = protocol === 'hysteria2'
    ? 'udp'
    : normalizeTransportName(pickString(streamSettings, ['network']) || 'raw');

  return {
    family: 'xray',
    protocol: protocol as XrayRuntimeTemplate['protocol'],
    remarks: label || pickString(outboundValue, ['tag']) || undefined,
    transport: transport as XrayRuntimeTemplate['transport'],
    outbound: compactObject({
      ...outboundValue,
      tag: pickString(outboundValue, ['tag']) || 'proxy'
    })
  };
}

function parseXrayOutboundArray(outbounds: unknown[], seed: string): VpnServer[] {
  const servers: VpnServer[] = [];

  for (const outbound of outbounds) {
    if (servers.length >= MAX_IMPORTED_SERVERS) break;
    const label = pickString(outbound, ['remarks', 'tag', 'metadata.remark', 'metadata.tag']) || `Xray JSON ${servers.length + 1}`;
    const runtime = xrayOutboundToRuntime(outbound, label);
    if (!runtime) continue;
    const server = buildServerFromRuntimeTemplate(runtime, label, `${seed}:outbound:${JSON.stringify(outbound)}`, servers.length);
    if (server) {
      servers.push(server);
    }
  }

  return servers;
}

function pickXrayConnectionLabel(payload: unknown, fallback: string) {
  return pickString(payload, [
    'remarks',
    'remark',
    'name',
    'displayName',
    'display_name',
    'serverDescription',
    'server_description',
    'profileTitle',
    'profile_title',
    'title'
  ]) || fallback;
}

function parseXrayConfigObject(payload: unknown, seed: string, index: number): VpnServer | null {
  if (!isRecord(payload)) {
    return null;
  }

  const outbounds = getPathValue(payload, 'outbounds');
  if (!Array.isArray(outbounds)) {
    return null;
  }

  const label = pickXrayConnectionLabel(payload, `Xray JSON ${index + 1}`);
  for (const outbound of outbounds) {
    const runtime = xrayOutboundToRuntime(outbound, label);
    if (!runtime) {
      continue;
    }

    const identity = `${seed}:config:${JSON.stringify(outbound)}`;
    return buildServerFromRuntimeTemplate(runtime, label, identity, index);
  }

  return null;
}

function parseXrayConfigArray(payload: unknown, seed: string): VpnServer[] {
  const arrays: Array<{ path: string; value: unknown[] }> = [];
  const objects: Array<{ path: string; value: unknown }> = [];

  if (Array.isArray(payload)) {
    arrays.push({ path: 'root', value: payload });
  } else if (isRecord(payload)) {
    objects.push({ path: 'root', value: payload });
  }

  for (const path of ['response', 'data', 'response.configs', 'response.xrayJson', 'configs', 'xrayJson', 'xray_json']) {
    const value = getPathValue(payload, path);
    if (Array.isArray(value)) {
      arrays.push({ path, value });
    }
  }

  for (const path of ['response', 'data', 'response.config', 'response.xrayJson', 'config', 'xrayConfig', 'xrayJson', 'xray_json']) {
    const value = getPathValue(payload, path);
    if (isRecord(value)) {
      objects.push({ path, value });
    }
  }

  const servers: VpnServer[] = [];
  const seenIds = new Set<string>();
  const pushServer = (server: VpnServer | null) => {
    if (!server || seenIds.has(server.id) || servers.length >= MAX_IMPORTED_SERVERS) {
      return;
    }
    seenIds.add(server.id);
    servers.push(server);
  };

  for (const { path, value } of arrays) {
    for (const item of value) {
      if (servers.length >= MAX_IMPORTED_SERVERS) break;
      pushServer(parseXrayConfigObject(item, `${seed}:${path}`, servers.length));
    }
    if (servers.length >= MAX_IMPORTED_SERVERS) break;
  }

  for (const { path, value } of objects) {
    if (servers.length >= MAX_IMPORTED_SERVERS) break;
    pushServer(parseXrayConfigObject(value, `${seed}:${path}`, servers.length));
  }

  return servers;
}

function normalizeTransportName(value: string | null | undefined) {
  const normalized = (value || 'raw').trim().toLowerCase();
  if (normalized === 'tcp') return 'raw';
  if (normalized === 'splithttp') return 'xhttp';
  return normalized;
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

  for (const candidate of candidates) {
    const trimmed = candidate.trim();
    if (!trimmed || (!trimmed.startsWith('{') && !trimmed.startsWith('['))) {
      continue;
    }

    try {
      return JSON.parse(trimmed);
    } catch {
      // Try the next JSON representation.
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

function buildStreamFromStructuredOptions(base: {
  network?: string;
  security?: string;
  host?: string;
  path?: string;
  serviceName?: string;
  source?: unknown;
}) {
  const params = new URLSearchParams();
  const source = base.source;

  const sni = firstDefinedString(
    pickString(source, ['sni', 'servername', 'serverName', 'peer', 'securityOptions.sni', 'securityOptions.servername', 'securityOptions.serverName', 'tlsSettings.serverName', 'realitySettings.serverName']),
    base.host
  );
  const fingerprint = pickString(source, ['fp', 'fingerprint', 'client-fingerprint', 'clientFingerprint', 'securityOptions.fingerprint', 'tlsSettings.fingerprint', 'realitySettings.fingerprint']);
  const publicKey = pickString(source, ['publicKey', 'public-key', 'pbk', 'securityOptions.publicKey', 'securityOptions.public-key', 'reality-opts.public-key', 'realityOpts.publicKey', 'realitySettings.publicKey']);
  const shortId = pickString(source, ['shortId', 'short-id', 'sid', 'securityOptions.shortId', 'securityOptions.short-id', 'reality-opts.short-id', 'realityOpts.shortId', 'realitySettings.shortId']);
  const spiderX = pickString(source, ['spiderX', 'spider-x', 'spx', 'securityOptions.spiderX', 'securityOptions.spider-x', 'realitySettings.spiderX']);
  const alpn = parseListValue(pickStructuredValue(source, ['alpn', 'securityOptions.alpn', 'tlsSettings.alpn']));

  if (base.network) params.set('type', base.network);
  if (base.security) params.set('security', base.security);
  if (sni) params.set('sni', sni);
  if (fingerprint) params.set('fp', fingerprint);
  if (publicKey) params.set('pbk', publicKey);
  if (shortId) params.set('sid', shortId);
  if (spiderX) params.set('spx', spiderX);
  if (alpn.length) params.set('alpn', alpn.join(','));

  const transportHost = firstDefinedString(
    pickString(source, ['host', 'authority', 'headers.Host', 'ws-opts.headers.Host', 'wsOpts.headers.Host', 'transportOptions.host', 'transportOptions.authority', 'transportOptions.headers.Host']),
    base.host
  );
  const path = firstDefinedString(
    base.path,
    pickString(source, ['path', 'pathPrefix', 'ws-opts.path', 'wsOpts.path', 'httpupgrade-opts.path', 'httpUpgradeOpts.path', 'xhttp-opts.path', 'xhttpOpts.path', 'transportOptions.path', 'transportOptions.pathPrefix'])
  );
  const serviceName = firstDefinedString(
    base.serviceName,
    pickString(source, ['serviceName', 'service-name', 'grpc-opts.grpc-service-name', 'grpcOpts.grpcServiceName', 'transportOptions.serviceName', 'transportOptions.service-name'])
  );
  const mode = pickString(source, ['mode', 'transportOptions.mode', 'xhttp-opts.mode', 'xhttpOpts.mode']);

  if (transportHost) params.set('host', transportHost);
  if (path) params.set('path', path);
  if (serviceName) params.set('serviceName', serviceName);
  if (mode) params.set('mode', mode);

  return buildStreamSettings({
    searchParams: params,
    network: base.network,
    security: base.security,
    host: transportHost,
    path,
    serviceName
  });
}

function buildRuntimeFromStructuredProxy(proxyValue: unknown, label: string): XrayRuntimeTemplate | null {
  if (!isRecord(proxyValue)) {
    return null;
  }

  const directOutbound = pickStructuredValue(proxyValue, ['outbound', 'xrayOutbound']);
  const directRuntime = xrayOutboundToRuntime(directOutbound, label);
  if (directRuntime) {
    return directRuntime;
  }

  const templatePayload = parseMaybeJsonObject(pickStructuredValue(proxyValue, [
    'clientOverrides.xrayJsonTemplate',
    'xrayJsonTemplate',
    'xray_json_template'
  ]));
  const templateOutbounds = parseXrayJsonServersFromPayload(templatePayload, `${label}:template`);
  if (templateOutbounds[0]?.runtimeTemplate) {
    return templateOutbounds[0].runtimeTemplate;
  }

  const protocolOptions = pickRecord(proxyValue, ['protocolOptions', 'protocolSettings', 'protocol_options', 'settings']);
  const transportOptions = pickRecord(proxyValue, ['transportOptions', 'transportSettings', 'transport_options']);
  const securityOptions = pickRecord(proxyValue, ['securityOptions', 'securitySettings', 'security_options']);
  const mergedSource = compactObject({
    ...proxyValue,
    protocolOptions,
    transportOptions,
    securityOptions,
    metadata: pickRecord(proxyValue, ['metadata']),
    clientOverrides: pickRecord(proxyValue, ['clientOverrides'])
  });

  const protocol = normalizeStructuredProtocol(firstDefinedString(
    pickString(proxyValue, ['protocol', 'type']),
    pickString(protocolOptions, ['protocol', 'type'])
  ));
  if (!['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2'].includes(protocol)) {
    return null;
  }

  const host = firstDefinedString(
    pickString(proxyValue, ['address', 'server', 'hostname', 'hostAddress', 'host', 'endpoint.address', 'node.address', 'node.host', 'resolvedAddress', 'resolvedHost']),
    pickString(protocolOptions, ['address', 'server', 'hostname', 'host', 'serverAddress']),
    pickString(transportOptions, ['address', 'server', 'hostname', 'serverAddress'])
  );
  const port = structuredPort(
    pickStructuredValue(proxyValue, ['port', 'serverPort', 'endpoint.port', 'node.port'])
      ?? pickStructuredValue(protocolOptions, ['port', 'serverPort'])
      ?? pickStructuredValue(transportOptions, ['port', 'serverPort']),
    443
  );

  if (!host || port === null) {
    return null;
  }

  const network = protocol === 'hysteria2'
    ? 'udp'
    : normalizeTransportName(firstDefinedString(
        pickString(proxyValue, ['transport', 'network']),
        pickString(transportOptions, ['transport', 'network', 'type'])
      ) || 'raw');
  const security = protocol === 'hysteria2'
    ? 'tls'
    : normalizeSecurityName(firstDefinedString(
        pickString(proxyValue, ['security']),
        pickString(securityOptions, ['security', 'type'])
      ), mergedSource);

  if (protocol === 'vless') {
    const userId = firstDefinedString(
      pickString(protocolOptions, ['uuid', 'id', 'userId', 'userID']),
      pickString(proxyValue, ['uuid', 'id', 'userId'])
    );
    if (!looksLikeUuid(userId)) {
      return null;
    }

    return {
      family: 'xray',
      protocol: 'vless',
      remarks: label,
      transport: network as XrayRuntimeTemplate['transport'],
      outbound: compactObject({
        tag: 'proxy',
        protocol: 'vless',
        settings: {
          vnext: [
            {
              address: host,
              port,
              users: [
                compactObject({
                  id: userId,
                  encryption: firstDefinedString(pickString(protocolOptions, ['encryption']), pickString(proxyValue, ['encryption'])) || 'none',
                  flow: firstDefinedString(pickString(protocolOptions, ['flow']), pickString(proxyValue, ['flow']))
                })
              ]
            }
          ]
        },
        streamSettings: buildStreamFromStructuredOptions({ network, security, host, source: mergedSource })
      })
    };
  }

  if (protocol === 'vmess') {
    const userId = firstDefinedString(
      pickString(protocolOptions, ['uuid', 'id', 'userId', 'userID']),
      pickString(proxyValue, ['uuid', 'id', 'userId'])
    );
    if (!looksLikeUuid(userId)) {
      return null;
    }

    return {
      family: 'xray',
      protocol: 'vmess',
      remarks: label,
      transport: network as XrayRuntimeTemplate['transport'],
      outbound: compactObject({
        tag: 'proxy',
        protocol: 'vmess',
        settings: {
          vnext: [
            {
              address: host,
              port,
              users: [
                compactObject({
                  id: userId,
                  alterId: pickNumberValue(protocolOptions, ['alterId', 'aid']) ?? pickNumberValue(proxyValue, ['alterId', 'aid']) ?? 0,
                  security: firstDefinedString(pickString(protocolOptions, ['cipher', 'security']), pickString(proxyValue, ['cipher', 'security'])) || 'auto'
                })
              ]
            }
          ]
        },
        streamSettings: buildStreamFromStructuredOptions({ network, security: security === 'none' ? 'tls' : security, host, source: mergedSource })
      })
    };
  }

  if (protocol === 'trojan') {
    const password = firstDefinedString(
      pickString(protocolOptions, ['password', 'pass']),
      pickString(proxyValue, ['password', 'pass'])
    );
    if (!password) {
      return null;
    }

    return {
      family: 'xray',
      protocol: 'trojan',
      remarks: label,
      transport: network as XrayRuntimeTemplate['transport'],
      outbound: compactObject({
        tag: 'proxy',
        protocol: 'trojan',
        settings: {
          servers: [{ address: host, port, password, level: 0 }]
        },
        streamSettings: buildStreamFromStructuredOptions({ network, security: security === 'none' ? 'tls' : security, host, source: mergedSource })
      })
    };
  }

  if (protocol === 'shadowsocks') {
    const method = firstDefinedString(
      pickString(protocolOptions, ['method', 'cipher', 'cipherMethod']),
      pickString(proxyValue, ['method', 'cipher', 'cipherMethod'])
    );
    const password = firstDefinedString(
      pickString(protocolOptions, ['password', 'pass']),
      pickString(proxyValue, ['password', 'pass'])
    );
    if (!method || !password) {
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
          servers: [{ address: host, port, method, password }]
        }
      })
    };
  }

  if (protocol === 'hysteria2') {
    const password = firstDefinedString(
      pickString(protocolOptions, ['password', 'auth', 'authStr']),
      pickString(proxyValue, ['password', 'auth', 'authStr'])
    );
    if (!password) {
      return null;
    }

    const source = compactObject({ ...mergedSource, sni: firstDefinedString(pickString(proxyValue, ['sni', 'servername', 'serverName']), host) });
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
          ...buildStreamFromStructuredOptions({ network: 'hysteria', security: 'tls', host, source }),
          hysteriaSettings: compactObject({ version: 2, auth: password })
        })
      })
    };
  }

  return null;
}

function parseResolvedProxyConfigArray(items: unknown[], seed: string): VpnServer[] {
  const servers: VpnServer[] = [];

  for (const item of items) {
    if (servers.length >= MAX_IMPORTED_SERVERS) break;
    if (!isRecord(item)) {
      continue;
    }

    if (pickBooleanValue(item, ['metadata.isDisabled', 'isDisabled', 'disabled']) === true) {
      continue;
    }

    const label = pickStructuredDisplayLabel(item) || `Xray JSON ${servers.length + 1}`;
    const technicalLabel = pickStructuredTechnicalLabel(item);
    const runtime = buildRuntimeFromStructuredProxy(item, label);
    if (!runtime) {
      continue;
    }

    const identity = `${seed}:structured:${pickString(item, ['metadata.uuid', 'uuid', 'id']) || JSON.stringify(item)}`;
    const server = buildServerFromRuntimeTemplate(runtime, label, identity, servers.length);
    if (server) {
      servers.push(preserveServerLocationFromTechnicalLabel(server, technicalLabel));
    }
  }

  return servers;
}

function parseResolvedProxyConfigServersFromPayload(payload: unknown, seed: string): VpnServer[] {
  const preferredArrays = collectArraysAtPaths(payload, [
    'response.rawHosts',
    'rawHosts',
    'data.rawHosts',
    'response.hosts',
    'hosts',
    'data.hosts',
    'response.subscription.rawHosts',
    'response.user.rawHosts',
    'response.resolvedProxyConfigs',
    'resolvedProxyConfigs',
    'data.resolvedProxyConfigs',
    'response.subscription.resolvedProxyConfigs',
    'response.user.resolvedProxyConfigs',
    'response.proxyConfigs',
    'proxyConfigs',
    'data.proxyConfigs',
    'response.proxies',
    'proxies',
    'data.proxies'
  ]);

  const explicitCandidates = preferredArrays
    .map(({ path, value }) => ({ path, servers: parseResolvedProxyConfigArray(value, `${seed}:${path}`), priority: path.toLowerCase().includes('rawhosts') ? 950 : 900 }))
    .filter((candidate) => candidate.servers.length);

  if (explicitCandidates.length) {
    return chooseBestStructuredServerSet(explicitCandidates);
  }

  const recursiveArrays = collectArraysByKey(payload, ['rawHosts', 'resolvedProxyConfigs', 'proxyConfigs', 'proxies']);
  const fallbackCandidates = recursiveArrays
    .map((value, index) => ({ path: `nested.${index}`, servers: parseResolvedProxyConfigArray(value, `${seed}:nested:${index}`), priority: 650 }))
    .filter((candidate) => candidate.servers.length);

  return chooseBestStructuredServerSet(fallbackCandidates);
}

function extractRuntimeEndpoint(runtimeTemplate: XrayRuntimeTemplate | null) {
  const settings = runtimeTemplate?.outbound?.settings as
    | {
        vnext?: Array<{ address?: string; port?: number }>;
        servers?: Array<{ address?: string; port?: number }>;
        address?: string;
        port?: number;
      }
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

  if (settings?.address) {
    return {
      host: settings.address,
      port: typeof settings.port === 'number' ? settings.port : 443
    };
  }

  return {
    host: undefined,
    port: 443
  };
}

function parseXrayJsonServersFromPayload(payload: unknown, seed: string): VpnServer[] {
  if (!payload) {
    return [];
  }

  const explicitOutbounds = collectArraysAtPaths(payload, [
    'outbounds',
    'response.outbounds',
    'response.config.outbounds',
    'response.xrayConfig.outbounds',
    'response.xrayJson.outbounds',
    'config.outbounds',
    'xrayConfig.outbounds',
    'xrayJson.outbounds'
  ]);

  const explicitCandidates = explicitOutbounds
    .map(({ path, value }) => ({ path, servers: parseXrayOutboundArray(value, `${seed}:${path}`), priority: 700 }))
    .filter((candidate) => candidate.servers.length);
  if (explicitCandidates.length) {
    return chooseBestStructuredServerSet(explicitCandidates);
  }

  const recursiveOutbounds = collectArraysByKey(payload, ['outbounds']);
  for (const outbounds of recursiveOutbounds) {
    const servers = parseXrayOutboundArray(outbounds, `${seed}:nested`);
    if (servers.length) {
      return servers;
    }
  }

  return [];
}

function parseXrayJsonStringCandidatesFromPayload(payload: unknown, seed: string): VpnServer[] {
  const candidates: ServerCandidate[] = [];
  const visited = { count: 0 };

  const walk = (source: unknown, path: string, depth: number) => {
    if (depth > MAX_JSON_WALK_DEPTH || visited.count > MAX_JSON_WALK_NODES || candidates.length > 64) {
      return;
    }

    visited.count += 1;

    if (typeof source === 'string') {
      const parsed = parseMaybeJsonObject(source);
      if (parsed) {
        const servers = parseXrayJsonOnlyServersFromPayload(parsed, `${seed}:${path}`);
        if (servers.length) {
          candidates.push({ path: `json-string.${path}`, servers, priority: /xray|json|config/i.test(path) ? 850 : 500 });
        }
      }
      return;
    }

    if (Array.isArray(source)) {
      source.forEach((item, index) => walk(item, `${path}.${index}`, depth + 1));
      return;
    }

    if (isRecord(source)) {
      for (const [key, value] of Object.entries(source)) {
        walk(value, `${path}.${key}`, depth + 1);
        if (candidates.length > 64) break;
      }
    }
  };

  walk(payload, 'root', 0);
  return chooseBestStructuredServerSet(candidates);
}

function parseXrayJsonOnlyServersFromPayload(payload: unknown, seed: string): VpnServer[] {
  const candidates = [
    { path: 'xray-json.standard-config-array', priority: 1200, servers: parseXrayConfigArray(payload, seed) },
    { path: 'xray-json.remnawave-structured', priority: 950, servers: parseResolvedProxyConfigServersFromPayload(payload, seed) },
    { path: 'xray-json.outbounds', priority: 700, servers: parseXrayJsonServersFromPayload(payload, seed) },
    { path: 'xray-json.embedded-json', priority: 500, servers: parseXrayJsonStringCandidatesFromPayload(payload, seed) }
  ].filter((candidate) => candidate.servers.length);

  return chooseBestStructuredServerSet(candidates);
}

export function parseXrayJsonSubscriptionToServers(rawText: string): VpnServer[] {
  const safeRawText = rawText.length > MAX_SUBSCRIPTION_BYTES
    ? rawText.slice(0, MAX_SUBSCRIPTION_BYTES)
    : rawText;
  const trimmed = stripUtfBom(safeRawText);

  if (!trimmed || (!trimmed.startsWith('{') && !trimmed.startsWith('['))) {
    return [];
  }

  try {
    const parsed = JSON.parse(trimmed);
    const servers = parseXrayJsonOnlyServersFromPayload(parsed, 'xray-json');
    return withUniqueSubscriptionIds(
      filterRemnawaveCascadeBackendMembers(servers).slice(0, MAX_IMPORTED_SERVERS)
    );
  } catch {
    return [];
  }
}
