import type { VpnServer, XrayRuntimeTemplate } from '../types/vpn';
import { canonicalJson, sha256Text } from '../utils/canonicalJson';
import { isJsonObject, readXrayConfigGraph, validateJsonBounds } from './remnawave/xrayConfig';

interface CachedTemplate extends Omit<XrayRuntimeTemplate, 'fullConfig'> {
  canonicalConfigId?: string;
}
interface CachedProfile extends Omit<VpnServer, 'runtimeTemplate'> {
  runtimeTemplate?: CachedTemplate;
}
interface ProfileCacheV2 {
  version: 2;
  graphs: Record<string, Record<string, unknown>>;
  servers: CachedProfile[];
}

export class ProfileCacheError extends Error {
  constructor() { super('Повреждённый или неподдерживаемый защищённый кэш профилей.'); }
}

// Only this compact representation enters DPAPI. Never use it in public state.
export function encodeProfileCache(servers: VpnServer[]): ProfileCacheV2 {
  if (servers.length > 1000) throw new ProfileCacheError();
  const graphs: ProfileCacheV2['graphs'] = Object.create(null);
  const identities = new WeakMap<object, string>();
  const cached = servers.map((server): CachedProfile => {
    if (!server.runtimeTemplate?.fullConfig) return { ...server };
    const { fullConfig, ...template } = server.runtimeTemplate;
    let id = identities.get(fullConfig);
    if (!id) {
      id = sha256Text(canonicalJson(fullConfig));
      identities.set(fullConfig, id);
    }
    if (!graphs[id]) graphs[id] = readXrayConfigGraph(fullConfig).config;
    return { ...server, runtimeTemplate: { ...template, canonicalConfigId: id } };
  });
  const cache: ProfileCacheV2 = { version: 2, graphs, servers: cached };
  if (new TextEncoder().encode(JSON.stringify(cache)).length > 8 * 1024 * 1024 - 1024) throw new ProfileCacheError();
  return cache;
}

export function decodeProfileCache(value: unknown): unknown[] {
  // The native store applies the same plaintext limit. Keep browser migration
  // and direct codec callers bounded too, before cloning canonical graphs.
  if (new TextEncoder().encode(JSON.stringify(value) ?? '').length > 8 * 1024 * 1024) throw new ProfileCacheError();
  // Legacy v1 arrays migrate in memory without touching their original file.
  if (Array.isArray(value)) {
    if (value.length > 1000) throw new ProfileCacheError();
    validateJsonBounds(value);
    return value;
  }
  if (!isJsonObject(value) || value.version !== 2 || !isJsonObject(value.graphs) || !Array.isArray(value.servers) || value.servers.length > 1000) throw new ProfileCacheError();
  validateJsonBounds(value, 70, 400000);
  const graphs = new Map<string, Record<string, unknown>>();
  for (const [id, config] of Object.entries(value.graphs)) {
    if (!isJsonObject(config) || id !== sha256Text(canonicalJson(config))) throw new ProfileCacheError();
    graphs.set(id, readXrayConfigGraph(config).config);
  }
  return value.servers.map((server) => {
    if (!isJsonObject(server)) throw new ProfileCacheError();
    if (!server.runtimeTemplate) return server;
    if (!isJsonObject(server.runtimeTemplate)) throw new ProfileCacheError();
    const { canonicalConfigId, ...template } = server.runtimeTemplate;
    if (Object.prototype.hasOwnProperty.call(template, 'fullConfig')) throw new ProfileCacheError();
    if (canonicalConfigId === undefined) return { ...server, runtimeTemplate: template };
    if (typeof canonicalConfigId !== 'string' || !graphs.has(canonicalConfigId)) throw new ProfileCacheError();
    return { ...server, runtimeTemplate: { ...template, fullConfig: graphs.get(canonicalConfigId) } };
  });
}
