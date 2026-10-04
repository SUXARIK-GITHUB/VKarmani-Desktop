import { describe, expect, it } from 'vitest';
import auto from './fixtures/xray/auto.json';
import { parseXrayJsonSubscriptionToServers as parse } from '../src/services/remnawave/subscriptionParser';
import { encodeProfileCache, decodeProfileCache, ProfileCacheError } from '../src/services/profileCache';

describe('versioned encrypted profile cache representation', () => {
  it('round-trips unknown fields without mutating inputs and shares canonical graphs', () => {
    const [profile] = parse(JSON.stringify(auto));
    const input = Array.from({ length: 100 }, (_, i) => ({ ...profile, id: `node-${i}` }));
    const before = structuredClone(input);
    const cache = encodeProfileCache(input);
    expect(Object.keys(cache.graphs)).toHaveLength(1);
    const restored = decodeProfileCache(JSON.parse(JSON.stringify(cache))) as typeof input;
    expect(restored).toEqual(input);
    expect(restored[0].runtimeTemplate!.fullConfig).toBe(restored[99].runtimeTemplate!.fullConfig);
    expect(input).toEqual(before);
    expect(JSON.stringify(cache).length).toBeLessThan(JSON.stringify(input).length);
    expect(cache.servers.every((server) => !Object.hasOwn(server.runtimeTemplate!, 'fullConfig'))).toBe(true);
  });
  it('stores a large shared graph once rather than amplifying it for every node', () => {
    const config = { ...auto, futureExtension: { unicode: 'Я'.repeat(200_000) } };
    const [profile] = parse(JSON.stringify(config));
    const input = Array.from({ length: 100 }, (_, i) => ({ ...profile, id: `large-node-${i}` }));
    const cache = encodeProfileCache(input);
    const bytes = new TextEncoder().encode(JSON.stringify(cache)).length;
    expect(bytes).toBeLessThan(600_000);
    expect(Object.keys(cache.graphs)).toHaveLength(1);
    expect(decodeProfileCache(cache)).toEqual(input);
  });
  it('keeps the legacy encrypted array readable without dropping profiles', () => {
    const input = parse(JSON.stringify(auto));
    expect(decodeProfileCache(input)).toBe(input);
  });
  it.each(['version', 'digest', 'reference', 'shape', 'inline'])('rejects corrupted %s without partial profile recovery', (kind) => {
    const cache: Record<string, any> = JSON.parse(JSON.stringify(encodeProfileCache(parse(JSON.stringify(auto)))));
    if (kind === 'version') cache.version = 3;
    if (kind === 'digest') Object.values<Record<string, unknown>>(cache.graphs)[0].dns = {};
    if (kind === 'reference') cache.servers[0].runtimeTemplate.canonicalConfigId = 'missing';
    if (kind === 'shape') cache.servers[0].runtimeTemplate = 'not a template';
    if (kind === 'inline') {
      delete cache.servers[0].runtimeTemplate.canonicalConfigId;
      cache.servers[0].runtimeTemplate.fullConfig = auto;
    }
    expect(() => decodeProfileCache(cache)).toThrow(ProfileCacheError);
  });
  it('checks imported graph integrity even when its digest is internally consistent', () => {
    const [profile] = parse(JSON.stringify(auto));
    profile.runtimeTemplate!.fullConfig!.outbounds = [];
    expect(() => encodeProfileCache([profile])).toThrow();
  });
  it('rejects oversized profile count instead of truncating cached profiles', () => {
    expect(() => decodeProfileCache(Array.from({ length: 1001 }, () => ({})))).toThrow(ProfileCacheError);
  });
  it('rejects an oversized cache before restoring any profiles', () => {
    expect(() => decodeProfileCache({ version: 2, graphs: {}, servers: [], padding: 'x'.repeat(8 * 1024 * 1024) })).toThrow(ProfileCacheError);
  });
});
