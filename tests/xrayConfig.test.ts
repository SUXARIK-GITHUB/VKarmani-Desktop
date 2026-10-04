import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import auto from './fixtures/xray/auto.json';
import { canonicalJson, sha256Text } from '../src/utils/canonicalJson';
import { readXrayConfigGraph, XrayConfigError } from '../src/services/remnawave/xrayConfig';
import { parseXrayJsonSubscriptionToServers as parse } from '../src/services/remnawave/subscriptionParser';
import { getServerPingEndpoint, pingNativeServer } from '../src/services/runtime';
import { __remnawaveTest } from '../src/services/remnawave';
import { migrateServerReferences, resolveServerReference, buildServerRuntimeFingerprint } from '../src/utils/serverIdentity';
import { rankServersForDisplay } from '../src/utils/serverSorting';

const copy = () => structuredClone(auto);
describe('lossless Xray configuration graph', () => {
  it('preserves every JSON value and does not mutate the input', () => {
    const input = copy(), graph = readXrayConfigGraph(input);
    expect(graph.config).toEqual(input);
    (graph.config.futureExtension as Record<string, unknown>).unicode = 'changed';
    expect(input).toEqual(auto);
    const [profile] = parse(JSON.stringify(input));
    expect(profile.runtimeTemplate?.fullConfig).toEqual(input);
    expect(profile.rawUri).toBeUndefined();
  });
  it('derives one Auto profile without a brand-name convention', () => {
    const profiles = parse(JSON.stringify(auto));
    expect(profiles).toHaveLength(1);
    expect(profiles[0].runtimeTemplate?.profileKind).toBe('auto');
    expect(profiles[0].runtimeTemplate?.primaryBalancerTag).toBe('general-choice');
    expect(profiles[0].runtimeTemplate?.memberTags).toEqual(['pool-a', 'pool-b']);
  });
  it('does not retain obsolete members when a canonical Auto replaces a larger cached set', () => {
    const profiles = parse(JSON.stringify(auto));
    expect(__remnawaveTest.shouldKeepPreviousFullProfile([...profiles, { ...profiles[0], id: 'old-member' }], profiles)).toBe(false);
  });
  it('does not present the representative member TCP latency as an Auto measurement', async () => {
    const [profile] = parse(JSON.stringify(auto));
    expect(getServerPingEndpoint(profile)).toBeNull();
    await expect(pingNativeServer(profile)).rejects.toThrow(/host\/port/);
  });
  it('migrates unambiguous legacy favorites/selection without guessing collisions', () => {
    const profiles = parse(JSON.stringify([auto, { ...auto, remarks: 'Second' }]));
    const legacy = profiles[1].legacyIds![0];
    // Both profiles previously hashed only their identical representative outbound.
    expect(resolveServerReference(profiles, legacy)).toBeNull();
    const unique = profiles.slice(1);
    expect(resolveServerReference(unique, legacy)).toBe(unique[0]);
    expect(migrateServerReferences(unique, [legacy, unique[0].id, 'missing'])).toEqual([unique[0].id, 'missing']);
    expect(rankServersForDisplay(unique, 'auto', [legacy])[0]).toBe(unique[0]);
  });
  it('runtime fingerprint changes when any full graph setting or credential changes', () => {
    const [profile] = parse(JSON.stringify(auto));
    const changed = structuredClone(profile);
    (changed.runtimeTemplate!.fullConfig!.futureExtension as Record<string, unknown>).unicode = 'Changed';
    expect(buildServerRuntimeFingerprint(profile)).toHaveLength(64);
    expect(buildServerRuntimeFingerprint(profile)).not.toBe(buildServerRuntimeFingerprint(changed));
  });
  it('preserves multiple balancers and their complete routing', () => {
    const input = copy();
    input.routing.balancers.push({ tag: 'second', selector: ['pool-b'], strategy: { type: 'random', settings: { expected: 1 } }, fallbackTag: 'pool-a' });
    input.routing.rules.unshift({ type: 'field', domain: ['domain:another.example'], balancerTag: 'second' } as typeof input.routing.rules[number]);
    const profiles = parse(JSON.stringify(input));
    expect(profiles).toHaveLength(1);
    expect(profiles[0].runtimeTemplate?.fullConfig?.routing).toEqual(input.routing);
  });
  it('uses case-sensitive prefix selectors and permits fallback-only operation', () => {
    const input = copy();
    input.routing.balancers[0].selector = ['POOL-'];
    expect(readXrayConfigGraph(input).memberTags).toEqual(['pool-b']);
    input.routing.balancers[0].fallbackTag = '';
    expect(() => readXrayConfigGraph(input)).toThrow(/selector matches nothing/);
  });
  it.each(['outbound', 'balancer'])('rejects duplicate %s tags', (kind) => {
    const input = copy();
    if (kind === 'outbound') input.outbounds.push(input.outbounds[0]);
    else input.routing.balancers.push(input.routing.balancers[0]);
    expect(() => parse(JSON.stringify(input))).toThrow(XrayConfigError);
  });
  it.each(['outboundTag', 'balancerTag', 'fallbackTag'])('rejects a broken %s reference without leaking its value', (key) => {
    const input = copy(), secret = 'credential-should-not-be-in-error';
    if (key === 'fallbackTag') input.routing.balancers[0].fallbackTag = secret;
    else (input.routing.rules[0] as Record<string, unknown>)[key] = secret;
    try { parse(JSON.stringify(input)); throw new Error('accepted broken graph'); }
    catch (error) { expect(error).toBeInstanceOf(XrayConfigError); expect(String(error)).not.toContain(secret); }
  });
  it('rejects ambiguous targets and invalid selector types', () => {
    const input = copy();
    (input.routing.rules[0] as Record<string, unknown>).balancerTag = 'general-choice';
    expect(() => readXrayConfigGraph(input)).toThrow(/ambiguous/);
    const other = copy();
    (other.routing.balancers[0] as Record<string, unknown>).selector = [17];
    expect(() => readXrayConfigGraph(other)).toThrow(/selector/);
  });
  it('validates dialerProxy references and rejects cycles', () => {
    const input = copy();
    (input.outbounds[0].streamSettings as Record<string, unknown>).sockopt = { dialerProxy: 'absent' };
    expect(() => readXrayConfigGraph(input)).toThrow(/missing target/);
    (input.outbounds[0].streamSettings as Record<string, unknown>).sockopt = { dialerProxy: 'pool-b' };
    (input.outbounds[1].streamSettings as Record<string, unknown>).sockopt = { dialerProxy: 'pool-a' };
    expect(() => readXrayConfigGraph(input)).toThrow(/cycle/);
  });
  it('prioritizes canonical configs over a larger rawHosts set', () => {
    const profiles = parse(JSON.stringify({ response: { config: auto, rawHosts: Array.from({ length: 30 }, (_, i) => ({ protocol: 'vless', host: `node${i}.example.com`, port: 443, uuid: '123e4567-e89b-12d3-a456-426614174000' })) } }));
    expect(profiles).toHaveLength(1);
    expect(profiles[0].runtimeTemplate?.fullConfig).toEqual(auto);
  });
  it('keeps IDs stable across object-key order and external profile order', () => {
    const input = copy(); input.remarks = 'Other';
    const first = parse(JSON.stringify([auto, input]));
    const reversedKeys = Object.fromEntries(Object.entries(auto).reverse());
    const second = parse(JSON.stringify([input, reversedKeys]));
    expect(first.map((p) => p.id).sort()).toEqual(second.map((p) => p.id).sort());
    input.outbounds[0].settings.vnext![0].users[0].id = '223e4567-e89b-12d3-a456-426614174000';
    expect(parse(JSON.stringify(input))[0].id).not.toBe(first[1].id);
  });
  it('reports malformed JSON, UTF-8 byte/depth limits and unsupported endpoints explicitly', () => {
    expect(() => parse('{invalid')).toThrow(/INVALID_JSON/);
    expect(() => parse(JSON.stringify({ text: '🌍'.repeat(524288) }))).toThrow(/document bytes/);
    let nested: unknown = {}; for (let i = 0; i < 65; i++) nested = { nested };
    expect(() => parse(JSON.stringify(nested))).toThrow(/complexity/);
    expect(() => parse(JSON.stringify({ outbounds: [{ protocol: 'future-protocol', settings: {} }] }))).toThrow(/UNSUPPORTED/);
  });
  it('handles a large Unicode graph within the explicit limit', () => {
    const input = copy(); input.futureExtension.unicode = 'Россия🌍'.repeat(20000);
    expect(parse(JSON.stringify(input))[0].runtimeTemplate?.fullConfig).toEqual(input);
  });
  it('preserves __proto__ as data without polluting prototypes', () => {
    const input = JSON.parse(JSON.stringify(auto).replace('"futureExtension":{', '"futureExtension":{"__proto__":{"polluted":true},'));
    expect(readXrayConfigGraph(input).config).toEqual(input);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});

describe('canonical identity digest', () => {
  it.each(['single', 'multi', 'auto', 'fallback', 'unicode', 'missing-optional'])('matches native wire/cache identity for %s profiles', (kind) => {
    let input: unknown = structuredClone(auto);
    if (kind === 'single' || kind === 'missing-optional') input = { outbounds: [structuredClone(auto.outbounds[0])] };
    if (kind === 'multi') input = { outbounds: structuredClone(auto.outbounds.slice(0, 2)) };
    if (kind === 'unicode') (input as Record<string, unknown>).remarks = 'Россия Я 🚀';
    if (kind === 'fallback') (input as typeof auto).routing.balancers[0].fallbackTag = 'pool-a';
    const profiles = parse(JSON.stringify(input));
    expect(profiles.length).toBeGreaterThan(0);
    for (const profile of profiles) {
      const wire = JSON.parse(JSON.stringify(profile));
      expect(canonicalJson(profile.runtimeTemplate)).toBe(canonicalJson(wire.runtimeTemplate));
      expect(buildServerRuntimeFingerprint(profile)).toBe(buildServerRuntimeFingerprint(wire));
      expect(JSON.parse(canonicalJson(profile.runtimeTemplate))).toEqual(wire.runtimeTemplate);
    }
  });
  it.each(['', 'abc', '🌍 Россия', 'a'.repeat(55), 'a'.repeat(56), 'a'.repeat(64), 'a'.repeat(1000000)])('matches standard SHA-256 for vector length %i', (input) => {
    expect(sha256Text(input)).toBe(createHash('sha256').update(input).digest('hex'));
  });
  it('sorts object keys without reordering arrays or deleting empty values', () => {
    expect(canonicalJson({ b: ['', null, []], a: 0 })).toBe('{"a":0,"b":["",null,[]]}');
  });
});
