import { describe, expect, it } from 'vitest';
import auto from './fixtures/xray/auto.json';
import { canonicalJson } from '../src/utils/canonicalJson';
import { readXrayConfigGraph, XrayConfigError } from '../src/services/remnawave/xrayConfig';
import { OperationOwnership } from '../src/utils/operationOwnership';
import { acceptRuntimeSnapshot, connectionFailureState } from '../src/utils/runtimeSnapshot';
import { supportRedactor } from '../src/utils/diagnosticsExport';
import type { RuntimeStatus } from '../src/types/vpn';

// Reproducible bounded generated inputs, not random time-dependent fuzzing.
function rng(seed: number) { return () => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed; }; }
function reverseKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reverseKeys);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).reverse().map(([key, child]) => [key, reverseKeys(child)]));
  return value;
}
describe('bounded release property and negative corpus', () => {
  it('preserves wire values and graph identity under 256 nested order permutations', () => {
    const next = rng(0x564b);
    for (let index = 0; index < 256; index++) {
      const input = { ...structuredClone(auto), futureExtension: { unicode: `Я 🚀 ${next()}`, optional: index % 2 ? undefined : null,
        list: [undefined, null, false, 0, { missing: undefined, empty: '', number: next() }] } };
      const wire = JSON.parse(JSON.stringify(input));
      expect(JSON.parse(canonicalJson(input))).toEqual(wire);
      expect(canonicalJson(input)).toBe(canonicalJson(reverseKeys(input)));
      expect(readXrayConfigGraph(wire).config).toEqual(wire);
    }
  });
  it('rejects 256 mutated references/types/cycles without leaking opaque tag data', () => {
    for (let index = 0; index < 256; index++) {
      const input = structuredClone(auto), secret = `synthetic-opaque-tag-${index}-not-for-errors`;
      if (index % 4 === 0) input.routing.balancers[0].fallbackTag = secret;
      if (index % 4 === 1) (input.routing.rules[0] as Record<string, unknown>).outboundTag = secret;
      if (index % 4 === 2) (input.routing.balancers[0] as Record<string, unknown>).selector = [null, index];
      if (index % 4 === 3) {
        (input.outbounds[0].streamSettings as Record<string, unknown>).sockopt = { dialerProxy: 'pool-b' };
        (input.outbounds[1].streamSettings as Record<string, unknown>).sockopt = { dialerProxy: 'pool-a' };
      }
      let caught: unknown;
      try { readXrayConfigGraph(input); } catch (error) { caught = error; }
      expect(caught).toBeInstanceOf(XrayConfigError);
      expect(String(caught)).not.toContain(secret);
    }
  });
  it('matches an independent conflict/token model over 5000 acquire/release interleavings', () => {
    const ownership = new OperationOwnership(), model = new Map<string, number>(), next = rng(0x004);
    const names = ['connect', 'disconnect', 'probe', 'export'];
    const conflicts = { connect: ['disconnect', 'probe'], disconnect: ['connect'], probe: ['connect'], export: [] };
    let sequence = 0;
    for (let index = 0; index < 5000; index++) {
      const name = names[next() % names.length];
      if (next() % 3) {
        const blocked = [...model.keys()].some(other => other === name || conflicts[name as keyof typeof conflicts].includes(other) || conflicts[other as keyof typeof conflicts].includes(name));
        const actual = ownership.acquire(name, conflicts);
        expect(actual).toBe(blocked ? null : ++sequence);
        if (!blocked) model.set(name, actual!);
      } else {
        const token = next() % 2 ? model.get(name) ?? -1 : sequence - 1;
        const allowed = model.get(name) === token;
        expect(ownership.release(name, token)).toBe(allowed);
        if (allowed) model.delete(name);
      }
      expect(Object.keys(ownership.snapshot()).sort()).toEqual([...model.keys()].sort());
    }
  });
  it('does not roll back newer native state through 1024 delayed snapshot/attempt pairs', () => {
    const next = rng(0x13);
    for (let index = 0; index < 1024; index++) {
      const revision = next() % 1000 + 1;
      const current: RuntimeStatus = { bridge: 'tauri', coreInstalled: true, tunnelActive: true, message: '', nativeInstanceId: 'candidate', runtimeRevision: revision };
      const stale = { ...current, tunnelActive: false, runtimeRevision: revision - 1 };
      expect(acceptRuntimeSnapshot(current, stale)).toBe(current);
      expect(connectionFailureState(stale, index, index + 1)).toBe('stale');
      expect(connectionFailureState({ ...current, operation: { id: index, kind: 'connect', stage: 'starting', startedAt: 0, deadlineAt: 1 } }, index, index)).toBe('pending');
      expect(connectionFailureState({ ...current, tunnelActive: false }, index, index)).toBe('idle');
    }
  });
  it('redacts 256 Unicode and encoded secret variants while retaining ordinary diagnostics', () => {
    for (let index = 0; index < 256; index++) {
      const secret = `тестовый-${index}-credential`, encoded = encodeURIComponent(secret);
      const redactor = supportRedactor({ accessKey: secret } as any);
      const output = redactor(`ordinary diagnostic ${secret} ${encoded} https://example.com/${encoded} Cookie: sid=${secret}`);
      expect(output).not.toContain(secret); expect(output).not.toContain(encoded);
      expect(output).toContain('ordinary diagnostic'); expect(output).not.toContain('https://');
    }
  });
});
