import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../src/utils/canonicalJson';

describe('canonical JSON follows the native JSON transport', () => {
  it.each([
    { optional: undefined, present: null },
    { nested: { optional: undefined, unicode: 'Я 🚀', flag: false, zero: 0, empty: '' } },
    { array: [undefined, null, , { absent: undefined, unknown: { b: 2, a: 1 } }] },
  ])('preserves the wire representation of %j', (value) => {
    expect(JSON.parse(canonicalJson(value))).toEqual(JSON.parse(JSON.stringify(value)));
    expect(canonicalJson(value)).toBe(canonicalJson(JSON.parse(JSON.stringify(value))));
  });
  it('keeps missing distinct from null and canonicalizes key order', () => {
    expect(canonicalJson({ missing: undefined })).toBe('{}');
    expect(canonicalJson({ present: null })).toBe('{"present":null}');
    expect(canonicalJson({ b: 2, a: 1 })).toBe(canonicalJson({ a: 1, b: 2 }));
  });
  it('checks 64 bounded nested optional-field permutations', () => {
    for (let seed = 0; seed < 64; seed++) {
      const value = { z: seed % 2 ? undefined : null, a: { unicode: `Я${seed}🚀`,
        unknown: { empty: '', flag: false, zero: 0, maybe: seed % 3 ? undefined : seed } },
        list: [seed, undefined, { optional: undefined, visible: seed % 2 === 0 }] };
      const wire = JSON.parse(JSON.stringify(value));
      expect(JSON.parse(canonicalJson(value))).toEqual(wire);
      expect(canonicalJson(value)).toBe(canonicalJson(wire));
    }
  });
});
