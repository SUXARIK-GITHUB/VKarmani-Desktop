import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { assertPeSectionBounds } from '../scripts/pe-structure.mjs';
function fixture() {
  const data = Buffer.alloc(1024);
  data.writeUInt16LE(0x5a4d,0); data.writeUInt32LE(128,60); data.writeUInt32LE(0x4550,128);
  data.writeUInt16LE(0x8664,132); data.writeUInt16LE(1,134); data.writeUInt16LE(240,148); data.writeUInt16LE(0x20b,152);
  data.writeUInt32LE(512,408); data.writeUInt32LE(512,412);
  return data;
}
describe('R68/R70 damaged PE resource rejection before execution', () => {
  it('accepts a bounded synthetic section and both actual trusted bundle structures', () => {
    expect(() => assertPeSectionBounds(fixture())).not.toThrow();
    for (const name of ['xray.exe','wintun.dll']) expect(() => assertPeSectionBounds(readFileSync(`resources/core/windows/${name}`))).not.toThrow();
  });
  it('rejects every byte truncation including intact MZ/amd64/PE32+ headers', () => {
    const data = fixture(); for (let length=0; length<data.length; length++) expect(() => assertPeSectionBounds(data.subarray(0,length))).toThrow();
  });
  it.each([[134,0],[134,97],[148,2],[148,65535]])('rejects invalid COFF metadata at %i = %i', (offset,value) => {
    const data=fixture();data.writeUInt16LE(value,offset);expect(()=>assertPeSectionBounds(data)).toThrow('section table');
  });
  it.each([0,200,0xfffffff0])('rejects raw pointers outside bounded section data %i without uint32 wrap', pointer => {
    const data=fixture();data.writeUInt32LE(pointer,412);expect(()=>assertPeSectionBounds(data)).toThrow('section data');
  });
  it('allows uninitialized data without a raw file span', () => {
    const data=fixture();data.writeUInt32LE(0,408);data.writeUInt32LE(0,412);expect(()=>assertPeSectionBounds(data)).not.toThrow();
  });
});
