// Structural bounds only; this is not a substitute for provenance, digest,
// signature, loader or native runtime verification.
export function assertPeSectionBounds(data, label = 'PE resource') {
  if (data.length < 256 || data.readUInt16LE(0) !== 0x5a4d) throw new Error(`${label}: invalid MZ header`);
  const pe = data.readUInt32LE(60);
  if (pe < 64 || pe + 26 > data.length || data.readUInt32LE(pe) !== 0x4550) throw new Error(`${label}: invalid PE header`);
  if (data.readUInt16LE(pe + 4) !== 0x8664 || data.readUInt16LE(pe + 24) !== 0x20b) throw new Error(`${label}: expected amd64 PE32+`);
  const count = data.readUInt16LE(pe + 6);
  const optionalSize = data.readUInt16LE(pe + 20);
  const table = pe + 24 + optionalSize;
  const end = table + count * 40;
  // IMAGE_FILE_HEADER: the Windows loader supports at most 96 sections.
  if (!count || count > 96 || optionalSize < 112 || end > data.length) throw new Error(`${label}: invalid PE section table`);
  for (let index = 0; index < count; index++) {
    const section = table + index * 40;
    const size = data.readUInt32LE(section + 16);
    const start = data.readUInt32LE(section + 20);
    // JS numbers safely hold the sum of two uint32 values; no wrapping.
    if (size && (start < end || start + size > data.length)) throw new Error(`${label}: truncated or overlapping PE section data`);
  }
}
