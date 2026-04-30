import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const coreDir = join(root, 'resources', 'core', 'windows');
const manifestPath = join(coreDir, 'core-manifest.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function assertWindowsX64Pe(path, label) {
  const header = readFileSync(path).subarray(0, 4096);
  const prefix = header.subarray(0, Math.min(32, header.length)).toString('utf8');
  if (prefix.startsWith('version https://git-lfs')) {
    throw new Error(`${label} is a Git LFS pointer, not a real binary`);
  }
  if (header.length < 256 || header[0] !== 0x4d || header[1] !== 0x5a) {
    throw new Error(`${label} has invalid MZ header`);
  }
  const peOffset = header.readUInt32LE(0x3c);
  if (peOffset < 64 || peOffset + 26 > header.length) {
    throw new Error(`${label} has invalid PE offset: ${peOffset}`);
  }
  if (header[peOffset] !== 0x50 || header[peOffset + 1] !== 0x45 || header[peOffset + 2] !== 0 || header[peOffset + 3] !== 0) {
    throw new Error(`${label} has invalid PE signature at offset ${peOffset}`);
  }
  const machine = header.readUInt16LE(peOffset + 4);
  const optionalHeaderMagic = header.readUInt16LE(peOffset + 24);
  if (machine !== 0x8664 || optionalHeaderMagic !== 0x20b) {
    throw new Error(`${label} must be Windows x64 PE32+. machine=0x${machine.toString(16)} optional=0x${optionalHeaderMagic.toString(16)}`);
  }
}

for (const expectedName of ['xray.exe', 'wintun.dll', 'geoip.dat', 'geosite.dat']) {
  const entry = manifest.files?.find((item) => String(item.file).toLowerCase() === expectedName.toLowerCase());
  if (!entry) {
    throw new Error(`core-manifest.json does not contain ${expectedName}`);
  }
  const path = join(coreDir, expectedName);
  const stat = statSync(path);
  if (stat.size !== Number(entry.size)) {
    throw new Error(`${expectedName} size mismatch. expected=${entry.size} actual=${stat.size}`);
  }
  const actualHash = sha256(path);
  const expectedHash = String(entry.sha256 || '').trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(expectedHash) || actualHash !== expectedHash) {
    throw new Error(`${expectedName} sha256 mismatch. expected=${expectedHash} actual=${actualHash}`);
  }
  console.log(`[core-manifest] OK ${expectedName} ${stat.size} ${actualHash}`);
}

assertWindowsX64Pe(join(coreDir, 'xray.exe'), 'xray.exe');
assertWindowsX64Pe(join(coreDir, 'wintun.dll'), 'wintun.dll');
console.log('[core-manifest] OK bundled Windows core files match manifest and PE headers');
