import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

// Execute the actual release checker against one owned file fixture. No updater,
// installer, application process, network operation or live AppData is invoked.
let fixture = '';
let originalCargo = '';
let originalLock = '';
let originalConfig = '';
let originalWorkflow = '';
const source = process.cwd();
beforeAll(() => {
  fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'vkarmani-updater-policy-'));
  for (const name of ['package.json', 'package-lock.json', '.npmrc', '.gitattributes', '.github/workflows/release.yml', 'src-tauri/Cargo.toml', 'src-tauri/Cargo.lock', 'src-tauri/tauri.conf.json', 'resources/core/windows/core-manifest.json', 'resources/core/windows/xray.exe', 'resources/core/windows/wintun.dll', 'resources/core/windows/geoip.dat', 'resources/core/windows/geosite.dat']) {
    const target = path.join(fixture, name); fs.mkdirSync(path.dirname(target), { recursive: true }); fs.copyFileSync(path.join(source, name), target);
  }
  originalCargo = fs.readFileSync(path.join(fixture, 'src-tauri/Cargo.toml'), 'utf8');
  originalLock = fs.readFileSync(path.join(fixture, 'src-tauri/Cargo.lock'), 'utf8').replace(/\r\n/g, '\n');
  originalConfig = fs.readFileSync(path.join(fixture, 'src-tauri/tauri.conf.json'), 'utf8');
  originalWorkflow = fs.readFileSync(path.join(fixture, '.github/workflows/release.yml'), 'utf8');
});
afterEach(() => {
  fs.writeFileSync(path.join(fixture, 'src-tauri/Cargo.toml'), originalCargo);
  fs.writeFileSync(path.join(fixture, 'src-tauri/Cargo.lock'), originalLock);
  fs.writeFileSync(path.join(fixture, 'src-tauri/tauri.conf.json'), originalConfig);
  fs.writeFileSync(path.join(fixture, '.github/workflows/release.yml'), originalWorkflow);
});
afterAll(() => {
  const resolved = fs.realpathSync(fixture); const relative = path.relative(fs.realpathSync(os.tmpdir()), resolved);
  if (!relative.startsWith('..') && !path.isAbsolute(relative) && path.basename(resolved).startsWith('vkarmani-updater-policy-')) fs.rmSync(resolved, { recursive: true });
});
function check() {
  const env = { ...process.env }; delete env.REQUIRE_UPDATER_SIGNING_KEY;
  return spawnSync(process.execPath, [path.join(source, 'scripts/verify-updater-config.mjs')], { cwd: fixture, env, encoding: 'utf8', timeout: 15000 });
}
describe('real updater dependency/security release guard', () => {
  it('accepts direct signed Windows artifacts with TLS and reviewed security pins', () => {
    const result = check(); expect(result.error).toBeUndefined(); expect(result.status).toBe(0);
    expect(result.stdout).toContain('direct signed EXE/MSI updater retains rustls-tls');
    expect(result.stdout).toContain('creates a draft');
  });
  it.each(['false', '${{ true }}'])('rejects automatic stable promotion or an unevaluated draft expression %s', value => {
    const workflow = originalWorkflow.replace('releaseDraft: true', `releaseDraft: ${value}`);
    expect(workflow).not.toBe(originalWorkflow);
    fs.writeFileSync(path.join(fixture, '.github/workflows/release.yml'), workflow);
    const result = check(); expect(result.status).toBe(1); expect(result.stderr).toContain('must build a draft first');
  });
  it('rejects an ambiguous duplicate draft setting', () => {
    fs.writeFileSync(path.join(fixture, '.github/workflows/release.yml'), originalWorkflow + '\n          releaseDraft: false\n');
    const result = check(); expect(result.status).toBe(1); expect(result.stderr).toContain('must build a draft first');
  });
  it.each([
    ['default feature reactivation', (text: string) => text.replace('default-features = false, features = ["rustls-tls"]', 'default-features = true, features = ["rustls-tls"]')],
    ['explicit zip reactivation', (text: string) => text.replace('features = ["rustls-tls"]', 'features = ["rustls-tls", "zip"]')],
    ['TLS removal', (text: string) => text.replace('features = ["rustls-tls"]', 'features = []')]
  ])('rejects %s', (_name, mutate) => {
    const changed = mutate(originalCargo); expect(changed).not.toBe(originalCargo); fs.writeFileSync(path.join(fixture, 'src-tauri/Cargo.toml'), changed);
    const result = check(); expect(result.status).toBe(1); expect(result.stderr).toContain('legacy archive support is forbidden');
  });
  it('rejects archive publication mode and a reintroduced ZIP lock entry', () => {
    const config = JSON.parse(originalConfig); config.bundle.createUpdaterArtifacts = 'v1Compatible'; fs.writeFileSync(path.join(fixture, 'src-tauri/tauri.conf.json'), JSON.stringify(config));
    const archiveMode = check(); expect(archiveMode.status).toBe(1); expect(archiveMode.stderr).toContain('createUpdaterArtifacts must be true');
    fs.writeFileSync(path.join(fixture, 'src-tauri/tauri.conf.json'), originalConfig);
    fs.writeFileSync(path.join(fixture, 'src-tauri/Cargo.lock'), originalLock + '\n[[package]]\nname = "zip"\nversion = "4.6.1"\n');
    const archiveLock = check(); expect(archiveLock.status).toBe(1); expect(archiveLock.stderr).toContain('must not include the legacy ZIP updater extractor');
  });
  it.each([['quinn-proto', '0.11.18', '0.11.14'], ['webpki-root-certs', '1.0.10', '1.0.6'], ['plist', '1.10.0', '1.8.0'], ['quick-xml', '0.41.0', '0.38.4']])('rejects %s downgrade', (name, patched, vulnerable) => {
    const old = `name = "${name}"\nversion = "${patched}"`;
    const changed = originalLock.replace(old, `name = "${name}"\nversion = "${vulnerable}"`); expect(changed).not.toBe(originalLock);
    fs.writeFileSync(path.join(fixture, 'src-tauri/Cargo.lock'), changed);
    const result = check(); expect(result.status).toBe(1); expect(result.stderr).toContain('must retain accepted patched dependencies');
  });
});
