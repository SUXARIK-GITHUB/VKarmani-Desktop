import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { expect, it } from 'vitest';

it('synchronizes release versions without changing dependency or resource identities and is idempotent', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'vkarmani-release-version-'));
  const files = ['package.json', 'package-lock.json', 'src-tauri/Cargo.toml',
    'src-tauri/Cargo.lock', 'src-tauri/tauri.conf.json', 'resources/core/windows/core-manifest.json'];
  const before = new Map(files.map(name => [name, readFileSync(path.resolve(name), 'utf8')]));
  try {
    for (const [name, content] of before) {
      mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
      writeFileSync(path.join(root, name), content);
    }
    const script = path.resolve('scripts/set-version.mjs');
    const run = () => execFileSync(process.execPath, [script, '0.99.123'], { cwd: root });
    const json = (name: string) => JSON.parse(readFileSync(path.join(root, name), 'utf8').replace(/^\uFEFF/, ''));
    run();
    expect(json('package.json').version).toBe('0.99.123');
    expect(json('package-lock.json').version).toBe('0.99.123');
    expect(json('package-lock.json').packages[''].version).toBe('0.99.123');
    expect(json('src-tauri/tauri.conf.json').version).toBe('0.99.123');
    const oldCore = JSON.parse(before.get(files[5])!.replace(/^\uFEFF/, ''));
    expect(json(files[5])).toEqual({ ...oldCore, version: '0.99.123' });
    const oldLock = JSON.parse(before.get(files[1])!);
    for (const [name, entry] of Object.entries(oldLock.packages)) {
      if (name !== '') expect(json(files[1]).packages[name]).toEqual(entry);
    }
    expect(readFileSync(path.join(root, files[2]), 'utf8'))
      .toBe(before.get(files[2])!.replace(/^version\s*=\s*"[^"]+"/m, 'version = "0.99.123"'));
    expect(readFileSync(path.join(root, files[3]), 'utf8'))
      .toBe(before.get(files[3])!.replace(/(\[\[package\]\]\r?\nname = "vkarmani-desktop"\r?\nversion = ")[^"]+/, '$10.99.123'));
    const first = files.map(name => readFileSync(path.join(root, name)));
    run();
    files.forEach((name, index) => expect(readFileSync(path.join(root, name))).toEqual(first[index]));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
