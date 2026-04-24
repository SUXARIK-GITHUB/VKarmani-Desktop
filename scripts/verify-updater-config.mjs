import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';

const root = process.cwd();
const readJson = (file) => JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));
const fail = (message) => {
  console.error(`[updater-check] ERROR: ${message}`);
  process.exitCode = 1;
};
const ok = (message) => console.log(`[updater-check] OK: ${message}`);

const pkg = readJson('package.json');
const tauri = readJson('src-tauri/tauri.conf.json');
const cargo = fs.readFileSync(path.join(root, 'src-tauri/Cargo.toml'), 'utf8');
const cargoVersion = cargo.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
const cargoLockPath = path.join(root, 'src-tauri/Cargo.lock');
const cargoLock = fs.existsSync(cargoLockPath) ? fs.readFileSync(cargoLockPath, 'utf8') : '';
const cargoLockVersion = cargoLock.match(/name = "vkarmani-desktop"\nversion = "([^"]+)"/m)?.[1];

if (!pkg.version) fail('package.json version is missing');
if (!tauri.version) fail('src-tauri/tauri.conf.json version is missing');
if (!cargoVersion) fail('src-tauri/Cargo.toml version is missing');
if (!cargoLockVersion) fail('src-tauri/Cargo.lock vkarmani-desktop version is missing');

if (pkg.version && tauri.version && cargoVersion && cargoLockVersion && pkg.version === tauri.version && pkg.version === cargoVersion && pkg.version === cargoLockVersion) {
  ok(`versions are synchronized: ${pkg.version}`);
} else {
  fail(`versions must match: package=${pkg.version}, tauri=${tauri.version}, cargo=${cargoVersion}, cargoLock=${cargoLockVersion}`);
}

const updater = tauri.plugins?.updater;
if (!updater) fail('plugins.updater is missing in tauri.conf.json');
if (!updater?.pubkey || updater.pubkey.length < 50) fail('plugins.updater.pubkey is missing or too short');
else ok('updater pubkey exists');

const endpoints = updater?.endpoints ?? [];
if (!Array.isArray(endpoints) || endpoints.length === 0) fail('plugins.updater.endpoints must contain latest.json URL');
else ok(`updater endpoint: ${endpoints.join(', ')}`);

if (!endpoints.some((endpoint) => String(endpoint).includes('/releases/latest/download/latest.json'))) {
  fail('endpoint should point to GitHub Releases latest.json download URL');
}

if (tauri.bundle?.createUpdaterArtifacts !== true) {
  fail('bundle.createUpdaterArtifacts must be true');
} else {
  ok('createUpdaterArtifacts is enabled');
}


const coreFiles = ['xray.exe', 'geoip.dat', 'geosite.dat', 'wintun.dll'];
const resources = tauri.bundle?.resources;

if (!resources || Array.isArray(resources)) {
  fail('bundle.resources must be a source-to-target map so Xray files are placed into $RESOURCE/core/windows/');
} else {
  ok('bundle.resources uses explicit source-to-target mapping');

  for (const file of coreFiles) {
    const source = `../resources/core/windows/${file}`;
    const target = `core/windows/${file}`;
    if (resources[source] !== target) {
      fail(`bundle.resources must map ${source} -> ${target}`);
    } else {
      ok(`resource mapping exists: ${target}`);
    }
  }

  const manifestTarget = resources['../resources/core/windows/core-manifest.json'];
  if (manifestTarget !== 'core/windows/core-manifest.json') {
    fail('bundle.resources must include core-manifest.json -> core/windows/core-manifest.json');
  } else {
    ok('resource mapping exists: core/windows/core-manifest.json');
  }
}

const manifestPath = path.join(root, 'resources/core/windows/core-manifest.json');
let manifest = null;
if (!fs.existsSync(manifestPath)) {
  fail('resources/core/windows/core-manifest.json is missing');
} else {
  manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  ok('core manifest exists');

  if (manifest.version && manifest.version !== pkg.version) {
    fail(`core manifest version must match package version: manifest=${manifest.version}, package=${pkg.version}`);
  } else if (manifest.version) {
    ok(`core manifest version matches package version: ${manifest.version}`);
  }
}

for (const file of coreFiles) {
  const filePath = path.join(root, 'resources/core/windows', file);
  if (!fs.existsSync(filePath)) {
    fail(`required bundled core file is missing: resources/core/windows/${file}`);
    continue;
  }

  const stat = fs.statSync(filePath);
  if (!stat.isFile() || stat.size <= 0) {
    fail(`required bundled core file is empty or invalid: resources/core/windows/${file}`);
    continue;
  }

  if (file === 'xray.exe' && stat.size < 1_000_000) {
    fail('resources/core/windows/xray.exe is suspiciously small and is probably corrupted');
    continue;
  }

  const expected = manifest?.files?.find?.((entry) => entry.file === file);
  if (!expected) {
    fail(`core manifest does not include ${file}`);
    continue;
  }

  if (expected.size !== stat.size) {
    fail(`core manifest size mismatch for ${file}: manifest=${expected.size}, actual=${stat.size}`);
  } else {
    ok(`core file size verified: ${file}`);
  }

  if (expected.sha256) {
    const actualHash = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
    if (expected.sha256 !== actualHash) {
      fail(`core manifest sha256 mismatch for ${file}: manifest=${expected.sha256}, actual=${actualHash}`);
    } else {
      ok(`core file sha256 verified: ${file}`);
    }
  }
}

const workflowPath = path.join(root, '.github/workflows/release.yml');
if (!fs.existsSync(workflowPath)) {
  fail('.github/workflows/release.yml is missing');
} else {
  ok('GitHub Actions release workflow exists');
  const workflow = fs.readFileSync(workflowPath, 'utf8');
  if (!/tauri-apps\/tauri-action@v0(\.\d+\.\d+)?/.test(workflow)) {
    fail('release workflow must use available tauri-apps/tauri-action@v0 or @v0.x.x');
  } else {
    ok('release workflow uses tauri-action v0');
  }
  if (!/includeUpdaterJson:\s*true/.test(workflow)) {
    fail('release workflow must set includeUpdaterJson: true');
  } else {
    ok('release workflow includes latest.json');
  }
  if (!/releaseDraft:\s*false/.test(workflow)) {
    fail('release workflow must publish a non-draft release, otherwise /releases/latest/download/latest.json can return 404');
  } else {
    ok('release workflow publishes non-draft releases');
  }
}

if (!process.env.TAURI_SIGNING_PRIVATE_KEY && process.env.GITHUB_ACTIONS) {
  fail('GitHub secret TAURI_SIGNING_PRIVATE_KEY is missing');
} else if (process.env.GITHUB_ACTIONS) {
  ok('TAURI_SIGNING_PRIVATE_KEY is available in GitHub Actions');
} else {
  console.log('[updater-check] INFO: local run: TAURI_SIGNING_PRIVATE_KEY is not required unless you build release artifacts locally.');
}

if (process.exitCode) {
  process.exit(process.exitCode);
}
