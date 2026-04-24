import fs from 'node:fs';
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

if (!pkg.version) fail('package.json version is missing');
if (!tauri.version) fail('src-tauri/tauri.conf.json version is missing');
if (!cargoVersion) fail('src-tauri/Cargo.toml version is missing');

if (pkg.version && tauri.version && cargoVersion && pkg.version === tauri.version && pkg.version === cargoVersion) {
  ok(`versions are synchronized: ${pkg.version}`);
} else {
  fail(`versions must match: package=${pkg.version}, tauri=${tauri.version}, cargo=${cargoVersion}`);
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
