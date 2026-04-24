import { readFileSync, existsSync } from 'node:fs';

function fail(message) {
  console.error(`Updater config error: ${message}`);
  process.exit(1);
}

const tauriConfigPath = 'src-tauri/tauri.conf.json';
const packageJsonPath = 'package.json';
const cargoTomlPath = 'src-tauri/Cargo.toml';
const workflowPath = '.github/workflows/release.yml';

if (!existsSync(tauriConfigPath)) fail(`${tauriConfigPath} not found`);
if (!existsSync(packageJsonPath)) fail(`${packageJsonPath} not found`);
if (!existsSync(cargoTomlPath)) fail(`${cargoTomlPath} not found`);
if (!existsSync(workflowPath)) fail(`${workflowPath} not found`);

const tauriConfig = JSON.parse(readFileSync(tauriConfigPath, 'utf8'));
const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
const cargoToml = readFileSync(cargoTomlPath, 'utf8');
const workflow = readFileSync(workflowPath, 'utf8');

const tauriVersion = tauriConfig.version;
const packageVersion = packageJson.version;
const cargoVersionMatch = cargoToml.match(/^version\s*=\s*"([^"]+)"/m);
const cargoVersion = cargoVersionMatch?.[1];

if (!tauriVersion) fail('src-tauri/tauri.conf.json version is empty');
if (tauriVersion !== packageVersion || tauriVersion !== cargoVersion) {
  fail(`versions mismatch: tauri=${tauriVersion}, package=${packageVersion}, cargo=${cargoVersion}`);
}

const updater = tauriConfig.plugins?.updater;
if (!updater) fail('plugins.updater is missing in tauri.conf.json');
if (!updater.pubkey || updater.pubkey.length < 40) fail('plugins.updater.pubkey is missing or too short');
if (!Array.isArray(updater.endpoints) || updater.endpoints.length === 0) fail('plugins.updater.endpoints is empty');

for (const endpoint of updater.endpoints) {
  if (typeof endpoint !== 'string') fail('updater endpoint must be a string');
  if (!endpoint.startsWith('https://github.com/')) fail(`updater endpoint must use GitHub HTTPS URL: ${endpoint}`);
  if (!endpoint.endsWith('/latest.json')) fail(`updater endpoint must point to latest.json: ${endpoint}`);
}

if (tauriConfig.bundle?.createUpdaterArtifacts !== true) {
  fail('bundle.createUpdaterArtifacts must be true so Tauri generates latest.json and .sig files');
}

if (!workflow.includes('tauri-apps/tauri-action@v0')) fail('release workflow must use tauri-apps/tauri-action@v0');
if (!workflow.includes('TAURI_SIGNING_PRIVATE_KEY')) fail('release workflow must pass TAURI_SIGNING_PRIVATE_KEY');
if (!workflow.includes('TAURI_SIGNING_PRIVATE_KEY_PASSWORD')) fail('release workflow must pass TAURI_SIGNING_PRIVATE_KEY_PASSWORD');

console.log(`Updater config OK for VKarmani Desktop ${tauriVersion}`);
