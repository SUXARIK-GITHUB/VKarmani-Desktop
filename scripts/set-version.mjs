#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

const version = process.argv[2]?.trim();
if (!version || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) {
  console.error('Usage: node scripts/set-version.mjs <semver>');
  console.error('Example: node scripts/set-version.mjs 0.13.22');
  process.exit(1);
}

const root = process.cwd();
const readJson = (file) => JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));
const writeJson = (file, value) => {
  fs.writeFileSync(path.join(root, file), `${JSON.stringify(value, null, 2)}\n`);
  console.log(`[version] ${file} -> ${version}`);
};

const packageJson = readJson('package.json');
packageJson.version = version;
writeJson('package.json', packageJson);

const packageLockPath = path.join(root, 'package-lock.json');
if (fs.existsSync(packageLockPath)) {
  const packageLock = JSON.parse(fs.readFileSync(packageLockPath, 'utf8'));
  packageLock.version = version;
  if (packageLock.packages?.['']) {
    packageLock.packages[''].version = version;
  }
  fs.writeFileSync(packageLockPath, `${JSON.stringify(packageLock, null, 2)}\n`);
  console.log(`[version] package-lock.json -> ${version}`);
}

const tauriConfPath = path.join(root, 'src-tauri', 'tauri.conf.json');
const tauriConf = JSON.parse(fs.readFileSync(tauriConfPath, 'utf8'));
tauriConf.version = version;
fs.writeFileSync(tauriConfPath, `${JSON.stringify(tauriConf, null, 2)}\n`);
console.log(`[version] src-tauri/tauri.conf.json -> ${version}`);

const cargoTomlPath = path.join(root, 'src-tauri', 'Cargo.toml');
let cargoToml = fs.readFileSync(cargoTomlPath, 'utf8');
cargoToml = cargoToml.replace(/^(version\s*=\s*)"[^"]+"/m, `$1"${version}"`);
fs.writeFileSync(cargoTomlPath, cargoToml);
console.log(`[version] src-tauri/Cargo.toml -> ${version}`);

const cargoLockPath = path.join(root, 'src-tauri', 'Cargo.lock');
if (fs.existsSync(cargoLockPath)) {
  let cargoLock = fs.readFileSync(cargoLockPath, 'utf8');
  cargoLock = cargoLock.replace(
    /(name = "vkarmani-desktop"\nversion = ")[^"]+(")/,
    `$1${version}$2`,
  );
  fs.writeFileSync(cargoLockPath, cargoLock);
  console.log(`[version] src-tauri/Cargo.lock -> ${version}`);
}
