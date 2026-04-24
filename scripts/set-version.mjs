import fs from 'node:fs';
import path from 'node:path';

const version = process.argv[2]?.trim();
if (!version || !/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) {
  console.error('Usage: npm run release:version -- 0.13.9');
  process.exit(1);
}

const root = process.cwd();
const jsonFiles = ['package.json', 'src-tauri/tauri.conf.json'];
for (const file of jsonFiles) {
  const full = path.join(root, file);
  const data = JSON.parse(fs.readFileSync(full, 'utf8'));
  data.version = version;
  fs.writeFileSync(full, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
  console.log(`[version] ${file} -> ${version}`);
}

const cargoPath = path.join(root, 'src-tauri/Cargo.toml');
const cargo = fs.readFileSync(cargoPath, 'utf8').replace(/^version\s*=\s*"[^"]+"/m, `version = "${version}"`);
fs.writeFileSync(cargoPath, cargo, 'utf8');
console.log(`[version] src-tauri/Cargo.toml -> ${version}`);
