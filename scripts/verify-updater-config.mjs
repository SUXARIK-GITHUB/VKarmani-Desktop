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


const forbiddenRegistryPatterns = [
  /packages\.applied-caas-gateway/i,
  /internal\.api\.openai\.org/i,
  /artifactory\/api\/npm\/npm-public/i,
];

for (const file of ['package-lock.json', '.npmrc', '.github/workflows/release.yml']) {
  const filePath = path.join(root, file);
  if (!fs.existsSync(filePath)) continue;
  const content = fs.readFileSync(filePath, 'utf8');
  if (forbiddenRegistryPatterns.some((pattern) => pattern.test(content))) {
    fail(`${file} contains an internal/private npm registry URL. Use https://registry.npmjs.org/ for GitHub Actions.`);
  } else {
    ok(`${file} does not contain internal npm registry URLs`);
  }
}

const npmrcPath = path.join(root, '.npmrc');
if (!fs.existsSync(npmrcPath)) {
  fail('.npmrc is missing; keep it committed so GitHub Actions uses the public npm registry consistently');
} else {
  const npmrc = fs.readFileSync(npmrcPath, 'utf8');
  if (!/^registry=https:\/\/registry\.npmjs\.org\/?$/m.test(npmrc)) {
    fail('.npmrc must set registry=https://registry.npmjs.org/');
  } else {
    ok('.npmrc forces public npm registry');
  }
}

const gitattributesPath = path.join(root, '.gitattributes');
if (!fs.existsSync(gitattributesPath)) {
  fail('.gitattributes is missing; binary runtime assets must be marked as binary');
} else {
  const gitattributes = fs.readFileSync(gitattributesPath, 'utf8');
  for (const pattern of ['*.exe binary', '*.dll binary', '*.dat binary']) {
    if (!gitattributes.includes(pattern)) {
      fail(`.gitattributes must contain "${pattern}" to prevent binary corruption`);
    } else {
      ok(`.gitattributes protects ${pattern}`);
    }
  }
  if (/filter\s*=\s*lfs/i.test(gitattributes)) {
    fail('.gitattributes must not enable Git LFS automatically for xray.exe; accidental LFS pointers break installed runtime');
  } else {
    ok('.gitattributes does not force Git LFS for runtime binaries');
  }
}

const scriptsDir = path.join(root, 'scripts');
if (fs.existsSync(scriptsDir)) {
  for (const scriptName of fs.readdirSync(scriptsDir).filter((name) => name.endsWith('.ps1')).sort()) {
    const scriptPath = path.join(scriptsDir, scriptName);
    const script = fs.readFileSync(scriptPath, 'utf8');
    const ambiguousRefs = [...script.matchAll(/\$(?!env:|Env:|script:|Script:|global:|Global:|local:|Local:|private:|Private:|using:|Using:)([A-Za-z_][A-Za-z0-9_]*):/g)];
    if (ambiguousRefs.length > 0) {
      const refs = ambiguousRefs.map((match) => match[0]).join(', ');
      fail(`${scriptName} contains ambiguous PowerShell variable reference before colon: ${refs}. Use braced variables before ':' to avoid parser errors.`);
    } else {
      ok(`${scriptName} has no ambiguous PowerShell variable references before colon`);
    }
  }
}

const pkg = readJson('package.json');
const tauri = readJson('src-tauri/tauri.conf.json');
const cargo = fs.readFileSync(path.join(root, 'src-tauri/Cargo.toml'), 'utf8');
const cargoVersion = cargo.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
const cargoLockPath = path.join(root, 'src-tauri/Cargo.lock');
const cargoLock = fs.existsSync(cargoLockPath) ? fs.readFileSync(cargoLockPath, 'utf8') : '';
const cargoLockVersion = (() => {
  const block = cargoLock.match(/\[\[package\]\]\r?\nname\s*=\s*"vkarmani-desktop"\r?\nversion\s*=\s*"([^"]+)"/m);
  return block?.[1];
})();

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



const assertWindowsPeBinary = (filePath, file) => {
  const buffer = fs.readFileSync(filePath);
  if (buffer.length < 64) {
    fail(`${file} is too small to contain a valid PE header`);
    return buffer;
  }

  if (buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
    if (buffer[0] === 0x00 && buffer[1] === 0x00 && buffer[2] === 0x00 && buffer[3] === 0x00 && buffer[4] === 0x4d && buffer[5] === 0x5a) {
      fail(`${file} is corrupted: it has 4 extra null bytes before the MZ header`);
    } else {
      fail(`${file} is corrupted: missing MZ header, first bytes are ${buffer[0]?.toString(16)} ${buffer[1]?.toString(16)}`);
    }
    return buffer;
  }
  ok(`PE MZ header verified: ${file}`);

  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset < 64 || peOffset + 4 > buffer.length || peOffset > 8192) {
    fail(`${file} is corrupted: invalid PE header offset ${peOffset}`);
    return buffer;
  }

  if (buffer[peOffset] !== 0x50 || buffer[peOffset + 1] !== 0x45 || buffer[peOffset + 2] !== 0x00 || buffer[peOffset + 3] !== 0x00) {
    fail(`${file} is corrupted: missing PE signature at offset ${peOffset}`);
  } else {
    ok(`PE signature verified: ${file}`);
  }

  const machine = buffer.readUInt16LE(peOffset + 4);
  if (machine !== 0x8664) {
    fail(`${file} must be Windows x64/AMD64, got machine=0x${machine.toString(16)}`);
  } else {
    ok(`PE machine x64 verified: ${file}`);
  }

  const optionalHeaderMagic = buffer.readUInt16LE(peOffset + 24);
  if (optionalHeaderMagic !== 0x20b) {
    fail(`${file} must be PE32+ x64, got optional header=0x${optionalHeaderMagic.toString(16)}`);
  } else {
    ok(`PE32+ header verified: ${file}`);
  }

  if (buffer.subarray(0, 32).toString('utf8').startsWith('version https://git-lfs')) {
    fail(`${file} is a Git LFS pointer instead of a real binary`);
  }

  return buffer;
};

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

  const fileBuffer = ['xray.exe', 'wintun.dll'].includes(file)
    ? assertWindowsPeBinary(filePath, file)
    : fs.readFileSync(filePath);

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
    const actualHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
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
  if (!/runs-on:\s*windows-2022/.test(workflow)) {
    fail('release workflow must use windows-2022 for a deterministic x64 Windows runner');
  } else {
    ok('release workflow uses windows-2022 x64 runner');
  }
  if (!/Validate PowerShell scripts/.test(workflow)) {
    fail('release workflow must validate PowerShell scripts before running fetch-xray-windows.ps1');
  } else {
    ok('release workflow validates PowerShell script syntax before fetch');
  }
  if (!/fetch-xray-windows\.ps1/.test(workflow)) {
    fail('release workflow must run scripts/fetch-xray-windows.ps1 before verify/build so CI bundles an official launch-tested Xray binary');
  } else {
    ok('release workflow fetches official Xray Windows x64 runtime before build');
  }
  if (!/lfs:\s*true/.test(workflow)) {
    fail('release workflow checkout must set lfs: true so binary assets are real files if the repository uses Git LFS');
  } else {
    ok('release workflow checkout uses lfs: true');
  }
  if (!/verify-xray-windows\.ps1/.test(workflow)) {
    fail('release workflow must run scripts/verify-xray-windows.ps1 before building installer');
  } else {
    ok('release workflow verifies xray.exe on Windows before build');
  }
  if (!/Refresh patched Rust transitive dependencies/.test(workflow) || !/rustls-webpki\s+--precise\s+0\.103\.13/.test(workflow) || !/tar\s+--precise\s+0\.4\.45/.test(workflow)) {
    fail('release workflow must refresh patched Rust transitive dependencies before cargo audit: rustls-webpki 0.103.13 and tar 0.4.45');
  } else {
    ok('release workflow refreshes patched Rust transitive dependencies before audit');
  }
  if (/cargo\s+audit\s+--deny\s+warnings/.test(workflow)) {
    fail('release workflow must not use cargo audit --deny warnings because Tauri transitive GTK/WebKit warnings block Windows releases');
  } else if (!/cargo\s+audit(\s|$)/.test(workflow)) {
    fail('release workflow must run cargo audit');
  } else {
    ok('release workflow runs cargo audit without denying transitive warnings');
  }
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

process.exit(process.exitCode ?? 0);
