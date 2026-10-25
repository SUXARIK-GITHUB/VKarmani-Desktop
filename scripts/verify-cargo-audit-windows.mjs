import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const target = 'x86_64-pc-windows-msvc';
// Exact, reviewed lock entries only. Becoming reachable or changing version
// removes the exception automatically; every other vulnerability blocks.
export const inactiveAdvisories = Object.freeze({
  'RUSTSEC-2026-0194': { package: 'quick-xml', version: '0.38.4', reason: 'tauri -> plist is cfg(target_os="macos"); duplicate-attribute parsing is absent on Windows' },
  'RUSTSEC-2026-0195': { package: 'quick-xml', version: '0.38.4', reason: 'tauri -> plist is cfg(target_os="macos"); namespace parsing is absent on Windows' },
  'RUSTSEC-2026-0185': { package: 'quinn-proto', version: '0.11.14', reason: 'reqwest http3/h3-quinn/quinn optional feature is disabled; QUIC stream path is absent' },
});
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
function requireValid(condition, message) { if (!condition) throw new Error(message); }

export function assessWindowsAudit(audit, metadata, tree) {
  requireValid(audit?.settings && Array.isArray(audit.settings.ignore) && audit.settings.ignore.length === 0, 'Audit ignores are forbidden');
  requireValid(audit.settings.severity == null && audit.settings.target_os?.length === 0 && audit.settings.target_arch?.length === 0, 'Use the complete unfiltered audit');
  const vulnerabilities = audit.vulnerabilities;
  requireValid(Array.isArray(vulnerabilities?.list) && vulnerabilities.count === vulnerabilities.list.length
    && vulnerabilities.found === (vulnerabilities.count > 0), 'Incomplete audit report');
  requireValid(Array.isArray(metadata?.packages) && typeof metadata.resolve?.root === 'string', 'Missing metadata root/packages');
  const root = metadata.packages.find(pkg => pkg.id === metadata.resolve.root);
  requireValid(root?.name === 'vkarmani-desktop' && typeof root.version === 'string', 'Unexpected production root');
  const packages = new Set(metadata.packages.map(pkg => `${pkg.name}@${pkg.version}`));
  const active = new Set();
  const rows = tree.trim().split(/\r?\n/);
  for (const row of rows) {
    const match = /^([A-Za-z0-9_-]+) v([^\s]+)(?: \(.*\))?(?: \(\*\))?$/.exec(row);
    requireValid(match, 'Unrecognized cargo tree output');
    const key = `${match[1]}@${match[2]}`;
    requireValid(packages.has(key), 'Tree entry missing from locked metadata');
    active.add(key);
  }
  requireValid(rows[0].startsWith(`${root.name} v${root.version} `) && active.size > 1, 'Incomplete production tree');
  const blocked = [], handled = [];
  for (const finding of vulnerabilities.list) {
    requireValid(typeof finding.advisory?.id === 'string' && typeof finding.package?.name === 'string'
      && typeof finding.package.version === 'string', 'Malformed vulnerability');
    const id = finding.advisory.id;
    const pkg = finding.package;
    const reachable = active.has(`${pkg.name}@${pkg.version}`);
    const reviewed = inactiveAdvisories[id];
    if (!reachable && reviewed?.package === pkg.name && reviewed.version === pkg.version) {
      handled.push({ id, package: pkg.name, version: pkg.version, target, reason: reviewed.reason,
        targetEvidence: 'Absent from locked Windows cargo tree including normal/build/dev and tauri/custom-protocol',
        reviewCondition: 'Re-review any manifest, feature, target, CI build arguments or advisory/package version change; reachable entry always blocks' });
    } else {
      blocked.push({ id, package: pkg.name, version: pkg.version, reachable,
        reason: reachable ? 'Windows-reachable vulnerability' : 'No exact reviewed inactive-target assessment' });
    }
  }
  return { status: blocked.length ? 'FAIL' : 'PASS', target, activePackages: active.size, handled, blocked,
    warnings: audit.warnings, treeSha256: hash(tree), metadataSha256: hash(JSON.stringify(metadata)),
    limitation: 'Tree is feature-aware evidence, not exact compilation proof; fresh artifact build/fingerprints independently verify absence' };
}

function run(command, args, allowed = [0]) {
  const result = spawnSync(command, args, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, shell: false });
  requireValid(!result.error && allowed.includes(result.status), `${command} failed (${result.status ?? 'unavailable'})`);
  if (result.stderr) process.stderr.write(result.stderr);
  return result;
}
export function main() {
  const host = run('rustc', ['-vV']).stdout;
  requireValid(process.platform === 'win32' && host.includes(`host: ${target}`), 'Audit gate requires the Windows production host');
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const manifest = path.join(root, 'src-tauri', 'Cargo.toml');
  const lock = path.join(root, 'src-tauri', 'Cargo.lock');
  const configuration = JSON.parse(fs.readFileSync(path.join(root, 'src-tauri', 'tauri.conf.json'), 'utf8'));
  const extraFeatures = configuration.build?.features ?? [];
  requireValid(Array.isArray(extraFeatures) && extraFeatures.every(feature => typeof feature === 'string'), 'Invalid build features');
  const features = [...new Set(['tauri/custom-protocol', ...extraFeatures])].join(',');
  const auditResult = run('cargo', ['audit', '--file', lock, '--json'], [0, 1]);
  const audit = JSON.parse(auditResult.stdout);
  requireValid(auditResult.status === (audit.vulnerabilities?.count > 0 ? 1 : 0), 'Unexpected scanner exit/report combination');
  const argumentsBase = ['--locked', '--manifest-path', manifest, '--features', features];
  const metadata = JSON.parse(run('cargo', ['metadata', ...argumentsBase, '--format-version', '1', '--filter-platform', target]).stdout);
  // cargo metadata includes weak optional dependencies on Cargo 1.94 (quinn).
  // Never use its packages/resolve list alone as the active compilation graph.
  // rust-toolchain sets CARGO_TERM_COLOR=always on hosted runners. Machine
  // output must explicitly disable ANSI styling; the strict parser stays intact.
  const tree = run('cargo', ['tree', '--color', 'never', ...argumentsBase, '--target', target, '--edges', 'normal,build,dev', '--prefix', 'none', '--format', '{p}']).stdout;
  const report = { ...assessWindowsAudit(audit, metadata, tree), features, lockSha256: hash(fs.readFileSync(lock)), audit };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (report.status !== 'PASS') process.exitCode = 1;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(); } catch (error) { console.error(`[windows-audit] ${error.message}`); process.exitCode = 1; }
}
