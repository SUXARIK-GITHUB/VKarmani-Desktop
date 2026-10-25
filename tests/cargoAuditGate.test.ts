import { describe, expect, it } from 'vitest';
import { assessWindowsAudit } from '../scripts/verify-cargo-audit-windows.mjs';

const vuln = (id = 'RUSTSEC-2026-0194', name = 'quick-xml', version = '0.38.4') => ({ advisory: { id }, package: { name, version } });
const metadata = { packages: [{ id: 'root', name: 'vkarmani-desktop', version: '0.13.70' },
  { id: 'dep', name: 'serde', version: '1.0.228' }, { id: 'xml', name: 'quick-xml', version: '0.38.4' }], resolve: { root: 'root' } };
const tree = 'vkarmani-desktop v0.13.70 (synthetic-root)\nserde v1.0.228\n';
const audit = (list = [vuln()]) => ({ settings: { ignore: [], severity: null, target_os: [], target_arch: [] },
  vulnerabilities: { found: list.length > 0, count: list.length, list }, warnings: { unsound: ['visible'] } });
describe('strict Windows release advisory gate', () => {
  it('handles only the three reviewed exact inactive lock entries and preserves warnings', () => {
    const result = assessWindowsAudit(audit([vuln(), vuln('RUSTSEC-2026-0195'), vuln('RUSTSEC-2026-0185', 'quinn-proto', '0.11.14')]), metadata, tree);
    expect(result.status).toBe('PASS'); expect(result.handled).toHaveLength(3);
    expect(result.warnings.unsound).toEqual(['visible']);
  });
  it('blocks a synthetic Windows-reachable High, including a formerly inactive advisory', () => {
    const result = assessWindowsAudit(audit(), metadata, tree + 'quick-xml v0.38.4\n');
    expect(result.status).toBe('FAIL'); expect(result.blocked[0].reachable).toBe(true);
    expect(assessWindowsAudit(audit([vuln('RUSTSEC-SYNTHETIC-HIGH', 'serde', '1.0.228')]), metadata, tree).status).toBe('FAIL');
  });
  it('does not silently accept a changed version or another inactive advisory', () => {
    expect(assessWindowsAudit(audit([vuln('RUSTSEC-2026-0194', 'quick-xml', '0.38.5')]), metadata, tree).status).toBe('FAIL');
    expect(assessWindowsAudit(audit([vuln('RUSTSEC-NEW-HIGH')]), metadata, tree).status).toBe('FAIL');
  });
  it('fails closed on missing/incomplete graphs, suppressed audit or scanner data', () => {
    expect(() => assessWindowsAudit(audit(), { ...metadata, resolve: {} }, tree)).toThrow();
    expect(() => assessWindowsAudit(audit(), metadata, tree + 'unrecognized output')).toThrow();
    expect(() => assessWindowsAudit(audit(), metadata, tree.split('\n')[0])).toThrow();
    const suppressed = audit(); suppressed.settings.ignore = ['RUSTSEC-2026-0194'];
    expect(() => assessWindowsAudit(suppressed, metadata, tree)).toThrow();
    const incomplete = audit(); incomplete.vulnerabilities.count = 0;
    expect(() => assessWindowsAudit(incomplete, metadata, tree)).toThrow();
  });
});
