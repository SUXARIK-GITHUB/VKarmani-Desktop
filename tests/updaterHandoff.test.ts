import { beforeEach, describe, expect, it, vi } from 'vitest';
import { canAutoInstallUpdate } from '../src/utils/updateSafety';
const check = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/plugin-updater', () => ({ check }));
vi.mock('../src/services/runtime', () => ({ isTauriRuntime: true, appVersion: '0.13.76' }));
beforeEach(() => { vi.resetModules(); check.mockReset(); });
describe('signed updater handoff order', () => {
  it('downloads and verifies before state seal/owned disconnect, then installs and closes its resource', async () => {
    const order: string[] = [];
    const update = { download: vi.fn(async () => { order.push('verified-download'); }), install: vi.fn(async () => { order.push('install'); }), close: vi.fn(async () => { order.push('close'); }) };
    check.mockResolvedValue(update); const service = await import('../src/services/updater');
    expect(await service.installAvailableUpdate(vi.fn(), async () => { order.push('state-seal-and-owned-cleanup'); })).toEqual({ ok: true });
    expect(order).toEqual(['verified-download', 'state-seal-and-owned-cleanup', 'install', 'close']);
  });
  it('does not disconnect or install when download/signature verification fails', async () => {
    const update = { download: vi.fn().mockRejectedValue(new Error('signature invalid')), install: vi.fn(), close: vi.fn().mockResolvedValue(undefined) };
    check.mockResolvedValue(update); const before = vi.fn(); const service = await import('../src/services/updater');
    expect((await service.installAvailableUpdate(vi.fn(), before)).ok).toBe(false);
    expect(before).not.toHaveBeenCalled(); expect(update.install).not.toHaveBeenCalled(); expect(update.close).toHaveBeenCalledOnce();
  });
  it('does not install when flush/seal/owned cleanup is unconfirmed', async () => {
    const update = { download: vi.fn().mockResolvedValue(undefined), install: vi.fn(), close: vi.fn().mockResolvedValue(undefined) };
    check.mockResolvedValue(update); const service = await import('../src/services/updater');
    expect((await service.installAvailableUpdate(vi.fn(), async () => { throw new Error('cleanup unconfirmed'); })).ok).toBe(false);
    expect(update.install).not.toHaveBeenCalled(); expect(update.close).toHaveBeenCalledOnce();
  });
  it('returns install failure and still releases the downloaded update resource', async () => {
    const update = { download: vi.fn().mockResolvedValue(undefined), install: vi.fn().mockRejectedValue(new Error('installer failed')), close: vi.fn().mockResolvedValue(undefined) };
    check.mockResolvedValue(update); const service = await import('../src/services/updater');
    expect((await service.installAvailableUpdate(vi.fn(), async () => undefined)).ok).toBe(false); expect(update.close).toHaveBeenCalledOnce();
  });
  it('does not begin handoff if a second update check finds no release', async () => {
    check.mockResolvedValue(null); const before = vi.fn(); const service = await import('../src/services/updater');
    expect((await service.installAvailableUpdate(vi.fn(), before)).ok).toBe(false); expect(before).not.toHaveBeenCalled();
  });
  it('defers automatic installation if a VPN appears during the verified download', async () => {
    let active = false;
    const update = { download: vi.fn(async () => { active = true; }), install: vi.fn(), close: vi.fn().mockResolvedValue(undefined) };
    check.mockResolvedValue(update); const sealAndDisconnect = vi.fn(); const service = await import('../src/services/updater');
    const result = await service.installAvailableUpdate(vi.fn(), async () => {
      if (!canAutoInstallUpdate({bridge:'tauri',coreInstalled:true,tunnelActive:active,systemProxyEnabled:false,proxyOwnership:'none',routeOwnership:'none',message:'fixture'},'idle')) throw new Error('Manual confirmation required');
      await sealAndDisconnect();
    });
    expect(result.ok).toBe(false); expect(sealAndDisconnect).not.toHaveBeenCalled(); expect(update.install).not.toHaveBeenCalled(); expect(update.close).toHaveBeenCalledOnce();
  });
});
