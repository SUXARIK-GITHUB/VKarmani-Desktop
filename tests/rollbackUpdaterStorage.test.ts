import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { NativeStateFake } from './helpers/nativeStateFake';
const mocks = vi.hoisted(() => ({ invoke: vi.fn(), check: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: mocks.invoke }));
vi.mock('@tauri-apps/plugin-updater', () => ({ check: mocks.check }));
vi.mock('../src/services/runtime', () => ({ isTauriRuntime: true, appVersion: '0.13.76' }));
let backend: NativeStateFake;
beforeEach(() => {
  vi.resetModules(); mocks.invoke.mockReset(); mocks.check.mockReset(); backend = new NativeStateFake();
  mocks.invoke.mockImplementation((command, args) => backend.invoke(command, args));
  vi.stubGlobal('window', { __TAURI_INTERNALS__: {}, localStorage: {getItem: () => null, setItem: vi.fn(), removeItem: vi.fn()}, setTimeout, clearTimeout });
  vi.stubGlobal('document', { body: { inert: false } });
});
afterEach(() => vi.unstubAllGlobals());
it('keeps settings durable during a slow update download that fails', async () => {
  let rejectDownload!: (error: Error) => void;
  const install = vi.fn();
  mocks.check.mockResolvedValue({ download: vi.fn(() => new Promise((_, reject) => { rejectDownload = reject; })), install });
  const storage = await import('../src/services/storage'); await storage.loadPersistentSnapshot();
  const updater = await import('../src/services/updater'); const result = updater.installAvailableUpdate(vi.fn());
  await vi.waitFor(() => expect(rejectDownload).toBeTypeOf('function'));
  expect(document.body.inert).toBe(false);
  storage.saveSettings({...storage.defaultSettings, language:'en'}); await storage.flushPersistentWrites();
  expect(backend.snapshot.payload.public.settings).toMatchObject({language:'en'});
  rejectDownload(new Error('synthetic download failure'));
  expect(await result).toMatchObject({ok:false}); expect(install).not.toHaveBeenCalled();
  expect(document.body.inert).toBe(false);
  storage.saveSelectedServerId('after-failure'); await storage.flushPersistentWrites();
  expect(backend.snapshot.payload.public.selectedServerId).toBe('after-failure');
});
it('drains saved edits and blocks input only for final install, restores input on installer failure', async () => {
  let release!: () => void;
  const storage = await import('../src/services/storage'); await storage.loadPersistentSnapshot();
  const install = vi.fn(async () => {
    expect(document.body.inert).toBe(true);
    expect(backend.snapshot.payload.public.settings).toMatchObject({language:'en'});
    throw new Error('synthetic install failure');
  });
  mocks.check.mockResolvedValue({ download: vi.fn(() => new Promise<void>(resolve => { release = resolve; })), install });
  const updater = await import('../src/services/updater'); const result = updater.installAvailableUpdate(vi.fn());
  await vi.waitFor(() => expect(release).toBeTypeOf('function'));
  storage.saveSettings({...storage.defaultSettings,language:'en'}); release();
  expect(await result).toMatchObject({ok:false}); expect(install).toHaveBeenCalledTimes(1);
  expect(document.body.inert).toBe(false);
  storage.saveSelectedServerId('resumed'); await storage.flushPersistentWrites();
  expect(backend.snapshot.payload.public.selectedServerId).toBe('resumed');
});
