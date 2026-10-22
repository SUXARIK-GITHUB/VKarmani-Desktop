import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
const mocks = vi.hoisted(() => ({ invoke: vi.fn(), listen: vi.fn(), quiesce: vi.fn(), resume: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: mocks.invoke }));
vi.mock('@tauri-apps/api/event', () => ({ listen: mocks.listen }));
vi.mock('../src/services/storage', () => ({ quiescePersistentWrites: mocks.quiesce, resumePersistentWrites: mocks.resume }));
let handlers: Array<(event: { payload: { id: string; action: string } }) => void>;
const ticket = 'a'.repeat(48);
const callbacks = () => ({ quiesce: vi.fn(), resume: vi.fn(), error: vi.fn() });
beforeEach(() => {
  vi.resetModules(); Object.values(mocks).forEach(mock => mock.mockReset()); handlers = [];
  mocks.listen.mockImplementation(async (_name, handler) => { handlers.push(handler); return vi.fn(); });
  mocks.quiesce.mockResolvedValue({ generation: 'b'.repeat(48), revision: '20' });
  vi.stubGlobal('document', { documentElement: { inert: false } });
});
afterEach(() => vi.unstubAllGlobals());
describe('native handoff barrier orchestration', () => {
  it('deduplicates StrictMode listeners and waits for the raw ACK without a JS timeout', async () => {
    const service = await import('../src/services/stateHandoff'); const old = callbacks(); const live = callbacks();
    const stopOld = await service.listenForStateHandoff(old); await service.listenForStateHandoff(live); stopOld();
    let release!: (value: boolean) => void; mocks.invoke.mockImplementation(() => new Promise(resolve => { release = resolve; }));
    handlers.forEach(handler => handler({ payload: { id: ticket, action: 'restart' } }));
    await vi.waitFor(() => expect(mocks.invoke).toHaveBeenCalledTimes(1));
    expect(mocks.invoke).toHaveBeenCalledWith('acknowledge_state_handoff', { ticket, generation: 'b'.repeat(48), revision: '20' });
    expect(document.documentElement.inert).toBe(true); expect(live.quiesce).toHaveBeenCalledOnce(); expect(old.quiesce).not.toHaveBeenCalled();
    release(false); await vi.waitFor(() => expect(live.resume).toHaveBeenCalledOnce());
    expect(document.documentElement.inert).toBe(false);
  });
  it('never acknowledges shutdown after flush fails; confirmed native cancel permits resume', async () => {
    mocks.quiesce.mockRejectedValue(new Error('disk full')); mocks.invoke.mockResolvedValue(undefined);
    const service = await import('../src/services/stateHandoff'); const cb = callbacks(); await service.listenForStateHandoff(cb);
    handlers[0]({ payload: { id: ticket, action: 'quit' } });
    await vi.waitFor(() => expect(cb.error).toHaveBeenCalledOnce());
    expect(mocks.invoke.mock.calls.map(call => call[0])).toEqual(['cancel_state_handoff']); expect(cb.resume).toHaveBeenCalledOnce();
  });
  it('keeps controls and writes frozen when cancellation of a possibly active native seal is unconfirmed', async () => {
    mocks.invoke.mockRejectedValue(new Error('unknown IPC result'));
    const service = await import('../src/services/stateHandoff'); const cb = callbacks(); await service.listenForStateHandoff(cb);
    handlers[0]({ payload: { id: ticket, action: 'elevate' } });
    await vi.waitFor(() => expect(cb.error).toHaveBeenCalledOnce());
    expect(mocks.resume).not.toHaveBeenCalled(); expect(cb.resume).not.toHaveBeenCalled(); expect(document.documentElement.inert).toBe(true);
  });
  it('does not unfreeze an update with an unknown seal result through a null ticket fallback', async () => {
    mocks.invoke.mockRejectedValue(new Error('unknown IPC result')); const service = await import('../src/services/stateHandoff');
    await expect(service.sealUpdateState()).rejects.toThrow('unknown IPC result');
    await expect(service.releaseUpdateState(null)).rejects.toThrow('STATE_HANDOFF_UNCONFIRMED');
    expect(mocks.resume).not.toHaveBeenCalled(); expect(document.documentElement.inert).toBe(true);
    const ownedTicket = mocks.invoke.mock.calls[0][1].ticket;
    expect(ownedTicket).toMatch(/^[a-f0-9]{48}$/); expect(mocks.invoke.mock.calls[1][1].ticket).toBe(ownedTicket);
    mocks.invoke.mockResolvedValue(undefined); await service.releaseUpdateState(ownedTicket);
    expect(document.documentElement.inert).toBe(false);
  });
  it('allows a pre-handoff download failure to return without any native seal cancellation', async () => {
    const service = await import('../src/services/stateHandoff'); await service.releaseUpdateState(null);
    expect(mocks.invoke).not.toHaveBeenCalled(); expect(document.documentElement.inert).toBe(false);
  });
});
