import { describe, expect, it, vi } from 'vitest';
const probes = vi.hoisted(() => ({ native:vi.fn(), state:vi.fn() }));
vi.mock('../src/services/runtime', () => { probes.native(); throw new Error('synthetic native module initialization failure'); });
vi.mock('../src/services/stateHandoff', () => { probes.state(); throw new Error('synthetic state module initialization failure'); });
import { RootErrorBoundary } from '../src/components/RootErrorBoundary';

describe('R17/R46 bootstrap failure containment', () => {
  it('loads the fallback without initializing native or storage modules', () => {
    expect(probes.native).not.toHaveBeenCalled(); expect(probes.state).not.toHaveBeenCalled();
    const receipt = RootErrorBoundary.getDerivedStateFromError(new Error('App import failed')).receipt;
    expect(receipt?.code).toBe('UI_RENDER_FAILED');
  });
  it('keeps the fallback available when deferred diagnostics and shutdown modules also fail', async () => {
    const boundary = new RootErrorBoundary({children:null});
    boundary.state = {...boundary.state,...RootErrorBoundary.getDerivedStateFromError(new Error('App initialization failed'))};
    const state = vi.spyOn(boundary,'setState').mockImplementation(() => undefined);
    boundary.componentDidCatch();
    await vi.waitFor(() => {expect(probes.native).toHaveBeenCalledOnce();expect(probes.state).toHaveBeenCalledOnce();expect(state).toHaveBeenCalledWith({handoffFailed:true});});
    expect(boundary.render()).not.toBeNull(); boundary.componentWillUnmount();
  });
});
