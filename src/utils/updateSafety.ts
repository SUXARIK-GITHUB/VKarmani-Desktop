import type { ConnectionState, RuntimeStatus } from '../types/vpn';

export function canAutoInstallUpdate(runtime: RuntimeStatus | null, connection: ConnectionState): boolean {
  // Missing native observations are unknown, never a clean-network default.
  return connection === 'idle' && runtime?.bridge === 'tauri'
    && runtime.tunnelActive === false && !runtime.xrayPid && !runtime.operation
    && runtime.systemProxyEnabled === false && !runtime.proxyAutoConfigUrl
    && runtime.proxyOwnership === 'none' && runtime.routeOwnership === 'none';
}

export function updateNeedsOwnedCleanup(runtime: RuntimeStatus): boolean {
  return runtime.tunnelActive || Boolean(runtime.xrayPid)
    || runtime.proxyOwnership !== 'none' || runtime.routeOwnership !== 'none';
}
