import packageJson from '../../package.json';
import type {
  ConnectivityProbe,
  ProxyStatus,
  RuntimeStatus,
  SplitTunnelEntry,
  TunnelMode,
  VpnServer,
  XrayRuntimeTemplate
} from '../types/vpn';

const tauriWindow = typeof window !== 'undefined'
  ? (window as Window & { __TAURI_INTERNALS__?: unknown; __TAURI__?: unknown })
  : undefined;

export const isTauriRuntime = Boolean(
  tauriWindow && (tauriWindow.__TAURI_INTERNALS__ || tauriWindow.__TAURI__)
);

export const appVersion = String(import.meta.env.VITE_APP_VERSION ?? packageJson.version ?? '0.13.8');
export const remnawavePanelUrl = import.meta.env.VITE_REMNAWAVE_PANEL_URL ?? '';
export const remnawaveSubscriptionUrl = import.meta.env.VITE_REMNAWAVE_SUBSCRIPTION_URL ?? '';
const envFlag = import.meta.env.VITE_ALLOW_DEMO_FALLBACK;
export const allowDemoFallbackByEnv = String(envFlag ?? '').trim().toLowerCase() === 'true';

async function invokeTauri<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  const { invoke } = await import('@tauri-apps/api/core');
  return invoke<T>(command, args);
}


function extractErrorMessage(error: unknown, depth = 0): string {
  if (depth > 4 || error == null) {
    return '';
  }

  if (typeof error === 'string') {
    return error.trim();
  }

  if (error instanceof Error) {
    const direct = error.message?.trim() ?? '';
    if (direct) {
      return direct;
    }
  }

  if (typeof error === 'object') {
    const record = error as Record<string, unknown>;
    const candidates = [
      record.message,
      record.error,
      record.cause,
      record.details,
      record.reason
    ];

    for (const candidate of candidates) {
      const nested = extractErrorMessage(candidate, depth + 1);
      if (nested) {
        return nested;
      }
    }

    if (Array.isArray(record.errors)) {
      for (const item of record.errors) {
        const nested = extractErrorMessage(item, depth + 1);
        if (nested) {
          return nested;
        }
      }
    }

    try {
      const serialized = JSON.stringify(error);
      if (serialized && serialized !== '{}') {
        return serialized;
      }
    } catch {
      // ignore serialization errors
    }
  }

  return '';
}

export function normalizeNativeError(error: unknown, fallback: string): Error {
  const message = extractErrorMessage(error) || fallback;
  return new Error(message);
}

function extractRuntimeTemplate(server: VpnServer): XrayRuntimeTemplate | null {
  return server.runtimeTemplate ?? null;
}

function mockRuntimeStatus(message: string): RuntimeStatus {
  return {
    bridge: isTauriRuntime ? 'tauri' : 'web-preview',
    coreInstalled: false,
    tunnelActive: false,
    launchMode: 'mock',
    message
  };
}

export async function getNativeRuntimeStatus(): Promise<RuntimeStatus> {
  if (!isTauriRuntime) {
    return mockRuntimeStatus('Сейчас открыт web-preview. Нативный runtime будет доступен в Tauri-сборке.');
  }

  try {
    return await invokeTauri<RuntimeStatus>('runtime_status');
  } catch (error) {
    return mockRuntimeStatus(normalizeNativeError(error, 'Не удалось получить статус runtime.').message);
  }
}

export async function requestNativeConnect(
  server: VpnServer,
  networkMode: TunnelMode = 'proxy',
  splitTunnelEntries: SplitTunnelEntry[] = []
) {
  if (!isTauriRuntime) {
    return getNativeRuntimeStatus();
  }

  const runtimeTemplate = extractRuntimeTemplate(server);
  if (!runtimeTemplate) {
    throw new Error('Для этого узла ещё нет runtime-конфига. Синхронизируйте live-профиль Remnawave или выберите другой сервер.');
  }

  return invokeTauri<RuntimeStatus>('request_connect', {
    serverId: server.id,
    serverLabel: `${server.country}, ${server.city}`,
    runtimeTemplate,
    networkMode,
    splitTunnelEntries
  });
}

export async function requestNativeDisconnect() {
  if (!isTauriRuntime) {
    return getNativeRuntimeStatus();
  }

  return invokeTauri<RuntimeStatus>('request_disconnect');
}

export async function cacheNativeProfileSync(profileCount: number, source: string) {
  if (!isTauriRuntime) {
    return;
  }

  await invokeTauri('cache_profile_sync', { profileCount, source });
}

export async function getNativeProxyStatus(): Promise<ProxyStatus> {
  if (!isTauriRuntime) {
    return {
      enabled: false,
      method: 'mock',
      scope: 'current-user',
      checkedAt: new Date().toLocaleString('ru-RU')
    };
  }

  return invokeTauri<ProxyStatus>('proxy_status');
}

export async function setNativeSystemProxy(enabled: boolean): Promise<ProxyStatus> {
  if (!isTauriRuntime) {
    return {
      enabled,
      server: enabled ? 'http=127.0.0.1:10809;https=127.0.0.1:10809' : undefined,
      bypass: enabled ? '<local>' : undefined,
      method: 'mock',
      scope: 'current-user',
      checkedAt: new Date().toLocaleString('ru-RU')
    };
  }

  return invokeTauri<ProxyStatus>('set_system_proxy', { enabled });
}

export async function runNativeConnectivityProbe(): Promise<ConnectivityProbe> {
  if (!isTauriRuntime) {
    return {
      success: false,
      checkedAt: new Date().toLocaleString('ru-RU'),
      httpPortOpen: false,
      socksPortOpen: false,
      message: 'Проверка доступна только в нативной Tauri-сборке.'
    };
  }

  return invokeTauri<ConnectivityProbe>('connectivity_probe');
}

export async function readNativeRuntimeLog(lines = 20): Promise<string[]> {
  if (!isTauriRuntime) {
    return [];
  }

  return invokeTauri<string[]>('read_runtime_log', { lines });
}

export async function writeNativeInterfaceLog(message: string, details?: string) {
  if (!isTauriRuntime) {
    return;
  }

  await invokeTauri('write_interface_log', { message, details });
}

export async function writeNativeRoutingLog(message: string, details?: string) {
  if (!isTauriRuntime) {
    return;
  }

  await invokeTauri('write_routing_log', { message, details });
}


export async function fetchRemoteText(url: string, accept = 'text/plain, application/json, text/html') {
  if (isTauriRuntime) {
    return invokeTauri<string>('fetch_remote_text', { url, accept });
  }

  const response = await fetch(url, {
    method: 'GET',
    headers: { Accept: accept }
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  return response.text();
}

export async function fetchRemoteJson<T = unknown>(url: string, accept = 'application/json, text/plain, text/html') {
  const raw = await fetchRemoteText(url, accept);
  return JSON.parse(raw) as T;
}



export async function fetchPublicIpSnapshot(mode: 'direct' | 'runtime' = 'direct'): Promise<string> {
  if (isTauriRuntime) {
    try {
      return await invokeTauri<string>('public_ip_snapshot', { mode });
    } catch {
      if (mode === 'runtime') {
        throw new Error('Не удалось определить VPN IP через локальный runtime.');
      }
    }
  }

  if (mode === 'runtime') {
    throw new Error('Определение VPN IP доступно только в нативной Tauri-сборке.');
  }

  const jsonCandidates = [
    'https://api.ipify.org?format=json',
    'https://api64.ipify.org?format=json'
  ];

  for (const url of jsonCandidates) {
    try {
      const payload = await fetchRemoteJson<{ ip?: string }>(url, 'application/json, text/plain');
      if (payload?.ip && typeof payload.ip === 'string' && payload.ip.trim()) {
        return payload.ip.trim();
      }
    } catch {
      // try next source
    }
  }

  try {
    const raw = await fetchRemoteText('https://api.ipify.org', 'text/plain');
    const value = raw.trim();
    if (value) {
      return value;
    }
  } catch {
    // ignore
  }

  throw new Error('Не удалось определить внешний IP.');
}

export async function ensureAdminLaunch(enabled: boolean) {
  if (!enabled || !isTauriRuntime || import.meta.env.DEV) {
    return false;
  }

  return invokeTauri<boolean>('ensure_admin_launch');
}

export async function setNativeLaunchOnStartup(enabled: boolean) {
  if (!isTauriRuntime) {
    return false;
  }

  return invokeTauri<boolean>('set_launch_on_startup', { enabled });
}

export async function performWindowAction(action: 'minimize' | 'maximize' | 'close') {
  if (!isTauriRuntime) {
    return;
  }

  if (action === 'minimize') {
    await invokeTauri('window_minimize');
    return;
  }

  if (action === 'maximize') {
    await invokeTauri('window_toggle_maximize');
    return;
  }

  await invokeTauri('window_close');
}

export async function requestWindowHide() {
  if (!isTauriRuntime) {
    return;
  }

  await invokeTauri('window_hide');
}

export async function startWindowDrag() {
  if (!isTauriRuntime) {
    return;
  }

  await invokeTauri('window_start_drag');
}

export function getIntegrationMeta() {
  return {
    panelUrl: remnawavePanelUrl,
    subscriptionUrl: remnawaveSubscriptionUrl,
    isConfigured: Boolean(remnawavePanelUrl || remnawaveSubscriptionUrl),
    modeLabel: remnawaveSubscriptionUrl
      ? 'Публичная subscription-интеграция'
      : remnawavePanelUrl
        ? 'Panel API'
        : 'Интеграция не настроена'
  };
}
