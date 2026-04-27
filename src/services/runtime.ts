import packageJson from '../../package.json';
import { redactSensitiveText } from '../utils/redaction';
import type {
  ConnectivityProbe,
  ProxyStatus,
  RuntimeStatus,
  TrafficSnapshot,
  RunningAppInfo,
  NativeAppInfo,
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
const WEB_FETCH_BODY_LIMIT_BYTES = 2 * 1024 * 1024;

function validateWebRemoteFetchUrl(rawUrl: string) {
  let parsed: URL;

  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('Некорректный URL для удалённого запроса.');
  }

  if (parsed.protocol !== 'https:') {
    throw new Error('Удалённые запросы разрешены только по HTTPS.');
  }

  if (parsed.username || parsed.password) {
    throw new Error('URL с userinfo запрещены для удалённого fetch.');
  }

  const host = parsed.hostname.trim().toLowerCase();
  const forbiddenHosts = new Set(['localhost', 'localhost.', '0.0.0.0', '127.0.0.1', '::1', '[::1]']);
  if (forbiddenHosts.has(host) || host.endsWith('.localhost')) {
    throw new Error('Локальные hostnames запрещены для удалённого fetch.');
  }

  if (/^(10|127)\./.test(host) || /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[0-1])\./.test(host) || /^169\.254\./.test(host)) {
    throw new Error('Локальные, приватные и служебные IP-адреса запрещены для удалённого fetch.');
  }

  return parsed.toString();
}

export const allowDemoFallbackByEnv = String(envFlag ?? '').trim().toLowerCase() === 'true';

const NATIVE_COMMAND_TIMEOUTS_MS: Record<string, number> = {
  request_connect: 45000,
  request_disconnect: 25000,
  set_system_proxy: 18000,
  public_ip_snapshot: 12000,
  fetch_remote_text: 20000,
  revoke_hwid_device: 20000,
  connectivity_probe: 12000,
  server_ping: 4500,
  traffic_snapshot: 7000,
  runtime_status: 9000,
  proxy_status: 9000,
  read_runtime_log: 5000,
  write_interface_log: 3500,
  write_routing_log: 3500,
  load_access_key_secure: 9000,
  save_access_key_secure: 12000,
  clear_access_key_secure: 9000,
  native_app_info: 12000,
  pick_executable_path: 120000
};

function commandTimeoutMessage(command: string, timeoutMs: number) {
  const seconds = Math.round(timeoutMs / 1000);
  if (command === 'request_connect') {
    return `Подключение заняло больше ${seconds} секунд. UI разблокирован, состояние runtime будет обновлено автоматически.`;
  }
  if (command === 'request_disconnect') {
    return `Отключение заняло больше ${seconds} секунд. UI разблокирован, состояние runtime будет обновлено автоматически.`;
  }
  if (command === 'set_system_proxy') {
    return `Изменение системного proxy заняло больше ${seconds} секунд. Проверьте состояние proxy в диагностике.`;
  }
  return `Нативная команда ${command} не ответила за ${seconds} секунд.`;
}

function withClientTimeout<T>(operation: Promise<T>, timeoutMs: number, command: string): Promise<T> {
  let timer: number | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = window.setTimeout(() => reject(new Error(commandTimeoutMessage(command, timeoutMs))), timeoutMs);
  });

  return Promise.race([operation, timeoutPromise]).finally(() => {
    if (timer !== undefined) {
      window.clearTimeout(timer);
    }
  }) as Promise<T>;
}

async function invokeTauri<T>(command: string, args: Record<string, unknown> = {}, timeoutMs = NATIVE_COMMAND_TIMEOUTS_MS[command] ?? 12000): Promise<T> {
  const { invoke } = await import('@tauri-apps/api/core');
  return withClientTimeout(invoke<T>(command, args), timeoutMs, command);
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
  const message = redactSensitiveText(extractErrorMessage(error) || fallback);
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

export async function listNativeRunningApps(): Promise<RunningAppInfo[]> {
  if (!isTauriRuntime) {
    return [];
  }

  return invokeTauri<RunningAppInfo[]>('list_running_apps');
}


export async function getNativeAppInfo(): Promise<NativeAppInfo> {
  if (!isTauriRuntime) {
    return {
      appVersion,
      xrayVersion: 'Web preview',
      hwid: '—',
      osName: navigator.platform || 'Web',
      osVersion: navigator.userAgent,
      osBuild: '—',
      osArchitecture: navigator.userAgent.includes('Win64') || navigator.userAgent.includes('x64') ? 'x64' : '—',
      deviceName: 'Web preview'
    };
  }

  return invokeTauri<NativeAppInfo>('native_app_info');
}

export async function pickNativeExecutablePath(): Promise<string | null> {
  if (!isTauriRuntime) {
    return null;
  }

  return invokeTauri<string | null>('pick_executable_path', {}, NATIVE_COMMAND_TIMEOUTS_MS.pick_executable_path);
}

export async function restartNativeApplication(): Promise<void> {
  if (!isTauriRuntime) {
    window.location.reload();
    return;
  }

  await invokeTauri('restart_application');
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



export async function pingNativeServer(server: VpnServer): Promise<ConnectivityProbe> {
  const host = server.host?.trim();
  const port = Number(server.port ?? 443);

  if (!host || !Number.isFinite(port) || port <= 0) {
    throw new Error('У выбранного сервера нет host/port для проверки пинга. Обновите профиль серверов.');
  }

  if (!isTauriRuntime) {
    const started = performance.now();
    await new Promise((resolve) => window.setTimeout(resolve, 80 + Math.round(Math.random() * 40)));
    return {
      success: true,
      checkedAt: new Date().toLocaleString('ru-RU'),
      httpPortOpen: false,
      socksPortOpen: false,
      latencyMs: Math.max(1, Math.round(performance.now() - started)),
      packetLossPct: 0,
      message: 'Web-preview имитирует TCP ping. В нативной сборке используется реальная TCP-проверка host:port.'
    };
  }

  return invokeTauri<ConnectivityProbe>('server_ping', { host, port });
}

export async function getNativeTrafficSnapshot(): Promise<TrafficSnapshot> {
  if (!isTauriRuntime) {
    return {
      receivedBytes: 0,
      sentBytes: 0,
      checkedAt: new Date().toLocaleString('ru-RU'),
      source: 'mock'
    };
  }

  return invokeTauri<TrafficSnapshot>('traffic_snapshot');
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

  await invokeTauri('write_interface_log', { message: redactSensitiveText(message), details: details ? redactSensitiveText(details) : undefined });
}

export async function writeNativeRoutingLog(message: string, details?: string) {
  if (!isTauriRuntime) {
    return;
  }

  await invokeTauri('write_routing_log', { message: redactSensitiveText(message), details: details ? redactSensitiveText(details) : undefined });
}


export async function fetchRemoteText(url: string, accept = 'text/plain, application/json, text/html') {
  if (isTauriRuntime) {
    return invokeTauri<string>('fetch_remote_text', { url, accept });
  }

  const safeUrl = validateWebRemoteFetchUrl(url);
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 8000);

  try {
    const response = await fetch(safeUrl, {
      method: 'GET',
      headers: { Accept: accept },
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const contentLength = Number(response.headers.get('content-length') ?? 0);
    if (contentLength > WEB_FETCH_BODY_LIMIT_BYTES) {
      throw new Error(`Ответ remote subscription слишком большой: ${contentLength} байт.`);
    }

    const text = await response.text();
    if (text.length > WEB_FETCH_BODY_LIMIT_BYTES) {
      throw new Error(`Ответ remote subscription слишком большой. Лимит: ${WEB_FETCH_BODY_LIMIT_BYTES} байт.`);
    }

    return text;
  } finally {
    window.clearTimeout(timeout);
  }
}

export async function fetchRemoteJson<T = unknown>(url: string, accept = 'application/json, text/plain, text/html') {
  const raw = await fetchRemoteText(url, accept);
  return JSON.parse(raw) as T;
}



export async function revokeNativeHwidDevice(
  panelUrl: string,
  payload: { uuid?: string; hwid?: string; userUuid?: string }
): Promise<unknown> {
  if (!isTauriRuntime) {
    throw new Error('Удалённый отзыв HWID доступен только в нативной Tauri-сборке.');
  }

  return invokeTauri('revoke_hwid_device', {
    panelUrl,
    uuid: payload.uuid,
    hwid: payload.hwid,
    userUuid: payload.userUuid
  });
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

export async function setNativeSessionAuthorized(authorized: boolean) {
  if (!isTauriRuntime) {
    return false;
  }

  try {
    return await invokeTauri<boolean>('set_session_authorized', { authorized });
  } catch {
    return false;
  }
}
