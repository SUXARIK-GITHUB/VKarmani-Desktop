import packageJson from '../../package.json';
import {structuredNativeError} from '../utils/nativeErrors';
import {nativeMutations,NATIVE_MUTATIONS} from './nativeTransport';
import {validateRepairPlan,type RuntimeRepairPlan} from '../utils/repairPlan';
import { getServerPingEndpoint } from '../utils/serverPing';
export { getServerPingEndpoint } from '../utils/serverPing';
import { redactSensitiveText } from '../utils/redaction';
import type {
  ConnectivityProbe,
  ProxyStatus,
  RuntimeStatus,
  TrafficSnapshot,
  RunningAppInfo,
  WindowsServiceInfo,
  NativeAppInfo,
  SplitTunnelEntry,
  RoutingExclusionSettings,
  TunnelMode,
  IpStack,
  VpnServer,
  XrayRuntimeTemplate
} from '../types/vpn';
import { buildServerRuntimeFingerprint } from '../utils/serverIdentity';
import { canonicalJson } from '../utils/canonicalJson';

const tauriWindow = typeof window !== 'undefined'
  ? (window as Window & { __TAURI_INTERNALS__?: unknown; __TAURI__?: unknown })
  : undefined;

export const isTauriRuntime = Boolean(
  tauriWindow && (tauriWindow.__TAURI_INTERNALS__ || tauriWindow.__TAURI__)
);

export const appVersion = String(import.meta.env.VITE_APP_VERSION ?? packageJson.version ?? '0.13.40');
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

  const host = parsed.hostname.trim().toLowerCase().replace(/\.$/, '');
  const forbiddenHosts = new Set(['localhost', 'localhost.', '0.0.0.0', '127.0.0.1', '::1', '[::1]']);
  if (forbiddenHosts.has(host) || host.endsWith('.localhost')) {
    throw new Error('Локальные hostnames запрещены для удалённого fetch.');
  }

  if (host !== 'vkarmani.com' && !host.endsWith('.vkarmani.com')) {
    throw new Error('Удалённый fetch разрешён только для доменов VKarmani (*.vkarmani.com).');
  }

  if (/^(10|127)\./.test(host) || /^192\.168\./.test(host) || /^172\.(1[6-9]|2\d|3[0-1])\./.test(host) || /^169\.254\./.test(host)) {
    throw new Error('Локальные, приватные и служебные IP-адреса запрещены для удалённого fetch.');
  }

  return parsed.toString();
}

export const allowDemoFallbackByEnv = String(envFlag ?? '').trim().toLowerCase() === 'true';

const NATIVE_COMMAND_TIMEOUTS_MS: Record<string, number> = {
  request_connect: 85000,
  request_disconnect: 22000,
  rollback_failed_connect: 22000,
  set_system_proxy: 18000,
  public_ip_snapshot: 12000,
  fetch_remote_text: 20000,
  revoke_hwid_device: 20000,
  connectivity_probe: 12000,
  repair_runtime_environment: 30000,
  server_ping: 9000,
  traffic_snapshot: 7000,
  runtime_status: 9000,
  runtime_observation: 9000,
  proxy_status: 9000,
  read_runtime_log: 5000,
  write_interface_log: 3500,
  write_routing_log: 3500,
  load_access_key_secure: 9000,
  save_access_key_secure: 12000,
  clear_access_key_secure: 9000,
  native_app_info: 12000,
  pick_executable_path: 120000,
  list_running_apps: 14000,
  list_windows_services: 14000,
  set_tray_update_state: 3500,
  set_session_authorized: 18000
};

function commandTimeoutError(command:string) {
  const language=typeof document!=='undefined'&&document.documentElement.lang==='en'?'en':'ru';
  return structuredNativeError({code:'NATIVE_COMMAND_TIMEOUT',category:'bridge',retryable:false,operationPending:NATIVE_MUTATIONS.has(command)},'Native response unavailable',language)!;
}

function withClientTimeout<T>(operation: Promise<T>, timeoutMs: number, command: string): Promise<T> {
  let timer: number | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = window.setTimeout(() => reject(commandTimeoutError(command)), timeoutMs);
  });

  operation.catch(() => {
    // Поздняя ошибка после клиентского timeout уже обработана Promise.race.
    // Не даём ей превратиться в unhandled rejection и подвесить UI-логику.
  });

  return Promise.race([operation, timeoutPromise]).finally(() => {
    if (timer !== undefined) {
      window.clearTimeout(timer);
    }
  }) as Promise<T>;
}

async function invokeTauri<T>(command: string, args: Record<string, unknown> = {}, timeoutMs = NATIVE_COMMAND_TIMEOUTS_MS[command] ?? 12000): Promise<T> {
  const { invoke } = await import('@tauri-apps/api/core');
  return withClientTimeout(nativeMutations.invoke(command,()=>invoke<T>(command,args)), timeoutMs, command);
}

export async function setNativeTrayUpdateState(available: boolean, busy: boolean): Promise<boolean> {
  if (!isTauriRuntime) {
    return false;
  }

  try {
    return await invokeTauri<boolean>('set_tray_update_state', { available, busy }, NATIVE_COMMAND_TIMEOUTS_MS.set_tray_update_state);
  } catch {
    return false;
  }
}



export async function openExternalUrl(url: string): Promise<void> {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:') {
    throw new Error('Открывать можно только HTTPS-ссылки.');
  }

  if (isTauriRuntime) {
    await invokeTauri<void>('open_external_url', { url: parsed.toString() }, 5000);
    return;
  }

  window.open(parsed.toString(), '_blank', 'noopener,noreferrer');
}



function extractErrorMessage(error: unknown, depth = 0,budget={remaining:128}): string {
  if (--budget.remaining<0||depth > 4 || error == null) {
    return '';
  }

  if (typeof error === 'string') {
    return error.slice(0,4096).trim();
  }

  if (error instanceof Error) {
    const direct = error.message?.slice(0,4096).trim() ?? '';
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
      const nested = extractErrorMessage(candidate, depth + 1,budget);
      if (nested) {
        return nested;
      }
    }

    if (Array.isArray(record.errors)) {
      for (const item of record.errors.slice(0,16)) {
        const nested = extractErrorMessage(item, depth + 1,budget);
        if (nested) {
          return nested;
        }
      }
    }

    // Unknown payload objects may contain private state or throwing toJSON.
    // Only explicit bounded message fields or structured codes cross into UI.
  }

  return '';
}

export function normalizeNativeError(error: unknown, fallback: string): Error {
  const structured=structuredNativeError(error,fallback,typeof document!=='undefined'&&document.documentElement.lang==='en'?'en':'ru');
  if(structured)return structured;
  let extracted='';try{extracted=extractErrorMessage(error);}catch{/* Arbitrary accessors cannot break the error path. */}
  const message = redactSensitiveText(extracted.slice(0,4096) || fallback);
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
    throw new Error(normalizeNativeError(error, 'Не удалось получить статус runtime.').message);
  }
}

export async function getNativeDiagnosticsSnapshot(): Promise<RuntimeStatus> {
  if (!isTauriRuntime) throw Error('DIAGNOSTICS_NATIVE_REQUIRED');
  return invokeTauri<RuntimeStatus>('diagnostics_snapshot');
}
export async function getNativeRuntimeObservation():Promise<RuntimeStatus>{
  if(!isTauriRuntime)return mockRuntimeStatus('Web preview has no native connection.');
  return invokeTauri<RuntimeStatus>('runtime_observation');
}

export async function requestNativeConnect(
  server: VpnServer,
  networkMode: TunnelMode = 'proxy',
  splitTunnelEntries: SplitTunnelEntry[] = [],
  ipStack: IpStack = 'ipv4',
  reconnect = false,
  routingExclusions?: RoutingExclusionSettings,
  tunRoutingMode: 'all' | 'selected' | 'exclude' = 'selected'
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
    serverFingerprint: buildServerRuntimeFingerprint(server),
    runtimeTemplate,
    canonicalTemplateJson: canonicalJson(runtimeTemplate),
    networkMode,
    tunRoutingMode,
    splitTunnelEntries,
    ipStack,
    reconnect,
    routingExclusions
  });
}

export async function listNativeRunningApps(): Promise<RunningAppInfo[]> {
  if (!isTauriRuntime) {
    return [];
  }

  return invokeTauri<RunningAppInfo[]>('list_running_apps');
}
export async function listNativeWindowsServices(): Promise<WindowsServiceInfo[]> {
  if (!isTauriRuntime) return [];
  return invokeTauri<WindowsServiceInfo[]>('list_windows_services');
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

export async function setNativeSystemProxy(enabled: boolean, expectedConfigPath?: string): Promise<ProxyStatus> {
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

  return invokeTauri<ProxyStatus>('set_system_proxy', { enabled, expectedConfigPath });
}

export async function rollbackFailedNativeConnect(expectedConfigPath: string): Promise<RuntimeStatus> {
  return invokeTauri<RuntimeStatus>('rollback_failed_connect', { expectedConfigPath });
}



export async function pingNativeServer(server: VpnServer): Promise<ConnectivityProbe> {
  const endpoint = getServerPingEndpoint(server);

  if (!endpoint) {
    throw new Error('У выбранного сервера нет host/port для проверки пинга. Обновите профиль серверов.');
  }

  const { host, port } = endpoint;

  if (!isTauriRuntime) {
    return { kind:'unavailable',success:false, checkedAt:new Date().toISOString(), httpPortOpen:false, socksPortOpen:false,
      message:'Endpoint measurement requires the native runtime; preview contains no synthetic latency.' };
  }

  return invokeTauri<ConnectivityProbe>('server_ping', { host, port });
}

export async function beginNativeTrafficSession(): Promise<number> {
  return isTauriRuntime ? invokeTauri<number>('traffic_session_start') : 0;
}
export async function getNativeTrafficSnapshot(sessionId: number): Promise<TrafficSnapshot> {
  if (!isTauriRuntime) {
    return {
      receivedBytes: 0,
      sentBytes: 0,
      checkedAt: new Date().toLocaleString('ru-RU'),
      source: 'unavailable'
    };
  }

  return invokeTauri<TrafficSnapshot>('traffic_snapshot', { sessionId });
}

export async function runNativeConnectivityProbe(): Promise<ConnectivityProbe> {
  if (!isTauriRuntime) {
    return {
      kind:'unavailable',
      success: false,
      checkedAt: new Date().toLocaleString('ru-RU'),
      httpPortOpen: false,
      socksPortOpen: false,
      message: 'Проверка доступна только в нативной Tauri-сборке.'
    };
  }

  return invokeTauri<ConnectivityProbe>('connectivity_probe');
}

export async function prepareNativeRuntimeRepair():Promise<RuntimeRepairPlan> {
  if(!isTauriRuntime)throw Error('REPAIR_NATIVE_REQUIRED');
  return validateRepairPlan(await invokeTauri<unknown>('prepare_runtime_repair'));
}
export async function repairNativeRuntimeEnvironment(planId:string): Promise<RuntimeStatus> {
  if (!isTauriRuntime) {
    throw Error('REPAIR_NATIVE_REQUIRED');
  }

  return invokeTauri<RuntimeStatus>('repair_runtime_environment',{planId});
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


export interface RemoteSubscriptionResponse {
  text: string;
  userinfo: { upload: string | null; download: string | null; total: string | null; expire: string | null };
}

export async function fetchRemoteText(url: string, accept = 'text/plain, application/json, text/html', userAgent?: string): Promise<string> {
  if (isTauriRuntime) {
    return invokeTauri<string>('fetch_remote_text', { url, accept, userAgent });
  }
  return (await fetchRemoteSubscription(url, accept, userAgent)).text;
}

export async function fetchRemoteSubscription(url: string, accept = 'application/json', userAgent?: string): Promise<RemoteSubscriptionResponse> {
  if (isTauriRuntime) return invokeTauri<RemoteSubscriptionResponse>('fetch_remote_subscription', { url, accept, userAgent });

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

    const { parseSubscriptionUserinfo } = await import('../utils/subscriptionMetadata');
    return { text, userinfo: parseSubscriptionUserinfo(response.headers.get('subscription-userinfo')) };
  } finally {
    window.clearTimeout(timeout);
  }
}

function looksLikeRawSubscriptionText(value: string) {
  const trimmed = value.trim();
  if (!trimmed) {
    return false;
  }

  if (/(?:vless|vmess|trojan|ss|hy2|hysteria2):\/\//i.test(trimmed)) {
    return true;
  }

  const compact = trimmed.replace(/\s+/g, '');
  return compact.length >= 16 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(compact);
}

export async function fetchRemoteJson<T = unknown>(url: string, accept = 'application/json, text/plain, text/html') {
  const raw = await fetchRemoteText(url, accept);
  try {
    return JSON.parse(raw) as T;
  } catch {
    if (looksLikeRawSubscriptionText(raw)) {
      throw new Error('Endpoint вернул не Xray JSON профиль. Продолжаем проверку через Xray JSON профиль.');
    }

    throw new Error('Ответ Remnawave не является валидным JSON-профилем. Продолжаем проверку через Xray JSON профиль.');
  }
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

export async function setNativeSessionAuthorized(authorized: boolean, accessKey?: string) {
  if (!isTauriRuntime) {
    return false;
  }

  try {
    return await invokeTauri<boolean>('set_session_authorized', { authorized, accessKey });
  } catch (error) {
    console.warn(
      '[VKarmani] native session authorization failed:',
      normalizeNativeError(error, 'Не удалось обновить native session.').message
    );
    return false;
  }
}
