import { normalizeStoredRules } from '../utils/appPolicies';
import type { AppSettings, SplitTunnelEntry, VpnServer } from '../types/vpn';
import { defaultRoutingExclusions, sanitizeRoutingExclusions } from '../utils/routingExclusions';
import { encodeProfileCache, decodeProfileCache } from './profileCache';
import { commitNativeChange, exportNativeStateLegacy, inspectNativeState, invokeStateProtocol, NativeStorageError, peekNativeState, readNativeState, recoverNativeState, storageFailure } from './nativeState';
export { NativeStorageError } from './nativeState';

const ACCESS_KEY_STORAGE = 'vkarmani.access-key';
const ACCESS_KEY_FORM_STORAGE = 'vkarmani.form.access-key';
const ACCESS_KEY_FALLBACK_STORAGE = 'vkarmani.access-key.fallback-v1';
const SETTINGS_STORAGE = 'vkarmani.settings';
const SPLIT_TUNNEL_STORAGE = 'vkarmani.split-tunnel.entries';
const FAVORITE_SERVERS_STORAGE = 'vkarmani.servers.favorites';
const SELECTED_SERVER_STORAGE = 'vkarmani.servers.selected';
const LAST_KNOWN_SERVERS_STORAGE = 'vkarmani.servers.last-known-xray-json';
const NATIVE_SETTINGS_KEY = 'settings';
const NATIVE_SPLIT_TUNNEL_KEY = 'splitTunnelEntries';
const NATIVE_FAVORITES_KEY = 'favoriteServerIds';
const NATIVE_SELECTED_SERVER_KEY = 'selectedServerId';
const NATIVE_LAST_KNOWN_SERVERS_KEY = 'lastKnownServers';

export const defaultSettings: AppSettings = {
  launchOnStartup: false,
  runAsAdmin: false,
  showDiagnostics: false,
  autoConnect: false,
  autoConnectFavorite: false,
  minimizeToTray: true,
  notifications: true,
  autoUpdate: true,
  autoInstallUpdates: false,
  themeGlow: true,
  sortServersByPing: false,
  tunRoutingMode: 'all',
  releaseChannel: 'stable',
  protocolStrategy: 'auto',
  profileSyncOnLogin: true,
  allowDemoFallback: false,
  useSystemProxy: true,
  probeOnConnect: true,
  tunnelMode: 'proxy',
  ipStack: 'ipv4',
  language: 'ru',
  routingExclusions: { ...defaultRoutingExclusions, domains: [], ips: [] }
};

export function normalizeStoredSettings(value: unknown, hasLegacyRules = false): AppSettings {
  if (!value || typeof value !== 'object') {
    return { ...defaultSettings, tunRoutingMode: hasLegacyRules ? 'selected' : 'all' };
  }

  const candidate = value as Partial<AppSettings>;
  const booleanKeys: Array<keyof Omit<AppSettings, 'releaseChannel' | 'protocolStrategy' | 'language' | 'tunnelMode' | 'ipStack' | 'routingExclusions' | 'tunRoutingMode'>> = [
    'launchOnStartup',
    'runAsAdmin',
    'showDiagnostics',
    'autoConnect',
    'autoConnectFavorite',
    'minimizeToTray',
    'notifications',
    'autoUpdate',
    'autoInstallUpdates',
    'themeGlow',
    'sortServersByPing',
    'profileSyncOnLogin',
    'allowDemoFallback',
    'useSystemProxy',
    'probeOnConnect'
  ];

  const next: AppSettings = { ...defaultSettings, tunRoutingMode: hasLegacyRules ? 'selected' : 'all' };
  if (candidate.tunRoutingMode === 'all' || candidate.tunRoutingMode === 'selected' || candidate.tunRoutingMode === 'exclude') next.tunRoutingMode = candidate.tunRoutingMode;

  for (const key of booleanKeys) {
    if (typeof candidate[key] === 'boolean') {
      (next as unknown as Record<string, unknown>)[key] = candidate[key];
    }
  }

  if (candidate.releaseChannel === 'stable') {
    next.releaseChannel = candidate.releaseChannel;
  }

  if (candidate.protocolStrategy === 'auto' || candidate.protocolStrategy === 'reality-first' || candidate.protocolStrategy === 'xray-only') {
    next.protocolStrategy = candidate.protocolStrategy;
  }

  if (candidate.tunnelMode === 'proxy' || candidate.tunnelMode === 'tun') {
    next.tunnelMode = candidate.tunnelMode;
  }

  if (candidate.ipStack === 'ipv4' || candidate.ipStack === 'ipv6') {
    next.ipStack = candidate.ipStack;
  }

  if (candidate.language === 'ru' || candidate.language === 'en') {
    next.language = candidate.language;
  }

  next.routingExclusions = sanitizeRoutingExclusions(candidate.routingExclusions);

  return next;
}


function isStoredXrayRuntimeTemplate(value: unknown): value is VpnServer['runtimeTemplate'] {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const candidate = value as Partial<NonNullable<VpnServer['runtimeTemplate']>>;
  return candidate.family === 'xray' && typeof candidate.outbound === 'object' && candidate.outbound !== null;
}

function isStoredVpnServer(value: unknown): value is VpnServer {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const candidate = value as Partial<VpnServer>;
  const hasValidRuntimeTemplate = candidate.runtimeTemplate === undefined || isStoredXrayRuntimeTemplate(candidate.runtimeTemplate);
  return typeof candidate.id === 'string'
    && typeof candidate.country === 'string'
    && typeof candidate.city === 'string'
    && typeof candidate.flag === 'string'
    && typeof candidate.load === 'number'
    && hasValidRuntimeTemplate;
}

function normalizeStoredServers(value: unknown): VpnServer[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const seen = new Set<string>();
  const servers: VpnServer[] = [];

  for (const item of value) {
    if (!isStoredVpnServer(item)) {
      continue;
    }

    const id = item.id.trim();
    if (!id || seen.has(id)) {
      continue;
    }

    seen.add(id);
    servers.push({
      ...item,
      id,
      source: 'subscription',
      sourceOrder: Number.isSafeInteger(item.sourceOrder) && (item.sourceOrder ?? -1) >= 0 ? item.sourceOrder : servers.length,
      latencyStatus: item.latencyStatus === 'ok' || item.latencyStatus === 'failed' ? item.latencyStatus : 'unchecked',
      latency: typeof item.latency === 'number' ? item.latency : null
    });

    if (servers.length >= 1000) {
      break;
    }
  }

  return servers;
}

function stripSensitiveServerRuntime(server: VpnServer): VpnServer {
  const { runtimeTemplate: _runtimeTemplate, rawUri: _rawUri, ...safeServer } = server;
  return {
    ...safeServer,
    latencyStatus: server.latencyStatus === 'ok' || server.latencyStatus === 'failed' ? server.latencyStatus : 'unchecked',
    latency: typeof server.latency === 'number' ? server.latency : null
  };
}

function stripSensitiveServerRuntimeList(value: VpnServer[]): VpnServer[] {
  return value.map(stripSensitiveServerRuntime);
}


const tauriWindow = typeof window !== 'undefined'
  ? (window as Window & { __TAURI_INTERNALS__?: unknown; __TAURI__?: unknown })
  : undefined;

const canUseTauriSecureStorage = Boolean(
  tauriWindow && (tauriWindow.__TAURI_INTERNALS__ || tauriWindow.__TAURI__)
);

let legacyMirrorAtBoot: Record<string, string> | null = null;
if (canUseTauriSecureStorage && typeof window !== 'undefined') {
  legacyMirrorAtBoot = {};
  try {
    for (const key of [SETTINGS_STORAGE, SPLIT_TUNNEL_STORAGE, FAVORITE_SERVERS_STORAGE, SELECTED_SERVER_STORAGE, LAST_KNOWN_SERVERS_STORAGE, ACCESS_KEY_STORAGE, ACCESS_KEY_FORM_STORAGE, ACCESS_KEY_FALLBACK_STORAGE]) {
      const value = window.localStorage.getItem(key);
      if (value !== null) legacyMirrorAtBoot[key] = value;
    }
  } catch { /* Native state remains available when a mirror is inaccessible. */ }
}
let bootstrapState: Promise<void> | null = null;
// A failed initial native restore cannot authorize the 0.13.76 autosave effects
// to replace durable values with render defaults. Restart/recovery reloads them.
let nativeRestoreFailed = false;

function validateNativeSettings(value: unknown): void {
  // A genuinely missing legacy preference can use the documented migration.
  // A present invalid policy must never become ALL while retaining autoconnect.
  if (value === undefined) return;
  const settings = value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
  if (!settings || settings.tunRoutingModeInvalid === true
    || (Object.prototype.hasOwnProperty.call(settings, 'tunRoutingMode')
      && (typeof settings.tunRoutingMode !== 'string'
        || !['all', 'selected', 'exclude'].includes(settings.tunRoutingMode)))) {
    throw new NativeStorageError('STATE_SETTINGS_INVALID', 'Сохранённая политика TUN недопустима. Автозапуск и сохранение заблокированы; оригиналы сохранены.', false);
  }
}

function initializeNativeState(): Promise<void> {
  if (!bootstrapState) {
    bootstrapState = (async () => {
      const current = await readNativeState();
      validateNativeSettings(current.payload.public[NATIVE_SETTINGS_KEY]);
      if (legacyMirrorAtBoot && Object.keys(legacyMirrorAtBoot).length && current.payload.legacyWebView === null) {
        // Retain the original mirror encrypted before any hydration/autosave
        // can replace it. It is evidence, never an automatic native override.
        await commitNativeChange('legacy', 'webView', legacyMirrorAtBoot);
      }
      legacyMirrorAtBoot = null;
    })().catch(error => { nativeRestoreFailed = true; throw error; });
  }
  return bootstrapState;
}


function safeLocalStorageSet(key: string, value: string) {
  if (typeof window === 'undefined') {
    return;
  }

  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Native storage is the source of truth in Tauri. Ignore broken localStorage
    // so a corrupted WebView profile does not break buttons/settings.
  }
}

function safeLocalStorageRemove(key: string) {
  if (typeof window === 'undefined') {
    return;
  }

  try {
    window.localStorage.removeItem(key);
  } catch {
    // Best effort cleanup only.
  }
}

const STORAGE_COMMAND_TIMEOUTS_MS: Record<string, number> = {
  save_client_state_value: 7000,
  load_client_state_value: 7000,
  clear_client_state_value: 7000,
  save_access_key_secure: 12000,
  load_access_key_secure: 9000,
  clear_access_key_secure: 9000,
  save_sensitive_client_state_value: 12000,
  load_sensitive_client_state_value: 9000,
  clear_sensitive_client_state_value: 9000
};

function storageTimeoutMessage(command: string, timeoutMs: number) {
  return `Локальная команда ${command} не ответила за ${Math.round(timeoutMs / 1000)} секунд.`;
}

function withStorageTimeout<T>(operation: Promise<T>, timeoutMs: number, command: string): Promise<T> {
  let timer: number | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = window.setTimeout(() => reject(new Error(storageTimeoutMessage(command, timeoutMs))), timeoutMs);
  });

  operation.catch(() => {
    // Поздняя ошибка после timeout не должна оставлять unhandled rejection.
  });

  return Promise.race([operation, timeoutPromise]).finally(() => {
    if (timer !== undefined) {
      window.clearTimeout(timer);
    }
  }) as Promise<T>;
}

async function invokeStorageRaw<T>(command: string, args: Record<string, unknown> = {}, expectedSession?: string): Promise<T> {
  await initializeNativeState();
  return invokeStateProtocol<T>(command, args, expectedSession);
}

async function invokeTauri<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  const timeoutMs = STORAGE_COMMAND_TIMEOUTS_MS[command] ?? 8000;
  try {
    return await withStorageTimeout(invokeStorageRaw<T>(command, args), timeoutMs, command);
  } catch (error) {
    // A renderer deadline is not cancellation of the still-running native read.
    // Its late success must never authorize queued render defaults.
    if (command.startsWith('load_')) nativeRestoreFailed = true;
    throw error;
  }
}

type PendingWrite = { command: string; args: Record<string, unknown>; session?: string };
// One active native IPC write and one latest pending value per known state key.
// A frontend timeout must never release the uncancellable native write lease.
const pendingWrites = new Map<string, PendingWrite>();
const writeFailures = new Map<string, NativeStorageError>();
const writeObservers = new Map<string, Promise<boolean>>();
let writeDrain: Promise<void> | null = null;
let writesQuiesced = false;

function reportStorageFailure(key: string, failure: NativeStorageError) {
  writeFailures.set(key, failure);
  if (typeof CustomEvent !== 'undefined' && typeof window.dispatchEvent === 'function') {
    window.dispatchEvent(new CustomEvent('vkarmani:storage-error', { detail: failure }));
  }
}

function queueStateWrite(key: string, command: string, args: Record<string, unknown>): Promise<boolean> {
  if (writesQuiesced || nativeRestoreFailed) return Promise.resolve(false);
  const profileWrite = key === 'protected/lastKnownServers' || key === 'public/lastKnownServers';
  pendingWrites.set(key, { command, args, session: profileWrite ? peekNativeState()?.payload.sessionGeneration : undefined });
  if (!writeDrain) {
    writeDrain = (async () => {
      try {
        while (pendingWrites.size) {
          const [nextKey, write] = pendingWrites.entries().next().value!;
          pendingWrites.delete(nextKey);
          try {
            await invokeStorageRaw(write.command, write.args, write.session);
            writeFailures.delete(nextKey);
          } catch (error) {
            const failure = storageFailure(error);
            if (failure.code === 'STATE_SESSION_CHANGED') writeFailures.delete(nextKey);
            else reportStorageFailure(nextKey, failure);
          }
        }
      } finally {
        writeDrain = null;
        writeObservers.clear();
      }
    })();
  }
  // Reuse one deadline observer per key, including its settled timeout result.
  // A stalled native IPC must not retain a new uncancellable Promise callback
  // for every subsequent settings edit.
  const existing = writeObservers.get(key);
  if (existing) return existing;
  const observedDrain = writeDrain;
  const observer = withStorageTimeout(observedDrain, STORAGE_COMMAND_TIMEOUTS_MS[command] ?? 8000, command)
    .then(() => !writeFailures.has(key), () => {
      if (writeDrain === observedDrain) {
        reportStorageFailure(key, new NativeStorageError('STATE_WRITE_PENDING', 'Сохранение ещё не подтверждено. Дождитесь завершения перед выходом.'));
      }
      return false;
    });
  writeObservers.set(key, observer);
  return observer;
}

export async function flushPersistentWrites(): Promise<void> {
  if (nativeRestoreFailed) throw new NativeStorageError('STATE_RESTORE_BLOCKED', 'Исходное состояние не загружено; сохранение заблокировано.', false);
  const deadline = performance.now() + 12000;
  while (writeDrain) {
    const remaining = deadline - performance.now();
    if (remaining <= 0) throw new NativeStorageError('STATE_WRITE_PENDING', 'Сохранение состояния ещё не завершено.');
    try {
      await withStorageTimeout(writeDrain, remaining, 'flush-state');
    } catch (error) {
      throw storageFailure(error);
    }
  }
  const failure = writeFailures.values().next().value;
  if (failure) throw failure;
}

export async function quiescePersistentWrites() {
  writesQuiesced = true;
  await flushPersistentWrites();
  const current = await readNativeState();
  return { generation: current.generation, revision: current.revision };
}
export function resumePersistentWrites() { writesQuiesced = false; }

export async function loadPersistentSnapshot() {
  await initializeNativeState();
  const native = await readNativeState();
  const values = native.payload.public;
  const entries = normalizeCompatibleRules(values[NATIVE_SPLIT_TUNNEL_KEY]);
  const favorites = values[NATIVE_FAVORITES_KEY];
  return {
    settings: normalizeStoredSettings(
      Object.prototype.hasOwnProperty.call(values, NATIVE_SETTINGS_KEY) && values[NATIVE_SETTINGS_KEY] === null
        ? { tunRoutingModeInvalid: true } : values[NATIVE_SETTINGS_KEY], entries.length > 0),
    entries,
    favorites: Array.isArray(favorites) ? [...new Set(favorites.map(value => String(value ?? '').trim()).filter(Boolean))] : [],
    selected: typeof values[NATIVE_SELECTED_SERVER_KEY] === 'string' ? String(values[NATIVE_SELECTED_SERVER_KEY]).trim() : ''
  };
}

// User-confirmed reload/recovery, never an automatic conflict rebase.
export async function inspectPersistentRecovery() {
  const current = await inspectNativeState(true);
  return { readOnly: current.readOnly, token: current.recoveryToken };
}

export async function reloadPersistentSnapshot(confirmedRecoveryToken?: string) {
  writesQuiesced = true;
  try {
    pendingWrites.clear();
    if (writeDrain) await withStorageTimeout(writeDrain, 12000, 'reload-state');
    const current = await inspectNativeState(true);
    if (confirmedRecoveryToken !== undefined) {
      await recoverNativeState(confirmedRecoveryToken);
    } else if (current.readOnly) {
      throw new NativeStorageError('STATE_RECOVERY_REQUIRED', 'Доступна резервная копия. Перечитывание не разрешает её восстановление; требуется отдельное подтверждение.', false);
    }
    bootstrapState = null;
    await initializeNativeState();
    const restored = await loadPersistentSnapshot();
    writeFailures.clear();
    nativeRestoreFailed = false;
    return restored;
  } finally { writesQuiesced = false; }
}
export async function prepareLegacyRollbackExport() {
  await flushPersistentWrites();
  return exportNativeStateLegacy();
}

async function saveNativeClientStateValue(key: string, value: unknown): Promise<boolean> {
  if (!canUseTauriSecureStorage) {
    return false;
  }

  try {
    return await queueStateWrite('public/' + key, 'save_client_state_value', {
      key,
      value: JSON.stringify(value)
    });
  } catch {
    return false;
  }
}

async function loadNativeClientStateValue<T>(key: string): Promise<T | null> {
  if (!canUseTauriSecureStorage) {
    return null;
  }

  try {
    const rawValue = await invokeTauri<string | null>('load_client_state_value', { key });
    if (!rawValue) {
      return null;
    }

    return JSON.parse(rawValue) as T;
  } catch (error) {
    throw storageFailure(error);
  }
}

async function saveNativeSensitiveClientStateValue(key: string, value: unknown): Promise<boolean> {
  if (!canUseTauriSecureStorage) {
    return false;
  }

  try {
    return await queueStateWrite('protected/' + key, 'save_sensitive_client_state_value', {
      key,
      value: JSON.stringify(value)
    });
  } catch {
    return false;
  }
}

async function loadNativeSensitiveClientStateValue<T>(key: string): Promise<T | null> {
  if (!canUseTauriSecureStorage) {
    return null;
  }

  try {
    const rawValue = await invokeTauri<string | null>('load_sensitive_client_state_value', { key });
    if (!rawValue) {
      return null;
    }

    return JSON.parse(rawValue) as T;
  } catch (error) {
    throw storageFailure(error);
  }
}

async function clearNativeSensitiveClientStateValue(key: string): Promise<boolean> {
  if (!canUseTauriSecureStorage) {
    return false;
  }

  try {
    return await queueStateWrite('protected/' + key, 'clear_sensitive_client_state_value', { key });
  } catch {
    return false;
  }
}

function parseStoredAccessKey(value: string | null) {
  if (!value) {
    return '';
  }

  try {
    const parsed = JSON.parse(value) as unknown;
    return typeof parsed === 'string' ? parsed.trim() : value.trim();
  } catch {
    return value.trim();
  }
}

function readFallbackAccessKeyPayload(value: string | null) {
  if (!value) {
    return '';
  }

  try {
    const parsed = JSON.parse(value) as unknown;
    if (parsed && typeof parsed === 'object' && 'value' in parsed) {
      const candidate = (parsed as { value?: unknown }).value;
      return typeof candidate === 'string' ? candidate.trim() : '';
    }
  } catch {
    return parseStoredAccessKey(value);
  }

  return parseStoredAccessKey(value);
}

function loadLegacyAccessKeyFromLocalStorage() {
  if (typeof window === 'undefined') {
    return '';
  }

  try {
    const values = [
      readFallbackAccessKeyPayload(window.localStorage.getItem(ACCESS_KEY_FALLBACK_STORAGE)),
      parseStoredAccessKey(window.localStorage.getItem(ACCESS_KEY_FORM_STORAGE)),
      parseStoredAccessKey(window.localStorage.getItem(ACCESS_KEY_STORAGE))
    ];

    return values.find((value) => value.trim()) ?? '';
  } catch {
    return '';
  }
}

function saveLegacyAccessKeyToLocalStorage(value: string) {
  if (typeof window === 'undefined') {
    return;
  }

  const normalized = value.trim();
  if (!normalized) {
    return;
  }

  try {
    window.localStorage.setItem(ACCESS_KEY_STORAGE, normalized);
    window.localStorage.setItem(ACCESS_KEY_FORM_STORAGE, JSON.stringify(normalized));
    window.localStorage.setItem(ACCESS_KEY_FALLBACK_STORAGE, JSON.stringify({
      version: 1,
      value: normalized,
      savedAt: new Date().toISOString(),
      reason: 'web-preview-storage'
    }));
  } catch {
    // localStorage can be unavailable in rare locked-down WebView profiles.
  }
}

function clearLegacyAccessKeyFromLocalStorage() {
  if (typeof window === 'undefined') {
    return;
  }

  try {
    window.localStorage.removeItem(ACCESS_KEY_STORAGE);
    window.localStorage.removeItem(ACCESS_KEY_FORM_STORAGE);
    window.localStorage.removeItem(ACCESS_KEY_FALLBACK_STORAGE);
  } catch {
    // ignore localStorage cleanup errors
  }
}

function canUseWebPreviewAccessKeyStorage() {
  return !canUseTauriSecureStorage && import.meta.env.DEV;
}

export function loadStoredAccessKey() {
  if (canUseTauriSecureStorage) {
    // Never prefill the field from plaintext WebView storage in the native app.
    // loadStoredAccessKeySecure() will migrate old values into DPAPI and remove them.
    return '';
  }

  return canUseWebPreviewAccessKeyStorage() ? loadLegacyAccessKeyFromLocalStorage() : '';
}

export async function loadStoredAccessKeySecure() {
  const legacyValue = canUseTauriSecureStorage ? '' : loadLegacyAccessKeyFromLocalStorage().trim();

  if (!canUseTauriSecureStorage) {
    return canUseWebPreviewAccessKeyStorage() ? legacyValue : '';
  }

  try {
    const stored = await invokeTauri<string | null>('load_access_key_secure');
    if (stored?.trim()) {
      clearLegacyAccessKeyFromLocalStorage();
      return stored.trim();
    }
  } catch (error) {
    // An unreadable authoritative file must not be replaced by a stale WebView
    // credential or mistaken for an invalid subscription. Keep the legacy
    // original until an explicit, successful protected migration can occur.
    throw storageFailure(error);
  }

  if (legacyValue) {
    if (!await queueStateWrite('access-key', 'save_access_key_secure', { value: legacyValue })) {
      throw new NativeStorageError('STATE_MIGRATION_FAILED', 'Не удалось завершить перенос ключа в защищённое хранилище.');
    }
    clearLegacyAccessKeyFromLocalStorage();
    return legacyValue;
  }

  clearLegacyAccessKeyFromLocalStorage();
  return '';
}

export async function saveStoredAccessKey(value: string): Promise<boolean> {
  const normalized = value.trim();
  if (!normalized) {
    await clearStoredAccessKey();
    return true;
  }

  if (canUseTauriSecureStorage) {
    try {
      const persisted = await queueStateWrite('access-key', 'save_access_key_secure', { value: normalized });
      if (persisted) clearLegacyAccessKeyFromLocalStorage();
      return persisted;
    } catch {
      // Do not block the active login session if DPAPI is temporarily unavailable.
      // The key simply will not be persisted instead of falling back to plaintext storage.
      return false;
    }
  }

  if (canUseWebPreviewAccessKeyStorage()) {
    saveLegacyAccessKeyToLocalStorage(normalized);
    return true;
  }

  return false;
}

export async function clearStoredAccessKey() {
  if (canUseTauriSecureStorage) {
    if (!await queueStateWrite('access-key', 'clear_access_key_secure', {})) {
      throw new NativeStorageError('STATE_CLEAR_FAILED', 'Не удалось удалить сохранённый ключ. Выход не завершён.');
    }
  }

  clearLegacyAccessKeyFromLocalStorage();
}

export function loadSettings() {
  if (canUseTauriSecureStorage) return { ...defaultSettings };
  if (typeof window === 'undefined') {
    return defaultSettings;
  }

  try {
    const rawValue = window.localStorage.getItem(SETTINGS_STORAGE);
    if (rawValue === null) {
      return normalizeStoredSettings(null, loadSplitTunnelEntries().length > 0);
    }

    const parsed: unknown = JSON.parse(rawValue);
    return normalizeStoredSettings(parsed === null ? { tunRoutingModeInvalid: true } : parsed, loadSplitTunnelEntries().length > 0);
  } catch {
    // Unreadable/present corrupt state is not an empty first-run profile.
    // Keep the original bytes and require an explicit TUN policy choice.
    return normalizeStoredSettings({ tunRoutingModeInvalid: true });
  }
}

export function saveSettings(value: AppSettings) {
  safeLocalStorageSet(SETTINGS_STORAGE, JSON.stringify(value));

  void saveNativeClientStateValue(NATIVE_SETTINGS_KEY, value);
}

export async function loadSettingsBackup() {
  const value = await loadNativeClientStateValue<unknown>(NATIVE_SETTINGS_KEY);
  const entries = await loadNativeClientStateValue<unknown>(NATIVE_SPLIT_TUNNEL_KEY);
  const hasLegacyRules = normalizeStoredRules(entries).length > 0;
  return value !== null && value !== undefined || hasLegacyRules ? normalizeStoredSettings(value, hasLegacyRules) : null;
}

export function loadSplitTunnelEntries() {
  if (canUseTauriSecureStorage) return [] as SplitTunnelEntry[];
  if (typeof window === 'undefined') {
    return [] as SplitTunnelEntry[];
  }

  try {
    const rawValue = window.localStorage.getItem(SPLIT_TUNNEL_STORAGE);
    if (!rawValue) {
      return [] as SplitTunnelEntry[];
    }

    try { return normalizeStoredRules(JSON.parse(rawValue) as unknown); }
    catch { return normalizeStoredRules(rawValue); }
  } catch {
    return [] as SplitTunnelEntry[];
  }
}

export function saveSplitTunnelEntries(value: SplitTunnelEntry[]) {
  safeLocalStorageSet(SPLIT_TUNNEL_STORAGE, JSON.stringify(value));

  void saveNativeClientStateValue(NATIVE_SPLIT_TUNNEL_KEY, value);
}

function normalizeCompatibleRules(value: unknown): SplitTunnelEntry[] {
  const entries = normalizeStoredRules(value);
  if (!Array.isArray(value)) return entries;
  // The076 editor knows only its own rule fields. Retain newer metadata on the
  // same rule so hydration/autosave cannot silently strip it from v2.
  return entries.map((entry, index) => {
    const original: unknown = value[index];
    return original && typeof original === 'object' && !Array.isArray(original)
      ? { ...original, ...entry } : entry;
  });
}

export async function loadSplitTunnelEntriesBackup() {
  const value = await loadNativeClientStateValue<unknown>(NATIVE_SPLIT_TUNNEL_KEY);
  return value === null || value === undefined ? null : normalizeCompatibleRules(value);
}


export function loadFavoriteServerIds() {
  if (canUseTauriSecureStorage) return [] as string[];
  if (typeof window === 'undefined') {
    return [] as string[];
  }

  try {
    const rawValue = window.localStorage.getItem(FAVORITE_SERVERS_STORAGE);
    const parsed = rawValue ? JSON.parse(rawValue) as unknown : [];
    if (!Array.isArray(parsed)) {
      return [] as string[];
    }
    return [...new Set(parsed.map((value) => String(value ?? '').trim()).filter(Boolean))];
  } catch {
    return [] as string[];
  }
}

export function saveFavoriteServerIds(value: string[]) {
  const normalized = [...new Set(value.map((item) => item.trim()).filter(Boolean))];
  safeLocalStorageSet(FAVORITE_SERVERS_STORAGE, JSON.stringify(normalized));

  void saveNativeClientStateValue(NATIVE_FAVORITES_KEY, normalized);
}

export async function loadFavoriteServerIdsBackup() {
  const value = await loadNativeClientStateValue<unknown>(NATIVE_FAVORITES_KEY);
  if (!Array.isArray(value)) {
    return null;
  }

  return [...new Set(value.map((item) => String(item ?? '').trim()).filter(Boolean))];
}

export function loadSelectedServerId() {
  if (canUseTauriSecureStorage) return '';
  if (typeof window === 'undefined') {
    return '';
  }

  try {
    return window.localStorage.getItem(SELECTED_SERVER_STORAGE)?.trim() ?? '';
  } catch {
    return '';
  }
}

export function saveSelectedServerId(value: string) {
  const normalized = value.trim();
  if (normalized) {
    safeLocalStorageSet(SELECTED_SERVER_STORAGE, normalized);
  } else {
    safeLocalStorageRemove(SELECTED_SERVER_STORAGE);
  }

  void saveNativeClientStateValue(NATIVE_SELECTED_SERVER_KEY, normalized);
}

export async function loadSelectedServerIdBackup() {
  const value = await loadNativeClientStateValue<unknown>(NATIVE_SELECTED_SERVER_KEY);
  return typeof value === 'string' ? value.trim() : null;
}


async function saveProtectedProfiles(servers: VpnServer[]) {
  try {
    return await saveNativeSensitiveClientStateValue(NATIVE_LAST_KNOWN_SERVERS_KEY, encodeProfileCache(servers));
  } catch {
    // Cache/serialization failure is not a subscription rejection. Preserve
    // the last atomic DPAPI file; do not turn a usable in-memory profile invalid.
    console.warn('[storage] Protected profile cache was not saved.');
    return false;
  }
}

let profileCacheEpoch = 0;
function assertProfileCacheEpoch(epoch: number) {
  if (epoch !== profileCacheEpoch) {
    throw new NativeStorageError('STATE_OPERATION_CANCELLED', 'Восстановление кэша отменено после очистки сессии.');
  }
}

export function loadLastKnownServers() {
  if (canUseTauriSecureStorage) return [] as VpnServer[];
  if (typeof window === 'undefined') {
    return [] as VpnServer[];
  }

  try {
    const rawValue = window.localStorage.getItem(LAST_KNOWN_SERVERS_STORAGE);
    const normalized = rawValue ? normalizeStoredServers(JSON.parse(rawValue) as unknown) : [] as VpnServer[];
    const safeServers = stripSensitiveServerRuntimeList(normalized);

    // Render-time reads do not mutate legacy originals. The async restore
    // confirms DPAPI persistence before retiring a plaintext migration source.
    return safeServers;
  } catch {
    return [] as VpnServer[];
  }
}

export function saveLastKnownServers(value: VpnServer[]) {
  const normalized = normalizeStoredServers(value);
  if (!normalized.length) {
    return;
  }

  const safeServers = stripSensitiveServerRuntimeList(normalized);

  // Открытый localStorage/client-state хранит только UI-метаданные серверов.
  // Полный runtimeTemplate/rawUri нужен для подключения и сохраняется только
  // в защищённом native DPAPI-кэше через save_sensitive_client_state_value.
  safeLocalStorageSet(LAST_KNOWN_SERVERS_STORAGE, JSON.stringify(safeServers));
  void saveNativeClientStateValue(NATIVE_LAST_KNOWN_SERVERS_KEY, safeServers);
  void saveProtectedProfiles(normalized);
}

export async function loadLastKnownServersBackup() {
  const epoch = profileCacheEpoch;
  const secureValue = await loadNativeSensitiveClientStateValue<unknown>(NATIVE_LAST_KNOWN_SERVERS_KEY);
  assertProfileCacheEpoch(epoch);
  let secureNormalized: VpnServer[] = [];
  if (secureValue) {
    try { secureNormalized = normalizeStoredServers(decodeProfileCache(secureValue)); }
    catch { throw new NativeStorageError('STATE_CORRUPT', 'Защищённый кэш профилей повреждён. Оригинал сохранён.', false); }
  }
  if (secureNormalized.length) {
    return secureNormalized;
  }

  const value = await loadNativeClientStateValue<unknown>(NATIVE_LAST_KNOWN_SERVERS_KEY);
  assertProfileCacheEpoch(epoch);
  const nativeNormalized = normalizeStoredServers(value);
  if (!nativeNormalized.length) {
    return null;
  }

  const nativeSafeServers = stripSensitiveServerRuntimeList(nativeNormalized);
  if (nativeNormalized.some((server) => server.runtimeTemplate || server.rawUri)) {
    if (!await saveProtectedProfiles(nativeNormalized)) {
      throw new NativeStorageError('STATE_MIGRATION_FAILED', 'Кэш профилей не перенесён в защищённое хранилище. Оригинал сохранён.');
    }
    assertProfileCacheEpoch(epoch);
    if (!await saveNativeClientStateValue(NATIVE_LAST_KNOWN_SERVERS_KEY, nativeSafeServers)) {
      throw new NativeStorageError('STATE_MIGRATION_FAILED', 'Защищённая копия сохранена; очистка старого кэша не завершена.');
    }
    assertProfileCacheEpoch(epoch);
    safeLocalStorageSet(LAST_KNOWN_SERVERS_STORAGE, JSON.stringify(nativeSafeServers));
    return nativeNormalized;
  }

  return nativeSafeServers.length ? nativeSafeServers : null;
}

export async function clearLastKnownServers() {
  profileCacheEpoch++;
  if (canUseTauriSecureStorage) {
    const publicCleared = await queueStateWrite('public/' + NATIVE_LAST_KNOWN_SERVERS_KEY, 'clear_client_state_value', { key: NATIVE_LAST_KNOWN_SERVERS_KEY });
    const protectedCleared = await clearNativeSensitiveClientStateValue(NATIVE_LAST_KNOWN_SERVERS_KEY);
    if (!publicCleared || !protectedCleared) {
      throw new NativeStorageError('STATE_CLEAR_FAILED', 'Не удалось полностью очистить кэш профилей. Выход не завершён.');
    }
  }
  safeLocalStorageRemove(LAST_KNOWN_SERVERS_STORAGE);
}
