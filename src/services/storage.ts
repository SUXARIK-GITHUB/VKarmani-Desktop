import type { AppSettings, SplitTunnelEntry } from '../types/vpn';
import { defaultRoutingExclusions, sanitizeRoutingExclusions } from '../utils/routingExclusions';

const ACCESS_KEY_STORAGE = 'vkarmani.access-key';
const ACCESS_KEY_FORM_STORAGE = 'vkarmani.form.access-key';
const ACCESS_KEY_FALLBACK_STORAGE = 'vkarmani.access-key.fallback-v1';
const SETTINGS_STORAGE = 'vkarmani.settings';
const SPLIT_TUNNEL_STORAGE = 'vkarmani.split-tunnel.entries';
const FAVORITE_SERVERS_STORAGE = 'vkarmani.servers.favorites';
const SELECTED_SERVER_STORAGE = 'vkarmani.servers.selected';
const NATIVE_SETTINGS_KEY = 'settings';
const NATIVE_SPLIT_TUNNEL_KEY = 'splitTunnelEntries';
const NATIVE_FAVORITES_KEY = 'favoriteServerIds';
const NATIVE_SELECTED_SERVER_KEY = 'selectedServerId';

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

function normalizeStoredSettings(value: unknown): AppSettings {
  if (!value || typeof value !== 'object') {
    return defaultSettings;
  }

  const candidate = value as Partial<AppSettings>;
  const booleanKeys: Array<keyof Omit<AppSettings, 'releaseChannel' | 'protocolStrategy' | 'language' | 'tunnelMode' | 'ipStack' | 'routingExclusions'>> = [
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
    'profileSyncOnLogin',
    'allowDemoFallback',
    'useSystemProxy',
    'probeOnConnect'
  ];

  const next: AppSettings = { ...defaultSettings };

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

const tauriWindow = typeof window !== 'undefined'
  ? (window as Window & { __TAURI_INTERNALS__?: unknown; __TAURI__?: unknown })
  : undefined;

const canUseTauriSecureStorage = Boolean(
  tauriWindow && (tauriWindow.__TAURI_INTERNALS__ || tauriWindow.__TAURI__)
);


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
  clear_access_key_secure: 9000
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

async function invokeTauri<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  const { invoke } = await import('@tauri-apps/api/core');
  const timeoutMs = STORAGE_COMMAND_TIMEOUTS_MS[command] ?? 8000;
  return withStorageTimeout(invoke<T>(command, args), timeoutMs, command);
}

async function saveNativeClientStateValue(key: string, value: unknown): Promise<boolean> {
  if (!canUseTauriSecureStorage) {
    return false;
  }

  try {
    await invokeTauri('save_client_state_value', {
      key,
      value: JSON.stringify(value)
    });
    return true;
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
  } catch {
    return null;
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
  const legacyValue = loadLegacyAccessKeyFromLocalStorage().trim();

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
    // If an old plaintext value exists, allow this session to recover it once,
    // but remove it immediately so the native app does not keep secrets in localStorage.
    if (legacyValue) {
      clearLegacyAccessKeyFromLocalStorage();
      return legacyValue;
    }

    throw error;
  }

  if (legacyValue) {
    try {
      await invokeTauri('save_access_key_secure', { value: legacyValue });
    } finally {
      clearLegacyAccessKeyFromLocalStorage();
    }

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
      await invokeTauri('save_access_key_secure', { value: normalized });
      return true;
    } catch {
      // Do not block the active login session if DPAPI is temporarily unavailable.
      // The key simply will not be persisted instead of falling back to plaintext storage.
      return false;
    } finally {
      // DPAPI is the only persistent storage for secrets in the native app.
      clearLegacyAccessKeyFromLocalStorage();
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
    try {
      await invokeTauri('clear_access_key_secure');
    } catch {
      // Clear local fallback anyway; secure storage can be repaired on next save.
    }
  }

  clearLegacyAccessKeyFromLocalStorage();
}

export function loadSettings() {
  if (typeof window === 'undefined') {
    return defaultSettings;
  }

  try {
    const rawValue = window.localStorage.getItem(SETTINGS_STORAGE);
    if (!rawValue) {
      return defaultSettings;
    }

    return normalizeStoredSettings(JSON.parse(rawValue) as unknown);
  } catch {
    return defaultSettings;
  }
}

export function saveSettings(value: AppSettings) {
  safeLocalStorageSet(SETTINGS_STORAGE, JSON.stringify(value));

  void saveNativeClientStateValue(NATIVE_SETTINGS_KEY, value);
}

export async function loadSettingsBackup() {
  const value = await loadNativeClientStateValue<unknown>(NATIVE_SETTINGS_KEY);
  return value ? normalizeStoredSettings(value) : null;
}

export function loadSplitTunnelEntries() {
  if (typeof window === 'undefined') {
    return [] as SplitTunnelEntry[];
  }

  try {
    const rawValue = window.localStorage.getItem(SPLIT_TUNNEL_STORAGE);
    if (!rawValue) {
      return [] as SplitTunnelEntry[];
    }

    const parsed = JSON.parse(rawValue) as unknown;
    if (!Array.isArray(parsed)) {
      return [] as SplitTunnelEntry[];
    }

    return parsed
      .filter((entry): entry is SplitTunnelEntry => Boolean(
        entry
        && typeof entry === 'object'
        && 'id' in entry
        && 'kind' in entry
        && 'value' in entry
        && 'enabled' in entry
      ))
      .map((entry: SplitTunnelEntry) => ({
        id: String(entry.id),
        kind: (entry.kind === 'service' ? 'service' : 'app') as SplitTunnelEntry['kind'],
        value: String(entry.value ?? '').trim(),
        enabled: Boolean(entry.enabled)
      }))
      .filter((entry) => Boolean(entry.value));
  } catch {
    return [] as SplitTunnelEntry[];
  }
}

export function saveSplitTunnelEntries(value: SplitTunnelEntry[]) {
  safeLocalStorageSet(SPLIT_TUNNEL_STORAGE, JSON.stringify(value));

  void saveNativeClientStateValue(NATIVE_SPLIT_TUNNEL_KEY, value);
}

export async function loadSplitTunnelEntriesBackup() {
  const value = await loadNativeClientStateValue<unknown>(NATIVE_SPLIT_TUNNEL_KEY);
  if (!Array.isArray(value)) {
    return null;
  }

  return value
    .filter((entry): entry is SplitTunnelEntry => Boolean(
      entry
      && typeof entry === 'object'
      && 'id' in entry
      && 'kind' in entry
      && 'value' in entry
      && 'enabled' in entry
    ))
    .map((entry: SplitTunnelEntry) => ({
      id: String(entry.id),
      kind: (entry.kind === 'service' ? 'service' : 'app') as SplitTunnelEntry['kind'],
      value: String(entry.value ?? '').trim(),
      enabled: Boolean(entry.enabled)
    }))
    .filter((entry) => Boolean(entry.value));
}


export function loadFavoriteServerIds() {
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
