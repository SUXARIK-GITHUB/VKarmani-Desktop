import type { AppSettings, SplitTunnelEntry } from '../types/vpn';

const ACCESS_KEY_STORAGE = 'vkarmani.access-key';
const ACCESS_KEY_FORM_STORAGE = 'vkarmani.form.access-key';
const ACCESS_KEY_FALLBACK_STORAGE = 'vkarmani.access-key.fallback-v1';
const SETTINGS_STORAGE = 'vkarmani.settings';
const SPLIT_TUNNEL_STORAGE = 'vkarmani.split-tunnel.entries';

export const defaultSettings: AppSettings = {
  launchOnStartup: false,
  runAsAdmin: false,
  showDiagnostics: false,
  autoConnect: false,
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
  language: 'ru'
};

function normalizeStoredSettings(value: unknown): AppSettings {
  if (!value || typeof value !== 'object') {
    return defaultSettings;
  }

  const candidate = value as Partial<AppSettings>;
  const booleanKeys: Array<keyof Omit<AppSettings, 'releaseChannel' | 'protocolStrategy' | 'language' | 'tunnelMode'>> = [
    'launchOnStartup',
    'runAsAdmin',
    'showDiagnostics',
    'autoConnect',
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

  if (candidate.releaseChannel === 'stable' || candidate.releaseChannel === 'beta') {
    next.releaseChannel = candidate.releaseChannel;
  }

  if (candidate.protocolStrategy === 'auto' || candidate.protocolStrategy === 'reality-first' || candidate.protocolStrategy === 'xray-only') {
    next.protocolStrategy = candidate.protocolStrategy;
  }

  if (candidate.tunnelMode === 'proxy' || candidate.tunnelMode === 'tun') {
    next.tunnelMode = candidate.tunnelMode;
  }

  if (candidate.language === 'ru' || candidate.language === 'en') {
    next.language = candidate.language;
  }

  return next;
}

const tauriWindow = typeof window !== 'undefined'
  ? (window as Window & { __TAURI_INTERNALS__?: unknown; __TAURI__?: unknown })
  : undefined;

const canUseTauriSecureStorage = Boolean(
  tauriWindow && (tauriWindow.__TAURI_INTERNALS__ || tauriWindow.__TAURI__)
);

async function invokeTauri<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  const { invoke } = await import('@tauri-apps/api/core');
  return invoke<T>(command, args);
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

  const values = [
    readFallbackAccessKeyPayload(window.localStorage.getItem(ACCESS_KEY_FALLBACK_STORAGE)),
    parseStoredAccessKey(window.localStorage.getItem(ACCESS_KEY_FORM_STORAGE)),
    parseStoredAccessKey(window.localStorage.getItem(ACCESS_KEY_STORAGE))
  ];

  return values.find((value) => value.trim()) ?? '';
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
      reason: canUseTauriSecureStorage ? 'secure-storage-backup' : 'web-storage'
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

export function loadStoredAccessKey() {
  return loadLegacyAccessKeyFromLocalStorage();
}

export async function loadStoredAccessKeySecure() {
  const fallback = loadLegacyAccessKeyFromLocalStorage();

  if (!canUseTauriSecureStorage) {
    return fallback;
  }

  try {
    const stored = await invokeTauri<string | null>('load_access_key_secure');
    if (stored?.trim()) {
      saveLegacyAccessKeyToLocalStorage(stored);
      return stored.trim();
    }
  } catch (error) {
    if (fallback.trim()) {
      return fallback.trim();
    }

    throw error;
  }

  if (fallback.trim()) {
    try {
      await invokeTauri('save_access_key_secure', { value: fallback.trim() });
    } catch {
      // The local fallback is intentionally kept so the user is not forced to paste the key again.
    }

    return fallback.trim();
  }

  return '';
}

export async function saveStoredAccessKey(value: string) {
  const normalized = value.trim();
  if (!normalized) {
    await clearStoredAccessKey();
    return;
  }

  // Save the fallback first. If DPAPI or the native bridge fails on a user's PC,
  // the key still survives restart and can be migrated back into secure storage later.
  saveLegacyAccessKeyToLocalStorage(normalized);

  if (canUseTauriSecureStorage) {
    try {
      await invokeTauri('save_access_key_secure', { value: normalized });
    } catch {
      // Do not break login because of secure-storage problems. The fallback above is enough to restore the session.
    }
  }
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
  if (typeof window === 'undefined') {
    return;
  }

  window.localStorage.setItem(SETTINGS_STORAGE, JSON.stringify(value));
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
  if (typeof window === 'undefined') {
    return;
  }

  window.localStorage.setItem(SPLIT_TUNNEL_STORAGE, JSON.stringify(value));
}
