import type { AppSettings, SplitTunnelEntry } from '../types/vpn';

const ACCESS_KEY_STORAGE = 'vkarmani.access-key';
const ACCESS_KEY_FORM_STORAGE = 'vkarmani.form.access-key';
const SETTINGS_STORAGE = 'vkarmani.settings';
const SPLIT_TUNNEL_STORAGE = 'vkarmani.split-tunnel.entries';

export const defaultSettings: AppSettings = {
  launchOnStartup: true,
  runAsAdmin: false,
  showDiagnostics: false,
  autoConnect: false,
  minimizeToTray: true,
  notifications: true,
  autoUpdate: true,
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
    return typeof parsed === 'string' ? parsed : value;
  } catch {
    return value;
  }
}

function loadLegacyAccessKeyFromLocalStorage() {
  if (typeof window === 'undefined') {
    return '';
  }

  return parseStoredAccessKey(window.localStorage.getItem(ACCESS_KEY_FORM_STORAGE)) || parseStoredAccessKey(window.localStorage.getItem(ACCESS_KEY_STORAGE));
}

function clearLegacyAccessKeyFromLocalStorage() {
  if (typeof window === 'undefined') {
    return;
  }

  window.localStorage.removeItem(ACCESS_KEY_STORAGE);
  window.localStorage.removeItem(ACCESS_KEY_FORM_STORAGE);
}

export function loadStoredAccessKey() {
  return canUseTauriSecureStorage ? '' : loadLegacyAccessKeyFromLocalStorage();
}

export async function loadStoredAccessKeySecure() {
  if (!canUseTauriSecureStorage) {
    return loadLegacyAccessKeyFromLocalStorage();
  }

  const stored = await invokeTauri<string | null>('load_access_key_secure');
  if (stored?.trim()) {
    clearLegacyAccessKeyFromLocalStorage();
    return stored;
  }

  const legacy = loadLegacyAccessKeyFromLocalStorage();
  if (legacy.trim()) {
    await saveStoredAccessKey(legacy);
    clearLegacyAccessKeyFromLocalStorage();
    return legacy;
  }

  clearLegacyAccessKeyFromLocalStorage();
  return '';
}

export async function saveStoredAccessKey(value: string) {
  const normalized = value.trim();
  if (!normalized) {
    await clearStoredAccessKey();
    return;
  }

  if (canUseTauriSecureStorage) {
    await invokeTauri('save_access_key_secure', { value: normalized });
    clearLegacyAccessKeyFromLocalStorage();
    return;
  }

  if (typeof window !== 'undefined') {
    window.localStorage.setItem(ACCESS_KEY_STORAGE, normalized);
    window.localStorage.setItem(ACCESS_KEY_FORM_STORAGE, JSON.stringify(normalized));
  }
}

export async function clearStoredAccessKey() {
  if (canUseTauriSecureStorage) {
    await invokeTauri('clear_access_key_secure');
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

    return { ...defaultSettings, ...(JSON.parse(rawValue) as Partial<AppSettings>) };
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
