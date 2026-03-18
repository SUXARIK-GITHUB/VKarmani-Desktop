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

export function loadStoredAccessKey() {
  if (typeof window === 'undefined') {
    return '';
  }

  return parseStoredAccessKey(window.localStorage.getItem(ACCESS_KEY_FORM_STORAGE)) || parseStoredAccessKey(window.localStorage.getItem(ACCESS_KEY_STORAGE));
}

export function saveStoredAccessKey(value: string) {
  if (typeof window === 'undefined') {
    return;
  }

  window.localStorage.setItem(ACCESS_KEY_STORAGE, value);
  window.localStorage.setItem(ACCESS_KEY_FORM_STORAGE, JSON.stringify(value));
}

export function clearStoredAccessKey() {
  if (typeof window === 'undefined') {
    return;
  }

  window.localStorage.removeItem(ACCESS_KEY_STORAGE);
  window.localStorage.removeItem(ACCESS_KEY_FORM_STORAGE);
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
