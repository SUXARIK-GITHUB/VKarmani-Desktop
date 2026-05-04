import type {
  AppSettings,
  ConnectivityProbe,
  DiagnosticsSnapshot,
  ProfileSyncInfo,
  ProxyStatus,
  RemnawaveSession,
  RuntimeStatus,
  UpdateInfo
} from '../types/vpn';
import { redactSensitiveText } from './redaction';

export interface SafeDiagnosticsExportInput {
  appVersion: string;
  runtimeStatus: RuntimeStatus | null;
  proxyStatus: ProxyStatus;
  connectivityProbe: ConnectivityProbe | null;
  diagnostics: DiagnosticsSnapshot | null;
  profileSyncInfo: ProfileSyncInfo;
  updateInfo: UpdateInfo;
  settings: AppSettings;
  session: RemnawaveSession | null;
  nativeLogLines: string[];
}

function toSafeSettings(settings: AppSettings) {
  return {
    launchOnStartup: settings.launchOnStartup,
    runAsAdmin: settings.runAsAdmin,
    showDiagnostics: settings.showDiagnostics,
    autoConnect: settings.autoConnect,
    autoConnectFavorite: settings.autoConnectFavorite,
    minimizeToTray: settings.minimizeToTray,
    notifications: settings.notifications,
    autoUpdate: settings.autoUpdate,
    autoInstallUpdates: settings.autoInstallUpdates,
    releaseChannel: settings.releaseChannel,
    protocolStrategy: settings.protocolStrategy,
    profileSyncOnLogin: settings.profileSyncOnLogin,
    allowDemoFallback: settings.allowDemoFallback,
    useSystemProxy: settings.useSystemProxy,
    probeOnConnect: settings.probeOnConnect,
    tunnelMode: settings.tunnelMode,
    ipStack: settings.ipStack,
    language: settings.language,
    routingExclusions: {
      enabled: settings.routingExclusions.enabled,
      bypassRuDomains: settings.routingExclusions.bypassRuDomains,
      bypassSuDomains: settings.routingExclusions.bypassSuDomains,
      bypassRfDomains: settings.routingExclusions.bypassRfDomains,
      domainCount: settings.routingExclusions.domains.length,
      ipCount: settings.routingExclusions.ips.length
    }
  };
}

function toSafeSession(session: RemnawaveSession | null) {
  if (!session) {
    return null;
  }

  return {
    userId: session.userId,
    displayName: session.displayName,
    source: session.source,
    plan: session.plan,
    shortUuid: session.shortUuid ? '[redacted-uuid]' : undefined,
    subscriptionUrl: session.subscriptionUrl ? '[redacted-url]' : undefined
  };
}

export function createSafeDiagnosticsPayload(input: SafeDiagnosticsExportInput): string {
  const report = {
    generatedAt: new Date().toISOString(),
    privacyNotice: 'Ключи, токены, UUID и subscription URL скрываются автоматически. Отчёт может содержать технические данные устройства: версия Windows, имя устройства, HWID и runtime-пути для поддержки.',
    appVersion: input.appVersion,
    runtimeStatus: input.runtimeStatus,
    proxyStatus: input.proxyStatus,
    connectivityProbe: input.connectivityProbe,
    diagnostics: input.diagnostics,
    profileSyncInfo: {
      ...input.profileSyncInfo,
      rawUrl: input.profileSyncInfo.rawUrl ? '[redacted-url]' : undefined
    },
    updateInfo: input.updateInfo,
    settings: toSafeSettings(input.settings),
    session: toSafeSession(input.session),
    logs: [...(input.diagnostics?.logLines ?? []), ...input.nativeLogLines].slice(-160)
  };

  return redactSensitiveText(JSON.stringify(report, null, 2));
}

export function buildDiagnosticsFilename() {
  return `vkarmani-diagnostics-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
}

export function downloadTextFile(filename: string, payload: string, mimeType = 'application/json;charset=utf-8') {
  const blob = new Blob([payload], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
