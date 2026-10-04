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
    sortServersByPing: settings.sortServersByPing,
    tunRoutingMode: settings.tunRoutingMode,
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

/** Defense in depth for free text: known credentials plus context-aware patterns.
 * The bundle schema never includes account identity, credential objects or raw config. */
export function supportRedactor(session: RemnawaveSession | null) {
  const secrets = [session?.accessKey, session?.userId, session?.shortUuid, session?.subscriptionUrl, session?.loginHint].filter((v): v is string => Boolean(v && v.length >= 3));
  const variants = new Set<string>();
  for (const value of secrets) {
    variants.add(value); variants.add(encodeURIComponent(value));
    const bytes = new TextEncoder().encode(value);
    variants.add(btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join('')));
    try { const url = new URL(value); for (const part of url.pathname.split('/')) if(part.length >= 5) variants.add(decodeURIComponent(part)); } catch { /* Plain key. */ }
  }
  return (raw: unknown): string => {
    if (typeof raw !== 'string') return '';
    let value = raw.slice(0, 65536);
    for (const secret of Array.from(variants).sort((a,b)=>b.length-a.length)) value = value.split(secret).join('[redacted]');
    return redactSensitiveText(value)
      .replace(/(?:https?|wss?):\/\/[^\s"'<>`]+/gi, '[redacted-url]')
      .replace(/(?:authorization|cookie|set-cookie)\s*[:=]\s*[^\r\n]+/gi,'[redacted-header]')
      .replace(/\b(?:bearer|basic)\s+[^\s"'<>]+/gi,'[redacted-auth]')
      .replace(/(?:access[_-]?key|user[_-]?id|password|token|secret|credential)\s*["']?\s*[:=]\s*["']?[^\s,;"']+/gi,'[redacted-secret]').slice(0, 4096);
  };
}
export function createSafeDiagnosticsPayload(input: SafeDiagnosticsExportInput): string {
  const text = supportRedactor(input.session);
  const runtime = input.runtimeStatus;
  const operation = (op: RuntimeStatus['operation']) => op && ({id:op.id,kind:text(op.kind),stage:text(op.stage),startedAt:op.startedAt,deadlineAt:op.deadlineAt,outcome:text(op.outcome)});
  const report = {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    privacyNotice: 'Credential, account identity, URLs, raw config, headers, DPAPI plaintext and device identifiers are omitted. Logs are bounded and redacted.',
    appVersion: text(input.appVersion),
    runtime: runtime && {bridge:runtime.bridge,coreFound:runtime.coreInstalled,active:runtime.tunnelActive,mode:runtime.networkMode,pid:runtime.xrayPid,revision:runtime.runtimeRevision,configHash:runtime.runtimeConfigHash,operation:operation(runtime.operation),lastOperation:operation(runtime.lastOperation),proxyOwnership:text(runtime.proxyOwnership),routeOwnership:text(runtime.routeOwnership),ownedRouteCount:runtime.ownedRoutes?.length ?? 0,reconnectAttempt:runtime.reconnectAttempt,lastExitCode:runtime.lastExitCode},
    proxy: {enabled:input.proxyStatus.enabled,autoDetect:input.proxyStatus.autoDetect,hasPac:Boolean(input.proxyStatus.autoConfigUrl),method:input.proxyStatus.method},
    probe: input.connectivityProbe && {success:input.connectivityProbe.success,httpPortOpen:input.connectivityProbe.httpPortOpen,socksPortOpen:input.connectivityProbe.socksPortOpen,latencyMs:input.connectivityProbe.latencyMs,checkedAt:text(input.connectivityProbe.checkedAt),message:text(input.connectivityProbe.message)},
    subscription: {state:runtime?.subscriptionState ?? 'unconfirmed',source:input.session?.source,refreshAfter:runtime?.subscriptionRefreshAfter},
    profileSync: {status:input.profileSyncInfo.status,source:input.profileSyncInfo.source,configCount:input.profileSyncInfo.configCount,readyCount:input.profileSyncInfo.readyCount,message:text(input.profileSyncInfo.message)},
    update: {status:input.updateInfo.status,currentVersion:text(input.updateInfo.currentVersion),available:input.updateInfo.available,version:text(input.updateInfo.version)},
    settings: toSafeSettings(input.settings),
    logs: [...(input.diagnostics?.logLines ?? []), ...input.nativeLogLines].slice(-160).map(text)
  };
  // Sanitize serialization too, covering enum/hash/numeric fields from untrusted IPC.
  const seen = new WeakSet<object>();
  let nodes = 0;
  function scrub(value: unknown, depth = 0): unknown {
    if (++nodes > 4000 || depth > 8) return '[bounded]';
    if (typeof value === 'string') return text(value);
    if (!value || typeof value !== 'object') return value;
    if (seen.has(value)) return '[cycle]';
    seen.add(value);
    if (Array.isArray(value)) return value.slice(0, 160).map(v => scrub(v, depth + 1));
    return Object.fromEntries(Object.entries(value).filter(([key]) => !/access.?key|user.?id|password|cookie|authorization|credential|token|secret|plaintext/i.test(key)).map(([key,val]) => [key,scrub(val,depth + 1)]));
  }
  return JSON.stringify(scrub(report), null, 2);
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
