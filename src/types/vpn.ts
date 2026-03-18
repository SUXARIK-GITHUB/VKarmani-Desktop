export type ConnectionState = 'idle' | 'connecting' | 'connected' | 'disconnecting';
export type AppTab = 'overview' | 'servers' | 'devices' | 'diagnostics' | 'settings';
export type ReleaseChannel = 'stable' | 'beta';
export type UiLanguage = 'ru' | 'en';
export type AccessKeyKind = 'short-uuid' | 'uuid' | 'url' | 'raw';
export type ProfileSyncState = 'idle' | 'syncing' | 'ready' | 'error';
export type RuntimeBridge = 'web-preview' | 'tauri';
export type RemnawaveSource = 'demo' | 'public-api' | 'panel-api';
export type RuntimeLaunchMode = 'mock' | 'xray-sidecar';
export type ProxyMethod = 'wininet-registry' | 'mock';
export type TunnelMode = 'proxy' | 'tun';
export type SplitTunnelEntryKind = 'app' | 'service';


export interface SplitTunnelEntry {
  id: string;
  kind: SplitTunnelEntryKind;
  value: string;
  enabled: boolean;
}

export interface XrayRuntimeTemplate {
  family: 'xray';
  protocol: 'vless' | 'vmess' | 'trojan' | 'shadowsocks' | 'unknown';
  transport?: 'raw' | 'ws' | 'grpc' | 'httpupgrade' | 'xhttp' | 'tcp';
  outbound: Record<string, unknown>;
  remarks?: string;
}

export interface VpnServer {
  id: string;
  country: string;
  city: string;
  flag: string;
  latency: number;
  load: number;
  protocol: 'Xray' | 'Reality' | 'VLESS' | 'Sing-box';
  isRecommended?: boolean;
  tags?: string[];
  ipPool?: string;
  description?: string;
  source?: 'demo' | 'subscription';
  host?: string;
  port?: number;
  rawLabel?: string;
  rawUri?: string;
  transportLabel?: string;
  runtimeTemplate?: XrayRuntimeTemplate;
}

export interface UserPlan {
  title: string;
  expiresAt: string;
  trafficUsedGb: number;
  trafficLimitGb: number;
  devices: number;
}

export interface RemnawaveSession {
  accessKey: string;
  userId: string;
  displayName: string;
  loginHint: string;
  deviceLimit: number;
  plan: UserPlan;
  source: RemnawaveSource;
  shortUuid?: string;
  subscriptionUrl?: string;
  rawSubscriptionUrl?: string;
}

export interface DeviceRecord {
  id: string;
  name: string;
  platform: string;
  location: string;
  lastSeen: string;
  status: 'online' | 'offline';
  isCurrent: boolean;
  reportedByPanel?: boolean;
  note?: string;
}

export interface SessionRecord {
  id: string;
  startedAt: string;
  serverLabel: string;
  durationLabel: string;
  transferredGb: number;
  status: 'completed' | 'current' | 'interrupted';
}

export interface DiagnosticsSnapshot {
  serviceStatus: 'ok' | 'warning' | 'offline';
  tunnelStatus: 'ok' | 'warning' | 'offline';
  routeMode: string;
  dnsMode: string;
  clientVersion: string;
  lastConfigSync: string;
  logLines: string[];
}

export interface ProfileSyncInfo {
  status: ProfileSyncState;
  source: RemnawaveSource;
  sourceLabel: string;
  configCount: number;
  lastSyncAt?: string;
  rawUrl?: string;
  message?: string;
  accessKeyKind?: AccessKeyKind;
}

export interface RuntimeStatus {
  bridge: RuntimeBridge;
  coreInstalled: boolean;
  tunnelActive: boolean;
  activeServerLabel?: string;
  profileCount?: number;
  lastSyncSource?: string;
  message: string;
  corePath?: string;
  configPath?: string;
  logPath?: string;
  launchMode?: RuntimeLaunchMode;
  socksPort?: number;
  httpPort?: number;
  lastPreparedServerId?: string;
  lastPreparedAt?: string;
  lastExitCode?: number;
  systemProxyEnabled?: boolean;
  proxyServer?: string;
  proxyBypass?: string;
  networkMode?: TunnelMode;
  tunInterfaceName?: string;
}

export interface ProxyStatus {
  enabled: boolean;
  server?: string;
  bypass?: string;
  method: ProxyMethod;
  scope: 'current-user';
  checkedAt: string;
}

export interface ConnectivityProbe {
  success: boolean;
  checkedAt: string;
  httpPortOpen: boolean;
  socksPortOpen: boolean;
  publicIp?: string;
  latencyMs?: number;
  message: string;
}

export interface IntegrationMeta {
  panelUrl: string;
  subscriptionUrl: string;
  isConfigured: boolean;
  modeLabel: string;
}

export interface AppSettings {
  launchOnStartup: boolean;
  runAsAdmin: boolean;
  showDiagnostics: boolean;
  autoConnect: boolean;
  minimizeToTray: boolean;
  notifications: boolean;
  autoUpdate: boolean;
  themeGlow: boolean;
  releaseChannel: ReleaseChannel;
  protocolStrategy: 'auto' | 'reality-first' | 'xray-only';
  profileSyncOnLogin: boolean;
  allowDemoFallback: boolean;
  useSystemProxy: boolean;
  probeOnConnect: boolean;
  tunnelMode: TunnelMode;
  language: UiLanguage;
}

export interface ConnectResult {
  externalIp: string;
  dnsMode: string;
  transport: string;
  probe?: ConnectivityProbe | null;
  proxy?: ProxyStatus | null;
}

export interface UpdateInfo {
  available: boolean;
  currentVersion: string;
  version?: string;
  notes?: string;
  publishedAt?: string;
  source: 'mock' | 'tauri';
  status: 'idle' | 'checking' | 'available' | 'downloading' | 'installing' | 'updated' | 'error';
  downloadedPercent?: number;
  message?: string;
}

export interface ToastItem {
  id: string;
  title: string;
  tone: 'info' | 'success' | 'error';
}
