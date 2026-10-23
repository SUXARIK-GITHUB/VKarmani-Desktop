export type ConnectionState = 'idle' | 'connecting' | 'connected' | 'disconnecting';
export type AppTab = 'overview' | 'support' | 'diagnostics' | 'settings';
export type ReleaseChannel = 'stable';
export type UiLanguage = 'ru' | 'en';
export type AccessKeyKind = 'short-uuid' | 'uuid' | 'url' | 'raw';
export type ProfileSyncState = 'idle' | 'syncing' | 'ready' | 'error';
export type RuntimeBridge = 'web-preview' | 'tauri';
export type RemnawaveSource = 'demo' | 'public-api' | 'panel-api';
export type RuntimeLaunchMode = 'mock' | 'xray-sidecar';
export type ProxyMethod = 'wininet-registry' | 'wininet-api' | 'mock';
export type TunnelMode = 'proxy' | 'tun';
export type IpStack = 'ipv4' | 'ipv6';
export type SplitTunnelEntryKind = 'app' | 'service';
export type RoutingPolicy = 'VPN' | 'DIRECT';
export type TunRoutingMode = 'all' | 'selected' | 'exclude';

export interface RoutingExclusionSettings {
  enabled: boolean;
  bypassRuDomains: boolean;
  bypassSuDomains: boolean;
  bypassRfDomains: boolean;
  domains: string[];
  ips: string[];
}

export interface RunningAppInfo {
  pid: number;
  name: string;
  path?: string;
  title?: string;
}

export interface NativeAppInfo {
  appVersion: string;
  xrayVersion: string;
  hwid: string;
  osName: string;
  osVersion: string;
  osBuild: string;
  osArchitecture: string;
  deviceName: string;
  corePath?: string;
}

export interface SplitTunnelEntry {
  id: string;
  kind: SplitTunnelEntryKind;
  value: string;
  enabled: boolean;
  policy?: RoutingPolicy;
  schemaVersion?: 2;
  invalidReason?: string;
}

export interface WindowsServiceInfo {
  name: string;
  displayName: string;
  exePath: string;
  processId: number;
  state: string;
  supported: boolean;
  reason?: string;
}

export interface XrayRuntimeTemplate {
  family: 'xray';
  protocol: 'vless' | 'vmess' | 'trojan' | 'shadowsocks' | 'hysteria2' | 'unknown';
  transport?: 'raw' | 'ws' | 'grpc' | 'httpupgrade' | 'xhttp' | 'tcp' | 'udp';
  outbound: Record<string, unknown>;
  remarks?: string;
  // For Remnawave cascade/full Xray JSON objects. The selected outbound is still
  // used for node identity/ping; Auto ping measures its graph members. Native runtime preserves routing,
  // DNS and extra outbounds from the full config when this field exists.
  fullConfig?: Record<string, unknown>;
  primaryOutboundTag?: string;
  profileKind?: 'node' | 'configuration' | 'auto';
  primaryBalancerTag?: string;
  memberTags?: string[];
}

export interface VpnServer {
  id: string;
  legacyIds?: string[];
  country: string;
  city: string;
  countryCode?: string;
  flag: string;
  sourceOrder?: number;
  latency?: number | null;
  latencyCheckedAt?: string;
  latencyIdentity?: string;
  latencySource?: 'physical-tcp' | 'auto-members-physical-tcp';
  latencyStatus?: 'unchecked' | 'checking' | 'ok' | 'failed';
  load: number;
  protocol: 'Xray' | 'Reality' | 'VLESS' | 'Hysteria2';
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
  trafficUsedGb: number | null;
  trafficLimitGb: number | null;
  devices: number | null;
  uploadBytes?: string | null;
  downloadBytes?: string | null;
  totalBytes?: string | null;
  expiresAtUnix?: string | null;
}

export interface RemnawaveSession {
  accessKey: string;
  userId: string;
  displayName: string;
  loginHint: string;
  deviceLimit: number | null;
  plan: UserPlan;
  source: RemnawaveSource;
  shortUuid?: string;
  subscriptionUrl?: string;
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
  remoteUuid?: string;
  hwid?: string;
  userUuid?: string;
  note?: string;
}

export interface SessionRecord {
  id: string;
  startedAt: string;
  serverLabel: string;
  durationLabel: string;
  transferredGb: number | null;
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
  readyCount?: number;
  lastSyncAt?: string;
  updatedAt?: string;
  rawUrl?: string;
  message?: string;
  accessKeyKind?: AccessKeyKind;
}

export interface RuntimeStatus {
  diagnosticFacts?: DiagnosticFacts;
  runtimeId?: string;
  nativeInstanceId?: string;
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
  lastPreparedServerFingerprint?: string;
  lastPreparedAt?: string;
  lastExitCode?: number;
  systemProxyEnabled?: boolean;
  proxyServer?: string;
  proxyBypass?: string;
  networkMode?: TunnelMode;
  tunRoutingMode?: TunRoutingMode;
  tunInterfaceName?: string;
  xrayPid?: number;
  runtimeConfigHash?: string;
  operation?: { id: number; kind: string; stage: string; startedAt: number; deadlineAt: number; outcome?: string };
  lastOperation?: RuntimeStatus['operation'];
  runtimeRevision?: number;
  routeOwnership?: string;
  ownedRoutes?: { destination: string; prefix: number; nextHop: string; interfaceIndex: number; interfaceLuid: string; metric: number; protocol: number }[];
  subscriptionState?: 'unconfirmed' | 'expired' | 'needs-refresh' | 'verified';
  subscriptionRefreshAfter?: number;
  reconnectAttempt?: number;
  proxyOwnership?: string;
  proxyAutoConfigUrl?: string;
  proxyAutoDetect?: boolean;
}

export interface RepairReceipt {atUnixMs:number;code:string;restoreProxy:boolean;routeCount:number}
export interface DiagnosticFacts {
  lastConnectFailure?:ConnectFailureObservation;
  tunInterface?:'ready'|'unavailable'|'not-applicable';
  ports?:DiagnosticPort[];
  checkedAtUnixMs:number;
  resourceIntegrity:'verified'|'mismatch'|'unavailable';
  storageMetadata:'present'|'missing'|'unavailable';
  logsMetadata:'present'|'missing'|'unavailable';
  elevation:'elevated'|'standard'|'unavailable';
  repairHistory:RepairReceipt[];
  repairHistoryStatus:'available'|'unavailable';
}
export interface ConnectFailureObservation {
  checkedAtUnixMs:number;operationId:number|null;mode:'proxy'|'tun';
  failure:{code:string;category:string;retryable:boolean;stage?:string;cause?:string;win32Code?:number};
  process:'running'|'exited'|'not-started'|'unavailable';exitCode:number|null;
  ports:DiagnosticPort[];systemProxy:'enabled'|'disabled'|'unavailable';
  proxyOwnership:string;routeOwnership:string;ownedRouteCount:number;
}
export interface DiagnosticPort {port:10808|10809|10810;state:'free'|'owned'|'foreign'|'unconfirmed'|'unavailable'}
export interface ProxyStatus {
  enabled: boolean;
  server?: string;
  bypass?: string;
  method: ProxyMethod;
  scope: 'current-user';
  checkedAt: string;
  autoConfigUrl?: string;
  autoDetect?: boolean;
}

export interface ConnectivityProbe {
  kind?: 'server-direct' | 'xray-http' | 'unavailable';
  success: boolean;
  checkedAt: string;
  httpPortOpen: boolean;
  socksPortOpen: boolean;
  publicIp?: string;
  latencyMs?: number;
  packetLossPct?: number;
  message: string;
}

export interface TrafficSnapshot {
  baselineChanged?: boolean;
  receivedBytes: number;
  sentBytes: number;
  checkedAt: string;
  source: 'xray-stats' | 'windows-tun-adapter' | 'unavailable';
  runtimeId?: string;
  sessionId?: number;
  unavailableReason?: string;
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
  autoConnectFavorite: boolean;
  minimizeToTray: boolean;
  notifications: boolean;
  autoUpdate: boolean;
  autoInstallUpdates: boolean;
  themeGlow: boolean;
  sortServersByPing: boolean;
  tunRoutingMode: TunRoutingMode;
  releaseChannel: ReleaseChannel;
  protocolStrategy: 'auto' | 'reality-first' | 'xray-only';
  profileSyncOnLogin: boolean;
  allowDemoFallback: boolean;
  useSystemProxy: boolean;
  probeOnConnect: boolean;
  tunnelMode: TunnelMode;
  ipStack: IpStack;
  language: UiLanguage;
  routingExclusions: RoutingExclusionSettings;
}

export interface ConnectResult {
  externalIp: string;
  dnsMode: string;
  transport: string;
  probe?: ConnectivityProbe | null;
  proxy?: ProxyStatus | null;
  runtime?: RuntimeStatus;
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
  code?: string;
  createdAt?: string;
  overflowCount?: number;
}
