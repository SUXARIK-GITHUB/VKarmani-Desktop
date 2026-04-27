import { useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
import { AppInfoModal } from './components/AppInfoModal';
import { AuthScreen } from './components/AuthScreen';
import { DiagnosticsTab } from './components/DiagnosticsTab';
import { OverviewTab } from './components/OverviewTab';
import { SettingsTab } from './components/SettingsTab';
import { SidebarNav } from './components/SidebarNav';
import { SplitTunnelModal } from './components/SplitTunnelModal';
import { StartupSkeleton } from './components/StartupSkeleton';
import { SupportTab } from './components/SupportTab';
import { ToastViewport } from './components/ToastViewport';
import { TabErrorBoundary } from './components/TabErrorBoundary';
import { WindowHeader } from './components/WindowHeader';
import { tr } from './i18n';
import { useOperationManager } from './hooks/useOperationManager';
import { buildDiagnosticsFilename, createSafeDiagnosticsPayload, downloadTextFile } from './utils/diagnosticsExport';
import { redactSensitiveText } from './utils/redaction';
import { buildTrafficBars, formatTrafficBytes } from './utils/traffic';
import { remnawaveClient } from './services/remnawave';
import {
  appVersion,
  ensureAdminLaunch,
  fetchPublicIpSnapshot,
  getIntegrationMeta,
  getNativeAppInfo,
  getNativeTrafficSnapshot,
  readNativeRuntimeLog,
  pingNativeServer,
  isTauriRuntime,
  listNativeRunningApps,
  pickNativeExecutablePath,
  requestWindowHide,
  setNativeLaunchOnStartup,
  setNativeSessionAuthorized,
  writeNativeInterfaceLog,
  writeNativeRoutingLog,
  normalizeNativeError
} from './services/runtime';
import {
  clearStoredAccessKey,
  loadFavoriteServerIds,
  loadFavoriteServerIdsBackup,
  loadSelectedServerId,
  loadSelectedServerIdBackup,
  loadSettings,
  loadSettingsBackup,
  loadSplitTunnelEntries,
  loadSplitTunnelEntriesBackup,
  loadStoredAccessKey,
  loadStoredAccessKeySecure,
  saveFavoriteServerIds,
  saveSelectedServerId,
  saveSettings,
  saveSplitTunnelEntries,
  saveStoredAccessKey
} from './services/storage';
import { checkForUpdates, installAvailableUpdate } from './services/updater';
import type {
  AppSettings,
  AppTab,
  ConnectResult,
  ConnectivityProbe,
  ConnectionState,
  DeviceRecord,
  DiagnosticsSnapshot,
  NativeAppInfo,
  ProfileSyncInfo,
  ProxyStatus,
  RemnawaveSession,
  RunningAppInfo,
  RuntimeStatus,
  SessionRecord,
  TrafficSnapshot,
  SplitTunnelEntry,
  ToastItem,
  UpdateInfo,
  VpnServer
} from './types/vpn';

function createToast(title: string, tone: ToastItem['tone']): ToastItem {
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    title: redactSensitiveText(title),
    tone
  };
}

const integrationMeta = getIntegrationMeta();
const sleep = (ms: number) => new Promise<void>((resolve) => window.setTimeout(resolve, ms));

type PendingServerSwitch = {
  nextServerId: string;
  previousServerId: string;
};

type PingProgressState = {
  active: boolean;
  total: number;
  completed: number;
  success: number;
  failed: number;
};

const EMPTY_PING_PROGRESS: PingProgressState = {
  active: false,
  total: 0,
  completed: 0,
  success: 0,
  failed: 0
};


function isRealityPreferredServer(server: VpnServer) {
  const haystack = [server.protocol, server.transportLabel, ...(server.tags ?? []), server.rawLabel]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();

  return haystack.includes('reality');
}

function rankServers(servers: VpnServer[], strategy: AppSettings['protocolStrategy']) {
  const scopedServers = strategy === 'xray-only'
    ? (() => {
      const runtimeReady = servers.filter((server: VpnServer) => Boolean(server.runtimeTemplate));
      return runtimeReady.length ? runtimeReady : servers;
    })()
    : servers;

  return [...scopedServers].sort((left: VpnServer, right: VpnServer) => {
    const leftScore = Number(Boolean(left.runtimeTemplate)) * 100 + Number(Boolean(left.isRecommended)) * 10 + (strategy === 'reality-first' && isRealityPreferredServer(left) ? 30 : 0);
    const rightScore = Number(Boolean(right.runtimeTemplate)) * 100 + Number(Boolean(right.isRecommended)) * 10 + (strategy === 'reality-first' && isRealityPreferredServer(right) ? 30 : 0);

    if (rightScore !== leftScore) {
      return rightScore - leftScore;
    }

    return `${left.country} ${left.city}`.localeCompare(`${right.country} ${right.city}`, 'ru');
  });
}

function pickPreferredServer(servers: VpnServer[], strategy: AppSettings['protocolStrategy']) {
  return rankServers(servers, strategy)[0] ?? null;
}

export default function App() {
  const [accessKey, setAccessKey] = useState(() => loadStoredAccessKey());
  const [settings, setSettings] = useState<AppSettings>(() => loadSettings());
  const language = settings.language;
  const [splitTunnelEntries, setSplitTunnelEntries] = useState<SplitTunnelEntry[]>(() => loadSplitTunnelEntries());
  const [activeTab, setActiveTab] = useState<AppTab>('overview');
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [authLoading, setAuthLoading] = useState(false);
  const [connectionState, setConnectionState] = useState<ConnectionState>('idle');
  const [servers, setServers] = useState<VpnServer[]>([]);
  const [selectedServerId, setSelectedServerId] = useState(() => loadSelectedServerId());
  const [favoriteServerIds, setFavoriteServerIds] = useState<string[]>(() => loadFavoriteServerIds());
  const [session, setSession] = useState<RemnawaveSession | null>(null);
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [sessionHistory, setSessionHistory] = useState<SessionRecord[]>([]);
  const [diagnostics, setDiagnostics] = useState<DiagnosticsSnapshot | null>(null);
  const [profileSyncInfo, setProfileSyncInfo] = useState<ProfileSyncInfo>(remnawaveClient.getProfileSyncInfo());
  const [runtimeStatus, setRuntimeStatus] = useState<RuntimeStatus>({
    bridge: isTauriRuntime ? 'tauri' : 'web-preview',
    coreInstalled: false,
    tunnelActive: false,
    launchMode: 'mock',
    message: isTauriRuntime ? 'Runtime загружается…' : 'Работаем в web preview.'
  });
  const [proxyStatus, setProxyStatus] = useState<ProxyStatus>({
    enabled: false,
    method: isTauriRuntime ? 'wininet-registry' : 'mock',
    scope: 'current-user',
    checkedAt: new Date().toLocaleString('ru-RU')
  });
  const [connectivityProbe, setConnectivityProbe] = useState<ConnectivityProbe | null>(null);
  const [errorText, setErrorText] = useState('');
  const [primaryExternalIp, setPrimaryExternalIp] = useState('—');
  const [vpnExternalIp, setVpnExternalIp] = useState('—');
  const [sessionDuration, setSessionDuration] = useState(0);
  const [connectedAt, setConnectedAt] = useState<number | null>(null);
  const [trafficBaseline, setTrafficBaseline] = useState<TrafficSnapshot | null>(null);
  const [trafficCurrent, setTrafficCurrent] = useState<TrafficSnapshot | null>(null);
  const [isCheckingPing, setIsCheckingPing] = useState(false);
  const [pingProgress, setPingProgress] = useState<PingProgressState>(EMPTY_PING_PROGRESS);
  const [checkingPingServerIds, setCheckingPingServerIds] = useState<string[]>([]);
  const [searchValue, setSearchValue] = useState('');
  const [isSyncingProfile, setIsSyncingProfile] = useState(false);
  const operationManager = useOperationManager();
  const [persistentStateReady, setPersistentStateReady] = useState(!isTauriRuntime);
  const [isBootstrapping, setIsBootstrapping] = useState(true);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [isAppInfoOpen, setIsAppInfoOpen] = useState(false);
  const [nativeAppInfo, setNativeAppInfo] = useState<NativeAppInfo | null>(null);
  const [isSplitTunnelOpen, setIsSplitTunnelOpen] = useState(false);
  const [runningApps, setRunningApps] = useState<RunningAppInfo[]>([]);
  const [isLoadingRunningApps, setIsLoadingRunningApps] = useState(false);
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo>({
    available: false,
    currentVersion: appVersion,
    source: isTauriRuntime ? 'tauri' : 'mock',
    status: 'idle',
    message: 'Проверка обновлений ещё не запускалась.'
  });
  const updateInfoRef = useRef<UpdateInfo>(updateInfo);
  const persistentRestoreStarted = useRef(false);
  const hasAutoCheckedUpdates = useRef(false);

  const hasTriedFavoriteAutoConnect = useRef(false);
  const hasTriedAdminLaunch = useRef(false);
  const lastRuntimeTunnelActive = useRef(false);
  const lostRuntimePollCount = useRef(0);
  const lastAppliedSplitTunnelSignature = useRef('');
  const initialProtocolStrategy = useRef(settings.protocolStrategy);
  const connectionActionLock = useRef(false);
  const updaterActionLock = useRef(false);
  const connectionStateRef = useRef<ConnectionState>(connectionState);
  const selectedServerIdRef = useRef(selectedServerId);
  const serversRef = useRef<VpnServer[]>(servers);
  const settingsRef = useRef<AppSettings>(settings);
  const splitTunnelEntriesRef = useRef<SplitTunnelEntry[]>(splitTunnelEntries);
  const favoriteServerIdsRef = useRef<string[]>(favoriteServerIds);
  const proxyStatusRef = useRef<ProxyStatus>(proxyStatus);
  const pendingServerSwitchRef = useRef<PendingServerSwitch | null>(null);
  const pendingTunnelModeRef = useRef<AppSettings['tunnelMode'] | null>(null);
  const pendingSplitTunnelReconnectRef = useRef(false);
  const pendingDisconnectAfterBusyRef = useRef(false);
  const connectionQueueFlushScheduled = useRef(false);
  const connectionQueueFlushRunning = useRef(false);
  const pingRunIdRef = useRef(0);
  const pingCheckInFlightRef = useRef(false);
  const runtimePollInFlight = useRef(false);
  const postConnectProbeInFlight = useRef(false);
  const manualRefreshInFlight = useRef(false);
  const snapshotRefreshQueued = useRef(false);
  const connectionActionStartedAt = useRef<number | null>(null);
  const lastToastSignatureRef = useRef<{ title: string; tone: ToastItem['tone']; at: number } | null>(null);
  const trayConnectActionRef = useRef<() => void>(() => undefined);
  const trayRestartProxyActionRef = useRef<() => void>(() => undefined);
  const trayLogoutActionRef = useRef<() => void>(() => undefined);

  function trackConnectionStateTransition(nextState: ConnectionState, currentState = connectionStateRef.current) {
    if (nextState === 'connecting' || nextState === 'disconnecting') {
      if (currentState !== nextState || connectionActionStartedAt.current === null) {
        connectionActionStartedAt.current = Date.now();
      }
      return;
    }

    connectionActionStartedAt.current = null;
  }

  function setConnectionStateSafe(next: ConnectionState | ((current: ConnectionState) => ConnectionState)) {
    if (typeof next === 'function') {
      setConnectionState((current: ConnectionState) => {
        const resolved = next(current);
        trackConnectionStateTransition(resolved, current);
        connectionStateRef.current = resolved;
        return resolved;
      });
      return;
    }

    trackConnectionStateTransition(next);
    connectionStateRef.current = next;
    setConnectionState(next);
  }

  useEffect(() => {
    connectionStateRef.current = connectionState;
  }, [connectionState]);

  useEffect(() => {
    if (connectionState !== 'connecting' && connectionState !== 'disconnecting') {
      return undefined;
    }

    const observedState = connectionState;
    const startedAt = connectionActionStartedAt.current ?? Date.now();
    const timer = window.setTimeout(() => {
      if (connectionStateRef.current !== observedState) {
        return;
      }

      const waitedMs = Date.now() - startedAt;
      if (waitedMs < 43_000) {
        return;
      }

      connectionActionLock.current = false;
      connectionQueueFlushRunning.current = false;
      void writeNativeRoutingLog(
        'Watchdog разблокировал UI после долгого действия подключения.',
        `${observedState} | ${Math.round(waitedMs / 1000)}s`
      );

      void refreshDiagnosticsAndRuntime().then((runtime) => {
        if (connectionStateRef.current !== observedState) {
          return;
        }

        setConnectionStateSafe(runtime?.tunnelActive ? 'connected' : 'idle');
        if (!runtime?.tunnelActive) {
          setVpnExternalIp('—');
          setConnectivityProbe(null);
          setSessionDuration(0);
        }
        pushToast(
          tr(language, 'Действие заняло слишком много времени. Интерфейс разблокирован, состояние VPN обновлено.', 'The action took too long. The UI was unlocked and VPN state was refreshed.'),
          'info'
        );
        scheduleConnectionQueueFlush('watchdog-unlock', 220);
      });
    }, 45_000);

    return () => window.clearTimeout(timer);
  }, [connectionState, language]);

  useEffect(() => {
    selectedServerIdRef.current = selectedServerId;
  }, [selectedServerId]);

  useEffect(() => {
    serversRef.current = servers;
  }, [servers]);

  useEffect(() => {
    settingsRef.current = settings;
  }, [settings]);

  useEffect(() => {
    splitTunnelEntriesRef.current = splitTunnelEntries;
  }, [splitTunnelEntries]);

  useEffect(() => {
    favoriteServerIdsRef.current = favoriteServerIds;
  }, [favoriteServerIds]);

  useEffect(() => {
    proxyStatusRef.current = proxyStatus;
  }, [proxyStatus]);

  useEffect(() => {
    updateInfoRef.current = updateInfo;
  }, [updateInfo]);

  useEffect(() => {
    if (!isTauriRuntime || persistentRestoreStarted.current) {
      setPersistentStateReady(true);
      return;
    }

    persistentRestoreStarted.current = true;
    let cancelled = false;

    void Promise.allSettled([
      loadSettingsBackup(),
      loadSplitTunnelEntriesBackup(),
      loadFavoriteServerIdsBackup(),
      loadSelectedServerIdBackup()
    ]).then(([settingsResult, splitResult, favoritesResult, selectedResult]) => {
      if (cancelled) {
        return;
      }

      if (settingsResult.status === 'fulfilled' && settingsResult.value) {
        settingsRef.current = settingsResult.value;
        setSettings(settingsResult.value);
      }

      if (splitResult.status === 'fulfilled' && splitResult.value) {
        splitTunnelEntriesRef.current = splitResult.value;
        setSplitTunnelEntries(splitResult.value);
      }

      if (favoritesResult.status === 'fulfilled' && favoritesResult.value) {
        favoriteServerIdsRef.current = favoritesResult.value;
        setFavoriteServerIds(favoritesResult.value);
      }

      if (selectedResult.status === 'fulfilled' && selectedResult.value) {
        selectedServerIdRef.current = selectedResult.value;
        setSelectedServerId(selectedResult.value);
      }
    }).finally(() => {
      if (!cancelled) {
        setPersistentStateReady(true);
      }
    });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    void loadStoredAccessKeySecure()
      .then((storedKey) => {
        if (!cancelled && storedKey.trim()) {
          const normalizedStoredKey = storedKey.trim();
          setAccessKey(normalizedStoredKey);

          if (settingsRef.current.autoConnectFavorite && !hasTriedFavoriteAutoConnect.current) {
            hasTriedFavoriteAutoConnect.current = true;
            void authorizeWithAccessKey(normalizedStoredKey, true);
          }
        }
      })
      .catch((error) => {
        void writeNativeInterfaceLog('Не удалось загрузить ключ из защищённого хранилища.', normalizeNativeError(error, 'secure storage error').message);
      });

    return () => {
      cancelled = true;
    };
  }, []);


  useEffect(() => {
    void setNativeSessionAuthorized(Boolean(isAuthorized && session));
  }, [isAuthorized, session]);

  useEffect(() => {
    if (persistentStateReady) {
      saveSettings(settings);
    }
  }, [settings, persistentStateReady]);

  useEffect(() => {
    if (persistentStateReady) {
      saveSplitTunnelEntries(splitTunnelEntries);
    }
  }, [splitTunnelEntries, persistentStateReady]);

  useEffect(() => {
    if (persistentStateReady) {
      saveFavoriteServerIds(favoriteServerIds);
    }
  }, [favoriteServerIds, persistentStateReady]);

  useEffect(() => {
    if (persistentStateReady) {
      saveSelectedServerId(selectedServerId);
    }
  }, [selectedServerId, persistentStateReady]);

  useEffect(() => {
    document.documentElement.lang = language;
    document.title = tr(language, 'VKarmani Desktop', 'VKarmani Desktop');
  }, [language]);

  useEffect(() => {
    void writeNativeInterfaceLog('VKarmani Desktop запущен.', `Версия ${appVersion}`);
  }, []);

  useEffect(() => {
    void writeNativeInterfaceLog('Активная вкладка изменена.', activeTab);
  }, [activeTab]);

  useEffect(() => {
    if (!settings.runAsAdmin || hasTriedAdminLaunch.current) {
      return;
    }

    hasTriedAdminLaunch.current = true;
    void ensureAdminLaunch(settings.runAsAdmin).catch(() => undefined);
  }, [settings.runAsAdmin]);

  useEffect(() => {
    if (!isTauriRuntime) {
      return;
    }

    void setNativeLaunchOnStartup(settings.launchOnStartup).catch(() => undefined);
  }, [settings.launchOnStartup]);

  useEffect(() => {
    if (!settings.showDiagnostics && activeTab === 'diagnostics') {
      setActiveTab('settings');
    }
  }, [settings.showDiagnostics, activeTab]);

  useEffect(() => {
    if (connectionState === 'connected') {
      setConnectedAt((current) => current ?? Date.now());
      return;
    }

    setConnectedAt(null);
    setSessionDuration(0);
  }, [connectionState]);

  useEffect(() => {
    if (connectionState !== 'connected' || !connectedAt) {
      return undefined;
    }

    const updateDuration = () => {
      setSessionDuration(Math.max(0, Math.floor((Date.now() - connectedAt) / 1000)));
    };

    updateDuration();
    const timer = window.setInterval(updateDuration, 1000);

    return () => window.clearInterval(timer);
  }, [connectionState, connectedAt]);


  useEffect(() => {
    let cancelled = false;
    let timer: number | undefined;
    let inFlight = false;

    if (connectionState !== 'connected') {
      setTrafficBaseline(null);
      setTrafficCurrent(null);
      return undefined;
    }

    const startedAt = connectedAt ?? Date.now();

    const updateTraffic = async () => {
      if (inFlight) {
        return;
      }

      inFlight = true;
      try {
        const snapshot = await getNativeTrafficSnapshot();
        if (cancelled) {
          return;
        }

        if (snapshot.source === 'unavailable') {
          const elapsedSeconds = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
          const estimated: TrafficSnapshot = {
            receivedBytes: Math.max(0, elapsedSeconds * 18_000),
            sentBytes: Math.max(0, elapsedSeconds * 6_000),
            checkedAt: new Date().toLocaleString('ru-RU'),
            source: 'session-estimate'
          };
          setTrafficBaseline((current) => current ?? { ...estimated, receivedBytes: 0, sentBytes: 0 });
          setTrafficCurrent(estimated);
          return;
        }

        setTrafficBaseline((current) => current ?? snapshot);
        setTrafficCurrent(snapshot);
      } catch {
        if (!cancelled) {
          const elapsedSeconds = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
          const estimated: TrafficSnapshot = {
            receivedBytes: Math.max(0, elapsedSeconds * 18_000),
            sentBytes: Math.max(0, elapsedSeconds * 6_000),
            checkedAt: new Date().toLocaleString('ru-RU'),
            source: 'session-estimate'
          };
          setTrafficBaseline((current) => current ?? { ...estimated, receivedBytes: 0, sentBytes: 0 });
          setTrafficCurrent(estimated);
        }
      } finally {
        inFlight = false;
      }
    };

    void updateTraffic();
    timer = window.setInterval(() => void updateTraffic(), 4000);

    return () => {
      cancelled = true;
      if (timer !== undefined) {
        window.clearInterval(timer);
      }
    };
  }, [connectionState, connectedAt]);

  useEffect(() => {
    let cancelled = false;

    const bootstrap = async () => {
      setIsBootstrapping(true);
      const [serversResult, historyResult, devicesResult, runtimeSnapshotResult] = await Promise.allSettled([
        remnawaveClient.loadServers(),
        remnawaveClient.loadHistory(),
        remnawaveClient.loadDevices(),
        remnawaveClient.loadRuntimeSnapshot()
      ]);

      if (cancelled) {
        return;
      }

      if (serversResult.status === 'fulfilled') {
        const result = serversResult.value;
        serversRef.current = result;
        setServers(result);
        const preferredServer = pickPreferredServer(result, initialProtocolStrategy.current);
        if (preferredServer) {
          setSelectedServerId((current: string) => {
            const nextId = current || preferredServer.id;
            selectedServerIdRef.current = nextId;
            return nextId;
          });
        }
      }

      if (historyResult.status === 'fulfilled') {
        setSessionHistory(historyResult.value);
      }

      if (devicesResult.status === 'fulfilled') {
        setDevices(devicesResult.value);
      }

      if (runtimeSnapshotResult.status === 'fulfilled') {
        const { runtime, diagnostics: nextDiagnostics, proxyStatus: nextProxy } = runtimeSnapshotResult.value;
        setRuntimeStatus(runtime);
        setDiagnostics(nextDiagnostics);
        setProxyStatus(nextProxy);
        setConnectionStateSafe(runtime.tunnelActive ? 'connected' : 'idle');
        lastRuntimeTunnelActive.current = runtime.tunnelActive;
      }

      setProfileSyncInfo(remnawaveClient.getProfileSyncInfo());
      void refreshPrimaryExternalIp();
      setIsBootstrapping(false);
    };

    void bootstrap().catch(() => {
      if (!cancelled) {
        setIsBootstrapping(false);
      }
    });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!isTauriRuntime) {
      return;
    }

    let disposed = false;
    let unlistenFn: (() => void) | undefined;

    void (async () => {
      try {
        const eventApi = await import('@tauri-apps/api/event');
        const unlistenTray = await eventApi.listen<string>('vkarmani://tray-action', (event: { payload: string }) => {
          if (event.payload === 'show') {
            setActiveTab('overview');
            return;
          }

          if (event.payload === 'connect') {
            setActiveTab('overview');
            trayConnectActionRef.current();
            return;
          }

          if (event.payload === 'disconnect') {
            if (connectionStateRef.current === 'connected') {
              trayConnectActionRef.current();
            }
            return;
          }

          if (event.payload === 'restart_proxy') {
            trayRestartProxyActionRef.current();
            return;
          }

          if (event.payload === 'logout') {
            setActiveTab('overview');
            trayLogoutActionRef.current();
          }
        });

        const unlistenNativeDisconnect = await eventApi.listen<string>('vkarmani://native-disconnect', () => {
          if (connectionStateRef.current === 'connecting' || connectionStateRef.current === 'disconnecting') {
            return;
          }

          lastRuntimeTunnelActive.current = false;
          lostRuntimePollCount.current = 0;
          setConnectionStateSafe('idle');
          setVpnExternalIp('—');
          setConnectivityProbe(null);
          setSessionDuration(0);
          void refreshDiagnosticsAndRuntime();
          void refreshPrimaryExternalIp();
          pushToast(
            tr(language, 'Xray остановился. Клиент обновил состояние без автоматического переподключения.', 'Xray stopped. The client refreshed state without automatic reconnect.'),
            'error'
          );
        });

        const unlisten = () => {
          unlistenTray();
          unlistenNativeDisconnect();
        };

        if (disposed) {
          unlisten();
          return;
        }

        unlistenFn = unlisten;
      } catch {
        // ignore in web preview
      }
    })();

    return () => {
      disposed = true;
      unlistenFn?.();
    };
  }, []);

  useEffect(() => {
    if (!isTauriRuntime) {
      return;
    }

    let disposed = false;
    let timer: number | undefined;

    const syncRuntime = async () => {
      if (disposed || runtimePollInFlight.current || manualRefreshInFlight.current) {
        return;
      }

      runtimePollInFlight.current = true;
      try {
        const { runtime: nextRuntime, diagnostics: nextDiagnostics, proxyStatus: nextProxy } = await remnawaveClient.loadRuntimeSnapshot();

        if (disposed) {
          return;
        }

        const lostTunnel = lastRuntimeTunnelActive.current && !nextRuntime.tunnelActive;

        setRuntimeStatus(nextRuntime);
        setDiagnostics(nextDiagnostics);
        setProxyStatus(nextProxy);

        if (nextRuntime.tunnelActive) {
          lostRuntimePollCount.current = 0;
          lastRuntimeTunnelActive.current = true;
          setConnectionStateSafe((current: ConnectionState) => current === 'disconnecting' ? current : 'connected');
          return;
        }

        if (lostTunnel && connectionStateRef.current === 'connected') {
          lostRuntimePollCount.current += 1;
          if (lostRuntimePollCount.current < 2) {
            void writeNativeRoutingLog('Runtime snapshot временно неактивен, ждём повторную проверку без переподключения.', `miss=${lostRuntimePollCount.current}`);
            return;
          }
        } else {
          lostRuntimePollCount.current = 0;
        }

        lastRuntimeTunnelActive.current = false;
        setConnectionStateSafe((current: ConnectionState) => current === 'connecting' || current === 'disconnecting' ? current : 'idle');

        if (!lostTunnel || connectionStateRef.current === 'disconnecting') {
          return;
        }

        if (nextRuntime.systemProxyEnabled) {
          try {
            const restoredProxy = await remnawaveClient.applySystemProxy(false);
            if (!disposed) {
              setProxyStatus(restoredProxy);
            }
          } catch {
            // ignore follow-up proxy restore failure here
          }
        }

        setVpnExternalIp('—');
        setConnectivityProbe(null);
        setSessionDuration(0);
        void refreshPrimaryExternalIp();
        pushToast(tr(language, 'Runtime остановился или потерял соединение. Состояние клиента обновлено.', 'Runtime stopped or lost connectivity. Client state was refreshed.'), 'error');
      } catch {
        // keep last known state
      } finally {
        runtimePollInFlight.current = false;
        if (!disposed) {
          timer = window.setTimeout(syncRuntime, connectionStateRef.current === 'connected' ? 4000 : 12000);
        }
      }
    };

    timer = window.setTimeout(syncRuntime, 250);

    return () => {
      disposed = true;
      if (timer !== undefined) {
        window.clearTimeout(timer);
      }
    };
  }, [connectionState, language]);

  useEffect(() => {
    setSelectedServerId((current: string) => {
      if (servers.some((server: VpnServer) => server.id === current)) {
        return current;
      }

      return pickPreferredServer(servers, settings.protocolStrategy)?.id ?? current;
    });
  }, [servers, settings.protocolStrategy]);

  function pushToast(title: string, tone: ToastItem['tone']) {
    if (!settings.notifications) {
      return;
    }

    const now = Date.now();
    const safeTitle = redactSensitiveText(title);
    const lastToast = lastToastSignatureRef.current;
    if (lastToast && lastToast.title === safeTitle && lastToast.tone === tone && now - lastToast.at < 1600) {
      return;
    }
    lastToastSignatureRef.current = { title: safeTitle, tone, at: now };
    const toast = createToast(safeTitle, tone);
    setToasts((items: ToastItem[]) => [...items.slice(-3), toast]);

    window.setTimeout(() => {
      setToasts((items: ToastItem[]) => items.filter((item: ToastItem) => item.id !== toast.id));
    }, 2800);
  }

  const selectedServer = useMemo(
    () => servers.find((server: VpnServer) => server.id === selectedServerId) ?? servers[0] ?? null,
    [servers, selectedServerId]
  );

  const splitTunnelSignature = useMemo(
    () => JSON.stringify(splitTunnelEntries.map((entry: SplitTunnelEntry) => ({
      id: entry.id,
      kind: entry.kind,
      value: entry.value.trim(),
      enabled: entry.enabled
    }))),
    [splitTunnelEntries]
  );

  const activeSplitTunnelCount = useMemo(
    () => splitTunnelEntries.filter((entry: SplitTunnelEntry) => entry.enabled && entry.value.trim()).length,
    [splitTunnelEntries]
  );

  const favoriteServerIdSet = useMemo(() => new Set(favoriteServerIds), [favoriteServerIds]);
  const favoriteServerRank = useMemo(() => new Map(favoriteServerIds.map((id, index) => [id, index])), [favoriteServerIds]);
  const deferredSearchValue = useDeferredValue(searchValue);

  const trafficReceivedBytes = Math.max(0, (trafficCurrent?.receivedBytes ?? 0) - (trafficBaseline?.receivedBytes ?? 0));
  const trafficSentBytes = Math.max(0, (trafficCurrent?.sentBytes ?? 0) - (trafficBaseline?.sentBytes ?? 0));
  const trafficChartBars = useMemo(
    () => buildTrafficBars(trafficReceivedBytes, trafficSentBytes, sessionDuration),
    [trafficReceivedBytes, trafficSentBytes, sessionDuration]
  );
  const packetLossText = connectivityProbe?.packetLossPct !== undefined
    ? `${connectivityProbe.packetLossPct}%`
    : connectivityProbe?.success
      ? '0%'
      : '—';

  const filteredServers = useMemo(() => {
    const normalized = deferredSearchValue.trim().toLowerCase();
    const strategyApplied = rankServers(servers, settings.protocolStrategy).sort((left, right) => {
      const leftFavoriteRank = favoriteServerRank.get(left.id);
      const rightFavoriteRank = favoriteServerRank.get(right.id);

      if (leftFavoriteRank !== undefined || rightFavoriteRank !== undefined) {
        if (leftFavoriteRank === undefined) return 1;
        if (rightFavoriteRank === undefined) return -1;
        return leftFavoriteRank - rightFavoriteRank;
      }

      return 0;
    });

    if (!normalized) {
      return strategyApplied;
    }

    return strategyApplied.filter((server: VpnServer) => {
      const haystack = [
        server.country,
        server.city,
        server.protocol,
        server.host,
        server.transportLabel,
        ...(server.tags ?? [])
      ]
        .join(' ')
        .toLowerCase();

      return haystack.includes(normalized);
    });
  }, [deferredSearchValue, servers, settings.protocolStrategy, favoriteServerRank]);

  useEffect(() => {
    if (settings.tunnelMode !== 'tun' || !selectedServer) {
      lastAppliedSplitTunnelSignature.current = splitTunnelSignature;
      return;
    }

    if (splitTunnelSignature === lastAppliedSplitTunnelSignature.current) {
      return;
    }

    lastAppliedSplitTunnelSignature.current = splitTunnelSignature;

    if (connectionState === 'connected') {
      pushToast(
        tr(language, 'Список TUN обновлён. Новые правила применятся при следующем ручном переподключении.', 'The TUN list was updated. New rules will apply on the next manual reconnect.'),
        'info'
      );
      void writeNativeRoutingLog('TUN правила изменены без автоматического переподключения.', 'apply-on-next-manual-reconnect');
      return;
    }

    if (connectionState === 'connecting' || connectionState === 'disconnecting' || connectionActionLock.current) {
      pushToast(
        tr(language, 'Список TUN обновлён. Текущее действие подключения не прерываем.', 'The TUN list was updated. The current connection action will not be interrupted.'),
        'info'
      );
    }
  }, [connectionState, settings.tunnelMode, selectedServer, splitTunnelSignature]);

  const statusTextMap: Record<ConnectionState, string> = {
    idle: tr(language, 'Готов к подключению', 'Ready to connect'),
    connecting: tr(language, 'Подключаем защищённый туннель…', 'Connecting secure tunnel…'),
    connected: tr(language, 'Соединение активно', 'Connection is active'),
    disconnecting: tr(language, 'Отключаемся…', 'Disconnecting…')
  };
  const statusText = statusTextMap[connectionState as ConnectionState];

  const connectLabelMap: Record<ConnectionState, string> = {
    idle: tr(language, 'Подключиться', 'Connect'),
    connecting: tr(language, 'Подключение…', 'Connecting…'),
    connected: tr(language, 'Отключиться', 'Disconnect'),
    disconnecting: tr(language, 'Отключение…', 'Disconnecting…')
  };
  const connectLabel = connectLabelMap[connectionState as ConnectionState];

  const sessionDurationText = new Date(sessionDuration * 1000).toISOString().slice(11, 19);
  const fallbackRuntimeServerAvailable = servers.some((server: VpnServer) => Boolean(server.runtimeTemplate));
  const connectionDisabledReason = connectionState === 'idle'
    ? !runtimeStatus.coreInstalled
      ? tr(language, 'Xray core не найден или ещё не готов.', 'Xray core is missing or not ready yet.')
      : !selectedServer && !fallbackRuntimeServerAvailable
        ? tr(language, 'Сначала синхронизируйте профиль и выберите сервер.', 'Sync the profile and choose a server first.')
        : selectedServer && !selectedServer.runtimeTemplate && !fallbackRuntimeServerAvailable
          ? tr(language, 'У выбранного сервера ещё нет runtime-конфига.', 'The selected server has no runtime config yet.')
          : settings.tunnelMode === 'tun' && activeSplitTunnelCount === 0
            ? tr(language, 'Для TUN добавьте хотя бы одну программу или службу.', 'Add at least one app or service for TUN.')
            : ''
    : '';
  const canConnectSelectedServer = connectionState !== 'idle' || !connectionDisabledReason;

  async function refreshDiagnosticsAndRuntime() {
    if (manualRefreshInFlight.current) {
      snapshotRefreshQueued.current = true;
      return null;
    }

    manualRefreshInFlight.current = true;
    try {
      const { runtime, diagnostics: nextDiagnostics, proxyStatus: nextProxy } = await remnawaveClient.loadRuntimeSnapshot();

      setRuntimeStatus(runtime);
      setDiagnostics(nextDiagnostics);
      setProxyStatus(nextProxy);
      lastRuntimeTunnelActive.current = runtime.tunnelActive;
      return runtime;
    } catch (error) {
      void writeNativeInterfaceLog('Не удалось обновить runtime/diagnostics snapshot.', normalizeNativeError(error, 'refresh failed').message);
      return null;
    } finally {
      manualRefreshInFlight.current = false;
      if (snapshotRefreshQueued.current) {
        snapshotRefreshQueued.current = false;
        window.setTimeout(() => {
          void refreshDiagnosticsAndRuntime();
        }, 120);
      }
    }
  }


  async function refreshPrimaryExternalIp() {
    try {
      const ip = await fetchPublicIpSnapshot('direct');
      setPrimaryExternalIp(ip);
      return ip;
    } catch {
      return null;
    }
  }

  async function refreshVpnExternalIp() {
    try {
      const ip = await fetchPublicIpSnapshot('runtime');
      setVpnExternalIp(ip);
      return ip;
    } catch {
      return null;
    }
  }

  async function refreshVpnExternalIpWithRetry(attempts = 5, delayMs = 650) {
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      const ip = await refreshVpnExternalIp();
      if (ip && ip !== '—') {
        return ip;
      }
      if (attempt < attempts - 1) {
        await sleep(delayMs);
      }
    }

    return null;
  }

  function runPostConnectProbe(server: VpnServer | null) {
    if (!settingsRef.current.probeOnConnect || postConnectProbeInFlight.current) {
      return;
    }

    postConnectProbeInFlight.current = true;
    void remnawaveClient.runConnectivityProbe()
      .then((probe) => {
        if (connectionStateRef.current !== 'connected') {
          return;
        }

        setConnectivityProbe(probe);
        if (probe.publicIp) {
          setVpnExternalIp(probe.publicIp);
        }
        void writeNativeRoutingLog(
          'Фоновая проверка маршрута после подключения завершена.',
          probe.message || server?.host || 'probe-finished'
        );
      })
      .catch((error) => {
        void writeNativeRoutingLog(
          'Фоновая проверка маршрута после подключения не выполнена.',
          normalizeNativeError(error, 'post-connect probe failed').message
        );
      })
      .finally(() => {
        postConnectProbeInFlight.current = false;
      });
  }

  function updateTunnelModePreference(value: AppSettings['tunnelMode']) {
    settingsRef.current = {
      ...settingsRef.current,
      tunnelMode: value
    };

    setSettings((current: AppSettings) => ({
      ...current,
      tunnelMode: value
    }));
  }

  function shouldUseSystemProxy(mode: AppSettings['tunnelMode'], enabledBySettings = settingsRef.current.useSystemProxy) {
    return mode === 'proxy' && enabledBySettings;
  }

  function getActiveSplitTunnelEntries(entries = splitTunnelEntriesRef.current) {
    return entries.filter((entry: SplitTunnelEntry) => entry.enabled && entry.value.trim());
  }

  function getServerById(serverId: string) {
    return serversRef.current.find((server: VpnServer) => server.id === serverId) ?? null;
  }

  function isActionBusy(action: string) {
    return operationManager.isBusy(action);
  }

  async function runActionOnce<T>(action: string, operation: () => Promise<T>): Promise<T | null> {
    return operationManager.run(action, operation);
  }

  function isConnectionActionBusy() {
    return connectionActionLock.current || connectionStateRef.current === 'connecting' || connectionStateRef.current === 'disconnecting';
  }

  function hasPendingConnectionActions() {
    return Boolean(
      pendingDisconnectAfterBusyRef.current ||
      pendingTunnelModeRef.current ||
      pendingServerSwitchRef.current ||
      pendingSplitTunnelReconnectRef.current
    );
  }

  function clearPendingConnectionQueue() {
    pendingServerSwitchRef.current = null;
    pendingTunnelModeRef.current = null;
    pendingSplitTunnelReconnectRef.current = false;
    pendingDisconnectAfterBusyRef.current = false;
  }

  function scheduleConnectionQueueFlush(reason = 'connection-queue', delayMs = 80) {
    if (connectionQueueFlushScheduled.current) {
      return;
    }

    connectionQueueFlushScheduled.current = true;
    window.setTimeout(() => {
      connectionQueueFlushScheduled.current = false;
      void flushPendingConnectionActions(reason);
    }, delayMs);
  }

  async function flushPendingConnectionActions(reason = 'connection-queue') {
    if (!hasPendingConnectionActions() || connectionQueueFlushRunning.current) {
      return;
    }

    if (isConnectionActionBusy()) {
      scheduleConnectionQueueFlush(`${reason}:busy`, 350);
      return;
    }

    connectionQueueFlushRunning.current = true;
    try {
      if (pendingDisconnectAfterBusyRef.current) {
        clearPendingConnectionQueue();

        if (connectionStateRef.current === 'connected') {
          void writeNativeRoutingLog('Выполняем отложенное отключение VPN.', reason);
          setConnectionStateSafe('disconnecting');
          try {
            await remnawaveClient.disconnect({ useSystemProxy: proxyStatusRef.current.enabled || shouldUseSystemProxy(settingsRef.current.tunnelMode, settingsRef.current.useSystemProxy) });
            setVpnExternalIp('—');
            setConnectivityProbe(null);
            setSessionDuration(0);
            setConnectionStateSafe('idle');
            await refreshDiagnosticsAndRuntime();
            await refreshPrimaryExternalIp();
            pushToast(tr(language, 'VPN отключён.', 'VPN disconnected.'), 'info');
          } catch (error) {
            setConnectionStateSafe('idle');
            pushToast(normalizeNativeError(error, tr(language, 'Не удалось отключить VPN.', 'Failed to disconnect VPN.')).message, 'error');
          }
        }
        return;
      }

      const queuedMode = pendingTunnelModeRef.current;
      if (queuedMode) {
        pendingTunnelModeRef.current = null;

        if (connectionStateRef.current === 'connected') {
          const serverForReconnect = getServerById(selectedServerIdRef.current) ?? selectedServer;
          if (serverForReconnect?.runtimeTemplate) {
            void writeNativeRoutingLog('Применяем отложенное изменение режима маршрутизации.', `${reason} | mode=${queuedMode}`);
            await handleReconnectToServer(serverForReconnect, serverForReconnect);
            return;
          }
        }
      }

      const queuedServer = pendingServerSwitchRef.current;
      if (queuedServer) {
        pendingServerSwitchRef.current = null;
        const nextServer = getServerById(queuedServer.nextServerId);
        const previousServer = getServerById(queuedServer.previousServerId);

        if (!nextServer) {
          return;
        }

        if (!nextServer.runtimeTemplate) {
          if (previousServer?.id) {
            selectedServerIdRef.current = previousServer.id;
            setSelectedServerId(previousServer.id);
          }
          pushToast(
            tr(language, 'Для выбранного сервера ещё нет live-конфига. Переключение отменено.', 'The selected server is not runtime-ready yet. Switching was cancelled.'),
            'info'
          );
          return;
        }

        if (connectionStateRef.current === 'connected') {
          void writeNativeRoutingLog('Выполняем отложенное переключение сервера.', `${reason} | ${nextServer.country}, ${nextServer.city}`);
          await handleReconnectToServer(nextServer, previousServer ?? nextServer);
          return;
        }
      }

      if (pendingSplitTunnelReconnectRef.current) {
        pendingSplitTunnelReconnectRef.current = false;

        if (settingsRef.current.tunnelMode === 'tun' && connectionStateRef.current === 'connected') {
          const serverForReconnect = getServerById(selectedServerIdRef.current) ?? selectedServer;
          if (serverForReconnect?.runtimeTemplate) {
            void writeNativeRoutingLog('Выполняем отложенное применение TUN правил.', reason);
            await handleReconnectToServer(serverForReconnect, serverForReconnect);
          }
        }
      }
    } finally {
      connectionQueueFlushRunning.current = false;
      if (hasPendingConnectionActions()) {
        scheduleConnectionQueueFlush(`${reason}:next`, 140);
      }
    }
  }

  function handleAddSplitTunnelEntry(kind: SplitTunnelEntry['kind'], rawValue: string) {
    const normalized = rawValue.trim();
    if (!normalized) {
      pushToast(
        kind === 'app'
          ? tr(language, 'Укажите exe-файл или путь к программе.', 'Enter an exe name or a program path.')
          : tr(language, 'Укажите имя службы Windows.', 'Enter a Windows service name.'),
        'info'
      );
      return false;
    }

    const key = `${kind}:${normalized.toLowerCase()}`;
    let created = false;

    setSplitTunnelEntries((current: SplitTunnelEntry[]) => {
      if (current.some((entry: SplitTunnelEntry) => `${entry.kind}:${entry.value.toLowerCase()}` === key)) {
        return current;
      }

      created = true;
      return [
        ...current,
        {
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          kind,
          value: normalized,
          enabled: true
        }
      ];
    });

    pushToast(
      created
        ? kind === 'app'
          ? tr(language, 'Программа добавлена в список TUN.', 'Program added to the TUN list.')
          : tr(language, 'Служба добавлена в список TUN.', 'Service added to the TUN list.')
        : tr(language, 'Такая запись уже есть в списке.', 'This entry already exists in the list.'),
      created ? 'success' : 'info'
    );

    if (created) {
      void writeNativeInterfaceLog(
        kind === 'app' ? 'Добавлена программа в TUN список.' : 'Добавлена служба в TUN список.',
        normalized
      );
    }

    return created;
  }

  function handleToggleSplitTunnelEntry(entryId: string) {
    const nextEntry = splitTunnelEntries.find((entry: SplitTunnelEntry) => entry.id === entryId) ?? null;
    if (nextEntry) {
      void writeNativeInterfaceLog(
        nextEntry.enabled ? 'Правило TUN отключено.' : 'Правило TUN включено.',
        `${nextEntry.kind}: ${nextEntry.value}`
      );
    }

    setSplitTunnelEntries((current: SplitTunnelEntry[]) => current.map((entry: SplitTunnelEntry) => (
      entry.id === entryId
        ? { ...entry, enabled: !entry.enabled }
        : entry
    )));
  }

  function handleRemoveSplitTunnelEntry(entryId: string) {
    const removedEntry = splitTunnelEntries.find((entry: SplitTunnelEntry) => entry.id === entryId) ?? null;
    if (removedEntry) {
      void writeNativeInterfaceLog('Запись удалена из TUN списка.', `${removedEntry.kind}: ${removedEntry.value}`);
    }

    setSplitTunnelEntries((current: SplitTunnelEntry[]) => current.filter((entry: SplitTunnelEntry) => entry.id !== entryId));
    pushToast(tr(language, 'Запись удалена из списка TUN.', 'Entry removed from the TUN list.'), 'info');
  }

  async function handleOpenAppInfo() {
    setIsAppInfoOpen(true);

    await runActionOnce('appInfo', async () => {
      try {
        const nextInfo = await getNativeAppInfo();
        setNativeAppInfo(nextInfo);
      } catch (error) {
        const message = normalizeNativeError(error, tr(language, 'Не удалось получить информацию о приложении.', 'Failed to get application information.')).message;
        setNativeAppInfo({
          appVersion,
          xrayVersion: message,
          hwid: '—',
          osName: 'Windows',
          osVersion: '—',
          osBuild: '—',
          osArchitecture: '—',
          deviceName: '—'
        });
        pushToast(message, 'error');
      }
    });
  }

  async function refreshRunningAppsForSplitTunnel() {
    await runActionOnce('splitApps', async () => {
      setIsLoadingRunningApps(true);
      try {
        const apps = await listNativeRunningApps();
        setRunningApps(apps);
      } catch (error) {
        pushToast(
          normalizeNativeError(error, tr(language, 'Не удалось получить список приложений.', 'Failed to load applications.')).message,
          'error'
        );
      } finally {
        setIsLoadingRunningApps(false);
      }
    });
  }

  function handleOpenSplitTunnel() {
    setIsSplitTunnelOpen(true);
    void refreshRunningAppsForSplitTunnel();
  }

  async function handlePickExecutableForSplitTunnel() {
    await runActionOnce('pickExecutable', async () => {
      try {
        const pickedPath = await pickNativeExecutablePath();
        if (pickedPath) {
          handleAddSplitTunnelEntry('app', pickedPath);
        }
      } catch (error) {
        pushToast(
          normalizeNativeError(error, tr(language, 'Не удалось выбрать приложение.', 'Failed to choose an application.')).message,
          'error'
        );
      }
    });
  }



  async function handleEnableSystemProxy() {
    await runActionOnce('proxy', async () => {
      try {
        const nextProxy = await remnawaveClient.applySystemProxy(true);
        setProxyStatus(nextProxy);
        void refreshDiagnosticsAndRuntime();
        pushToast(tr(language, 'Системный proxy включён.', 'System proxy enabled.'), 'success');
        void writeNativeRoutingLog('Системный proxy включён вручную.', nextProxy.server ?? '127.0.0.1:10809');
      } catch (error) {
        pushToast(
          error instanceof Error
            ? error.message
            : tr(language, 'Не удалось включить системный proxy.', 'Failed to enable the system proxy.'),
          'error'
        );
      }
    });
  }

  async function handleDisableSystemProxy() {
    await runActionOnce('proxy', async () => {
      try {
        const nextProxy = await remnawaveClient.applySystemProxy(false);
        setProxyStatus(nextProxy);
        void refreshDiagnosticsAndRuntime();
        pushToast(tr(language, 'Системный proxy выключен.', 'System proxy disabled.'), 'info');
        void writeNativeRoutingLog('Системный proxy выключен вручную.');
      } catch (error) {
        pushToast(
          error instanceof Error
            ? error.message
            : tr(language, 'Не удалось выключить системный proxy.', 'Failed to disable system proxy.'),
          'error'
        );
      }
    });
  }

  async function handleRestartSystemProxy() {
    if (connectionStateRef.current !== 'connected' || !proxyStatusRef.current.enabled) {
      pushToast(tr(language, 'Системный proxy сейчас не запущен.', 'System proxy is not active now.'), 'info');
      return;
    }

    await runActionOnce('proxy', async () => {
      try {
        await remnawaveClient.applySystemProxy(false);
        await sleep(350);
        const nextProxy = await remnawaveClient.applySystemProxy(true);
        setProxyStatus(nextProxy);
        void refreshDiagnosticsAndRuntime();
        pushToast(tr(language, 'Прокси перезапущен.', 'Proxy restarted.'), 'success');
        void writeNativeRoutingLog('Системный proxy перезапущен из меню tray.', nextProxy.server ?? '127.0.0.1:10809');
      } catch (error) {
        pushToast(
          error instanceof Error
            ? error.message
            : tr(language, 'Не удалось перезапустить proxy.', 'Failed to restart proxy.'),
          'error'
        );
      }
    });
  }

  async function handleRunConnectivityProbe() {
    await runActionOnce('probe', async () => {
      try {
        const probe = await remnawaveClient.runConnectivityProbe();
        setConnectivityProbe(probe);
        void refreshDiagnosticsAndRuntime();
        pushToast(
          probe.success
            ? tr(language, 'Проверка маршрута завершена успешно.', 'Route probe completed successfully.')
            : probe.message || tr(language, 'Проверка маршрута завершилась с предупреждением.', 'Route probe completed with a warning.'),
          probe.success ? 'success' : 'info'
        );
        void writeNativeRoutingLog('Запущена ручная проверка маршрута.', probe.message || probe.publicIp || 'probe-finished');
      } catch (error) {
        pushToast(
          error instanceof Error
            ? error.message
            : tr(language, 'Не удалось выполнить проверку маршрута.', 'Failed to run the route probe.'),
          'error'
        );
      }
    });
  }

  function getPingableServers() {
    return serversRef.current.filter((server: VpnServer) => {
      const host = server.host?.trim();
      const port = Number(server.port ?? 443);
      return Boolean(host) && Number.isFinite(port) && port > 0 && port <= 65535;
    });
  }

  function updateServerPingState(
    serverId: string,
    patch: Pick<VpnServer, 'latency' | 'latencyCheckedAt' | 'latencyStatus'>
  ) {
    const updatePingState = (items: VpnServer[]) => items.map((server) => (
      server.id === serverId ? { ...server, ...patch } : server
    ));

    serversRef.current = updatePingState(serversRef.current);
    setServers((current) => updatePingState(current));
  }

  async function handleRefreshPing() {
    if (pingCheckInFlightRef.current || isCheckingPing) {
      pushToast(tr(language, 'Проверка пинга уже идёт. Остальные кнопки можно использовать.', 'Ping check is already running. Other buttons remain available.'), 'info');
      return;
    }

    const targets = getPingableServers();
    if (!targets.length) {
      pushToast(tr(language, 'Нет серверов с host/port для проверки пинга. Обновите серверы.', 'No servers with host/port are available for ping check. Refresh servers.'), 'info');
      return;
    }

    const runId = pingRunIdRef.current + 1;
    pingRunIdRef.current = runId;

    const activeIds = new Set<string>();
    const markActive = (serverId: string) => {
      activeIds.add(serverId);
      setCheckingPingServerIds(Array.from(activeIds));
      updateServerPingState(serverId, {
        latency: null,
        latencyCheckedAt: new Date().toLocaleString('ru-RU'),
        latencyStatus: 'checking'
      });
    };

    const markInactive = (serverId: string) => {
      activeIds.delete(serverId);
      setCheckingPingServerIds(Array.from(activeIds));
    };

    pingCheckInFlightRef.current = true;
    setIsCheckingPing(true);
    setPingProgress({
      active: true,
      total: targets.length,
      completed: 0,
      success: 0,
      failed: 0
    });
    void writeNativeInterfaceLog(`Запущена проверка пинга всех серверов: ${targets.length}.`);

    let cursor = 0;
    let completed = 0;
    let success = 0;
    let failed = 0;
    const concurrency = Math.min(4, Math.max(1, targets.length));

    const updateProgress = () => {
      setPingProgress({
        active: true,
        total: targets.length,
        completed,
        success,
        failed
      });
    };

    const worker = async () => {
      while (pingRunIdRef.current === runId) {
        const index = cursor;
        cursor += 1;
        const targetServer = targets[index];

        if (!targetServer) {
          return;
        }

        markActive(targetServer.id);

        try {
          const probe = await pingNativeServer(targetServer);

          if (pingRunIdRef.current !== runId) {
            return;
          }

          const measuredLatency = Number.isFinite(probe.latencyMs) && probe.latencyMs !== undefined && probe.latencyMs !== null
            ? Math.max(1, Math.round(probe.latencyMs))
            : null;

          const packetLoss = probe.packetLossPct ?? (probe.success ? 0 : 100);

          if (probe.success && measuredLatency) {
            success += 1;
            updateServerPingState(targetServer.id, {
              latency: measuredLatency,
              latencyCheckedAt: new Date().toLocaleString('ru-RU'),
              latencyStatus: 'ok'
            });
          } else {
            failed += 1;
            updateServerPingState(targetServer.id, {
              latency: null,
              latencyCheckedAt: new Date().toLocaleString('ru-RU'),
              latencyStatus: 'failed'
            });
          }

          if (targetServer.id === selectedServerIdRef.current) {
            setConnectivityProbe({
              ...probe,
              packetLossPct: packetLoss
            });
          }

          void writeNativeRoutingLog(
            'Проверка пинга сервера завершена.',
            `${getServerPrimaryLabelForToast(targetServer)} · ${probe.success && measuredLatency ? `${measuredLatency} мс` : 'нет ответа'}`
          );
        } catch (error) {
          if (pingRunIdRef.current !== runId) {
            return;
          }

          failed += 1;
          updateServerPingState(targetServer.id, {
            latency: null,
            latencyCheckedAt: new Date().toLocaleString('ru-RU'),
            latencyStatus: 'failed'
          });
          void writeNativeRoutingLog(
            'Проверка пинга сервера завершилась ошибкой.',
            `${getServerPrimaryLabelForToast(targetServer)} · ${error instanceof Error ? error.message : 'unknown error'}`
          );
        } finally {
          if (pingRunIdRef.current === runId) {
            completed += 1;
            markInactive(targetServer.id);
            updateProgress();
          }

          await sleep(0);
        }
      }
    };

    try {
      await Promise.all(Array.from({ length: concurrency }, () => worker()));

      if (pingRunIdRef.current !== runId) {
        return;
      }

      void refreshDiagnosticsAndRuntime();
      pushToast(
        tr(
          language,
          `Пинг проверен: ${success}/${targets.length} серверов ответили, ${failed} без ответа.`,
          `Ping checked: ${success}/${targets.length} servers responded, ${failed} did not respond.`
        ),
        success > 0 ? 'success' : 'info'
      );
    } catch (error) {
      pushToast(
        error instanceof Error
          ? error.message
          : tr(language, 'Не удалось проверить пинг.', 'Failed to check ping.'),
        'error'
      );
    } finally {
      if (pingRunIdRef.current === runId) {
        pingCheckInFlightRef.current = false;
        setIsCheckingPing(false);
        setCheckingPingServerIds([]);
        setPingProgress(EMPTY_PING_PROGRESS);
      }
    }
  }

  function getServerPrimaryLabelForToast(server: VpnServer) {
    return [server.country, server.city].filter(Boolean).join(', ') || server.rawLabel || server.id;
  }

  function handleToggleFavoriteServer(serverId: string) {
    setFavoriteServerIds((current) => {
      const normalized = serverId.trim();
      if (!normalized) {
        return current;
      }

      if (current.includes(normalized)) {
        return current.filter((item) => item !== normalized);
      }

      // Новое избранное всегда идёт первым: пользователь сразу видит выбранный
      // сервер сверху списка и этот порядок переживает перезапуск/обновление.
      return [normalized, ...current.filter((item) => item !== normalized)];
    });
  }

  async function handleRevokeDevice(deviceId: string) {
    if (!deviceId) {
      return;
    }

    await runActionOnce(`device:${deviceId}`, async () => {
      try {
        const nextDevices = await remnawaveClient.revokeDevice(deviceId);
        setDevices(Array.isArray(nextDevices) ? nextDevices : []);
        void refreshDiagnosticsAndRuntime();
        pushToast(tr(language, 'Устройство отключено.', 'Device revoked.'), 'info');
        void writeNativeInterfaceLog('Устройство отключено пользователем.', deviceId);
      } catch (error) {
        pushToast(
          error instanceof Error
            ? error.message
            : tr(language, 'Не удалось отключить устройство.', 'Failed to revoke the device.'),
          'error'
        );
      }
    });
  }

  async function handleTunnelModeChange(nextMode: AppSettings['tunnelMode']) {
    const currentSettings = settingsRef.current;
    const currentConnectionState = connectionStateRef.current;
    const activeSplitEntries = getActiveSplitTunnelEntries();

    if (nextMode === currentSettings.tunnelMode && !pendingTunnelModeRef.current) {
      return;
    }

    if (currentConnectionState !== 'idle' && nextMode === 'tun' && activeSplitEntries.length === 0) {
      pushToast(
        tr(language, 'Для TUN сначала добавьте хотя бы одну программу или службу. Текущее подключение оставлено без изменений.', 'For TUN, add at least one program or service first. The current connection was left unchanged.'),
        'info'
      );
      return;
    }

    if (isConnectionActionBusy()) {
      updateTunnelModePreference(nextMode);
      pendingTunnelModeRef.current = nextMode;
      pushToast(
        tr(language, 'Режим выбран. Применим его после завершения текущего действия подключения.', 'Mode selected. It will be applied after the current connection action finishes.'),
        'info'
      );
      void writeNativeRoutingLog('Изменение режима маршрутизации поставлено в очередь.', `${currentSettings.tunnelMode} -> ${nextMode}`);
      scheduleConnectionQueueFlush('queued-tunnel-mode-change');
      return;
    }

    connectionActionLock.current = true;
    try {
      const previousMode = currentSettings.tunnelMode;
      const previousUseSystemProxy = currentSettings.useSystemProxy;
      const serverForReconnect = getServerById(selectedServerIdRef.current) ?? selectedServer;
      void writeNativeInterfaceLog('Пользователь меняет режим маршрутизации.', `${previousMode} -> ${nextMode}`);

      updateTunnelModePreference(nextMode);

      if (nextMode === 'tun' && activeSplitEntries.length === 0) {
        pushToast(
          tr(language, 'Выбран TUN режим. Сначала добавьте программы или службы, затем подключайтесь.', 'TUN mode selected. Add apps or services first, then connect.'),
          'info'
        );
      }

      if (currentConnectionState !== 'connected' || !serverForReconnect) {
        pushToast(
          nextMode === 'tun'
            ? tr(language, 'Выбран TUN режим.', 'TUN mode selected.')
            : tr(language, 'Выбран proxy режим.', 'Proxy mode selected.'),
          'info'
        );
        return;
      }

      try {
        setConnectionStateSafe('disconnecting');
        await remnawaveClient.disconnect({ useSystemProxy: proxyStatusRef.current.enabled || (previousMode !== 'tun' && previousUseSystemProxy) });
        setVpnExternalIp('—');
        setConnectivityProbe(null);
        setSessionDuration(0);

        setConnectionStateSafe('connecting');
        const response = await remnawaveClient.connect(serverForReconnect, {
          useSystemProxy: shouldUseSystemProxy(nextMode, previousUseSystemProxy),
          probeAfterConnect: false,
          tunnelMode: nextMode,
          splitTunnelEntries: splitTunnelEntriesRef.current
        });
        setConnectivityProbe(response.probe ?? null);
        if (response.proxy) {
          setProxyStatus(response.proxy);
        }
        setSessionDuration(0);
        setConnectionStateSafe('connected');
        runPostConnectProbe(serverForReconnect);
        void refreshDiagnosticsAndRuntime();
        void refreshVpnExternalIpWithRetry().then((resolvedVpnIp) => {
          if (!resolvedVpnIp) {
            setVpnExternalIp(response.probe?.publicIp ?? response.externalIp);
          }
        });
        void writeNativeRoutingLog('Режим маршрутизации переключён.', `${previousMode} -> ${nextMode} | сервер ${serverForReconnect.country}, ${serverForReconnect.city}`);
        pushToast(
          nextMode === 'tun'
            ? tr(language, 'Режим переключён на TUN.', 'The mode was switched to TUN.')
            : tr(language, 'Режим переключён на proxy.', 'The mode was switched to proxy.'),
          'success'
        );
      } catch (error) {
        settingsRef.current = {
          ...settingsRef.current,
          tunnelMode: previousMode,
          useSystemProxy: previousUseSystemProxy
        };
        setSettings((current: AppSettings) => ({
          ...current,
          tunnelMode: previousMode,
          useSystemProxy: previousUseSystemProxy
        }));
        void writeNativeRoutingLog(
          'Ошибка при переключении режима маршрутизации.',
          normalizeNativeError(error, 'unknown-error').message
        );
        setConnectionStateSafe('idle');
        setVpnExternalIp('—');
        setConnectivityProbe(null);
        setSessionDuration(0);
        await refreshDiagnosticsAndRuntime();
        await refreshPrimaryExternalIp();
        pushToast(
          error instanceof Error
            ? error.message
            : tr(language, 'Не удалось переключить режим туннеля.', 'Failed to switch the tunnel mode.'),
          'error'
        );
      }
    } finally {
      connectionActionLock.current = false;
      scheduleConnectionQueueFlush('after-tunnel-mode-change');
    }
  }

  async function handleSyncProfile(silent = false, accessKeyOverride?: string) {
    const normalizedAccessKey = (accessKeyOverride ?? accessKey).trim();
    if (!normalizedAccessKey) {
      return null;
    }

    try {
      void writeNativeInterfaceLog('Запущена синхронизация профиля Remnawave.');
      setIsSyncingProfile(true);
      setProfileSyncInfo((current: ProfileSyncInfo) => ({
        ...current,
        status: 'syncing',
        message: tr(language, 'Синхронизируем профиль Remnawave…', 'Syncing Remnawave profile…')
      }));

      const result = await remnawaveClient.syncProfile(normalizedAccessKey, settingsRef.current.allowDemoFallback);
      serversRef.current = result.servers;
      setServers(result.servers);
      setFavoriteServerIds((current) => current.filter((id) => result.servers.some((server: VpnServer) => server.id === id)));
      setProfileSyncInfo(result.profile);
      const refreshedSession = remnawaveClient.getCachedSession();
      if (refreshedSession) {
        setSession(refreshedSession);
      }
      const refreshedDevices = await remnawaveClient.loadDevices();
      setDevices(refreshedDevices);

      const preferredServer = pickPreferredServer(result.servers, settingsRef.current.protocolStrategy);
      setSelectedServerId((current: string) => {
        const nextId = result.servers.some((item: VpnServer) => item.id === current)
          ? current
          : preferredServer?.id ?? current;
        selectedServerIdRef.current = nextId;
        return nextId;
      });

      await refreshDiagnosticsAndRuntime();
      void writeNativeInterfaceLog(
        'Профиль Remnawave синхронизирован.',
        `${result.profile.configCount} конфигов | источник: ${result.profile.sourceLabel}`
      );

      if (!silent) {
        pushToast(result.profile.message ?? tr(language, 'Профиль синхронизирован.', 'Profile synced.'), 'success');
      }

      return result;
    } catch (error) {
      const message = normalizeNativeError(error, tr(language, 'Не удалось синхронизировать профиль.', 'Failed to sync profile.')).message;
      setProfileSyncInfo((current: ProfileSyncInfo) => ({
        ...current,
        status: 'error',
        message
      }));
      void writeNativeInterfaceLog('Ошибка синхронизации профиля Remnawave.', message);
      if (!silent) {
        pushToast(message, 'error');
      }
      return null;
    } finally {
      setIsSyncingProfile(false);
    }
  }

  async function authorizeWithAccessKey(rawAccessKey: string, connectFavoriteAfterLaunch = false) {
    const normalizedAccessKey = rawAccessKey.trim();

    if (!normalizedAccessKey) {
      setErrorText(tr(language, 'Сначала вставьте ключ доступа.', 'Paste the access key first.'));
      return;
    }

    if (!normalizedAccessKey.startsWith('https://sub.vkarmani.com/')) {
      setErrorText(tr(language, 'Ключ должен начинаться с https://sub.vkarmani.com/. Другие ключи не принимаются.', 'The key must start with https://sub.vkarmani.com/. Other keys are not accepted.'));
      return;
    }

    try {
      const currentSettings = settingsRef.current;
      void writeNativeInterfaceLog(connectFavoriteAfterLaunch ? 'Начата авторизация по сохранённому ключу для автоподключения.' : 'Начата авторизация по ключу доступа.');
      setAuthLoading(true);
      setErrorText('');
      setAccessKey(normalizedAccessKey);
      const response = await remnawaveClient.authorizeByAccessKey(normalizedAccessKey, currentSettings.allowDemoFallback);
      setSession(response);
      const nextDevices = await remnawaveClient.loadDevices();
      setDevices(nextDevices);
      setIsAuthorized(true);
      const keyPersisted = await saveStoredAccessKey(normalizedAccessKey);

      if (!connectFavoriteAfterLaunch) {
        pushToast(tr(language, 'Ключ доступа принят.', 'Access key accepted.'), 'success');
        if (!keyPersisted) {
          pushToast(
            tr(language, 'Ключ принят, но не сохранён: защищённое хранилище Windows временно недоступно.', 'The key was accepted but not saved: Windows secure storage is temporarily unavailable.'),
            'error'
          );
        }
      }
      void writeNativeInterfaceLog('Авторизация по ключу доступа завершена успешно.');

      let serverPool = serversRef.current;
      let preferredServerForAutoConnect = selectedServer;

      if (currentSettings.profileSyncOnLogin) {
        const syncResult = await handleSyncProfile(true, normalizedAccessKey);
        if (syncResult?.servers) {
          serverPool = syncResult.servers;
          preferredServerForAutoConnect = pickPreferredServer(syncResult.servers, currentSettings.protocolStrategy);
        }
      }

      if (connectFavoriteAfterLaunch) {
        const favoriteServer = favoriteServerIdsRef.current
          .map((id) => serverPool.find((server: VpnServer) => server.id === id && server.runtimeTemplate) ?? serverPool.find((server: VpnServer) => server.id === id))
          .find((server): server is VpnServer => Boolean(server));

        if (favoriteServer) {
          preferredServerForAutoConnect = favoriteServer;
          setSelectedServerId(favoriteServer.id);
          selectedServerIdRef.current = favoriteServer.id;
          pushToast(tr(language, 'Автоподключение к избранному серверу запущено.', 'Auto-connecting to a favorite server.'), 'info');
        } else {
          pushToast(tr(language, 'Избранный сервер для автоподключения не найден.', 'No favorite server was found for auto-connect.'), 'info');
        }
      }

      if ((currentSettings.autoConnect || connectFavoriteAfterLaunch) && preferredServerForAutoConnect) {
        void handleConnectionToggle(preferredServerForAutoConnect);
      }
    } catch (error) {
      void writeNativeInterfaceLog(
        'Ошибка авторизации по ключу доступа.',
        normalizeNativeError(error, 'unknown-error').message
      );
      const message = normalizeNativeError(error, tr(language, 'Не удалось проверить ключ доступа.', 'Failed to validate access key.')).message;
      setErrorText(message);
      pushToast(message, 'error');
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleAuthorize() {
    await authorizeWithAccessKey(accessKey, false);
  }

  async function handleReconnectToServer(nextServer: VpnServer, previousServer: VpnServer | null) {
    if (isConnectionActionBusy()) {
      pendingServerSwitchRef.current = {
        nextServerId: nextServer.id,
        previousServerId: previousServer?.id ?? selectedServerIdRef.current
      };
      scheduleConnectionQueueFlush('queued-reconnect');
      return;
    }

    connectionActionLock.current = true;
    try {
      const currentSettings = settingsRef.current;
      const currentSplitTunnelEntries = splitTunnelEntriesRef.current;
      setConnectionStateSafe('connecting');
      if (currentSettings.tunnelMode === 'tun' && getActiveSplitTunnelEntries(currentSplitTunnelEntries).length === 0) {
        if (previousServer?.id) {
          selectedServerIdRef.current = previousServer.id;
          setSelectedServerId(previousServer.id);
        }
        pushToast(
          tr(language, 'Для TUN сначала добавьте хотя бы одну программу или службу.', 'For TUN, add at least one program or service first.'),
          'info'
        );
        setConnectionStateSafe(previousServer ? 'connected' : 'idle');
        return;
      }

      const response = await remnawaveClient.connect(nextServer, {
        useSystemProxy: shouldUseSystemProxy(currentSettings.tunnelMode, currentSettings.useSystemProxy),
        probeAfterConnect: false,
        tunnelMode: currentSettings.tunnelMode,
        splitTunnelEntries: currentSplitTunnelEntries
      });
      setConnectivityProbe(response.probe ?? null);
      if (response.proxy) {
        setProxyStatus(response.proxy);
      }
      setSessionDuration(0);
      setConnectionStateSafe('connected');
      runPostConnectProbe(nextServer);
      void refreshDiagnosticsAndRuntime();
      void refreshVpnExternalIpWithRetry().then((resolvedVpnIp) => {
        if (!resolvedVpnIp) {
          setVpnExternalIp(response.probe?.publicIp ?? response.externalIp);
        }
      });
      pushToast(
        `${tr(language, 'Мягкое переподключение', 'Soft reconnect')}: ${nextServer.country}, ${nextServer.city}`,
        'success'
      );
    } catch (error) {
      if (proxyStatusRef.current.enabled || shouldUseSystemProxy(settingsRef.current.tunnelMode, settingsRef.current.useSystemProxy)) {
        try {
          const restoredProxy = await remnawaveClient.applySystemProxy(false);
          setProxyStatus(restoredProxy);
        } catch {
          // ignore follow-up proxy restore failure
        }
      }

      if (previousServer?.id) {
        selectedServerIdRef.current = previousServer.id;
        setSelectedServerId(previousServer.id);
      }

      setConnectivityProbe(null);
      setVpnExternalIp('—');
      setSessionDuration(0);
      setConnectionStateSafe('idle');
      await refreshDiagnosticsAndRuntime();
      await refreshPrimaryExternalIp();
      pushToast(
        error instanceof Error
          ? error.message
          : tr(language, 'Не удалось переключить сервер без разрыва соединения.', 'Failed to switch server without disconnecting.'),
        'error'
      );
    } finally {
      connectionActionLock.current = false;
      scheduleConnectionQueueFlush('after-reconnect');
    }
  }


  function findMatchingServer(candidates: VpnServer[], baseServer: VpnServer | null) {
    if (!baseServer) {
      return pickPreferredServer(candidates, settingsRef.current.protocolStrategy);
    }

    return candidates.find((server: VpnServer) => server.id === baseServer.id)
      ?? candidates.find((server: VpnServer) => {
        const sameRuntime = JSON.stringify(server.runtimeTemplate ?? null) === JSON.stringify(baseServer.runtimeTemplate ?? null);
        const sameEndpoint = server.host === baseServer.host && (server.port ?? 443) === (baseServer.port ?? 443);
        const sameLabel = server.country === baseServer.country && server.city === baseServer.city && server.protocol === baseServer.protocol;
        return sameRuntime || sameEndpoint || sameLabel;
      })
      ?? pickPreferredServer(candidates, settingsRef.current.protocolStrategy);
  }

  async function resolveServerForConnection(baseServer: VpnServer | null) {
    let resolvedServer = baseServer ?? pickPreferredServer(serversRef.current, settingsRef.current.protocolStrategy);

    if (resolvedServer?.runtimeTemplate) {
      return resolvedServer;
    }

    const cachedServers = await remnawaveClient.loadServers();
    resolvedServer = findMatchingServer(cachedServers, resolvedServer);
    if (resolvedServer?.runtimeTemplate) {
      if (resolvedServer.id !== selectedServerIdRef.current) {
        selectedServerIdRef.current = resolvedServer.id;
        setSelectedServerId(resolvedServer.id);
      }
      return resolvedServer;
    }

    if (accessKey.trim()) {
      const syncResult = await handleSyncProfile(true);
      const syncedServers = syncResult?.servers ?? await remnawaveClient.loadServers();
      resolvedServer = findMatchingServer(syncedServers, resolvedServer);
      if (resolvedServer?.runtimeTemplate) {
        if (resolvedServer.id !== selectedServerIdRef.current) {
          selectedServerIdRef.current = resolvedServer.id;
          setSelectedServerId(resolvedServer.id);
        }
        return resolvedServer;
      }
    }

    return resolvedServer ?? null;
  }

  async function handleSelectServer(nextServerId: string) {
    if (nextServerId === selectedServerIdRef.current) {
      return;
    }

    const nextServer = getServerById(nextServerId);
    const previousServer = getServerById(selectedServerIdRef.current) ?? selectedServer;
    if (nextServer) {
      void writeNativeInterfaceLog('Выбран сервер.', `${nextServer.country}, ${nextServer.city}`);
    }

    selectedServerIdRef.current = nextServerId;
    setSelectedServerId(nextServerId);

    if (!nextServer) {
      return;
    }

    if (connectionStateRef.current === 'idle') {
      return;
    }

    if (!nextServer.runtimeTemplate) {
      if (previousServer?.id) {
        selectedServerIdRef.current = previousServer.id;
        setSelectedServerId(previousServer.id);
      }
      pushToast(
        tr(language, 'Для этого сервера ещё нет live-конфига. Текущее подключение оставлено без изменений.', 'This server is not runtime-ready yet. The current connection was left unchanged.'),
        'info'
      );
      return;
    }

    if (isConnectionActionBusy()) {
      pendingServerSwitchRef.current = {
        nextServerId,
        previousServerId: previousServer?.id ?? ''
      };
      pushToast(
        tr(language, 'Сервер выбран. Переключим VPN после завершения текущего действия.', 'Server selected. The VPN will switch after the current action finishes.'),
        'info'
      );
      void writeNativeRoutingLog('Переключение сервера поставлено в очередь.', `${nextServer.country}, ${nextServer.city}`);
      scheduleConnectionQueueFlush('queued-server-select');
      return;
    }

    if (connectionStateRef.current === 'connected') {
      await handleReconnectToServer(nextServer, previousServer);
    }
  }

  async function handleConnectionToggle(serverOverride: VpnServer | null = null) {
    const currentState = connectionStateRef.current;

    if (isConnectionActionBusy()) {
      if (currentState === 'connecting') {
        pendingDisconnectAfterBusyRef.current = true;
        pushToast(
          tr(language, 'Отключение поставлено в очередь и выполнится сразу после подключения.', 'Disconnect was queued and will run right after the connection attempt finishes.'),
          'info'
        );
        void writeNativeRoutingLog('Отключение поставлено в очередь во время подключения.');
        scheduleConnectionQueueFlush('queued-disconnect');
      }
      return;
    }

    connectionActionLock.current = true;
    try {
      const currentSettings = settingsRef.current;
      const currentMode = currentSettings.tunnelMode;
      const currentSplitTunnelEntries = splitTunnelEntriesRef.current;
      let targetServer = await resolveServerForConnection(serverOverride ?? getServerById(selectedServerIdRef.current) ?? selectedServer ?? null);
      if (!targetServer) {
        setErrorText(tr(language, 'Сервер пока не выбран. Синхронизируйте профиль и выберите узел.', 'Server is not selected yet. Sync the profile and choose a node.'));
        void writeNativeRoutingLog('Подключение остановлено: активный сервер не выбран.');
        return;
      }

      if (!targetServer.runtimeTemplate && currentState !== 'connected') {
        setErrorText(tr(language, 'Не удалось найти готовый сервер в активном профиле. Обновите профиль и попробуйте ещё раз.', 'No runtime-ready server was found in the active profile. Sync the profile and try again.'));
        void writeNativeRoutingLog('Подключение остановлено: runtime-ready сервер не найден.', `${targetServer.country}, ${targetServer.city}`);
        pushToast(tr(language, 'Сначала обновите профиль или выберите другой сервер.', 'Sync the profile or choose another server first.'), 'info');
        return;
      }

      try {
        if (currentState === 'connected') {
          void writeNativeRoutingLog('Пользователь отключает VPN.', `${targetServer.country}, ${targetServer.city}`);
          setConnectionStateSafe('disconnecting');
          await remnawaveClient.disconnect({ useSystemProxy: proxyStatusRef.current.enabled || shouldUseSystemProxy(currentMode, currentSettings.useSystemProxy) });
          setVpnExternalIp('—');
          setSessionDuration(0);
          setConnectivityProbe(null);
          setConnectionStateSafe('idle');
          await refreshDiagnosticsAndRuntime();
          await refreshPrimaryExternalIp();
          pushToast(tr(language, 'VPN отключён.', 'VPN disconnected.'), 'info');
          void writeNativeRoutingLog('VPN отключён.', `${targetServer.country}, ${targetServer.city}`);
          return;
        }

        void refreshPrimaryExternalIp();
        if (currentMode === 'tun' && getActiveSplitTunnelEntries(currentSplitTunnelEntries).length === 0) {
          pushToast(
            tr(language, 'Для TUN сначала добавьте хотя бы одну программу или службу.', 'For TUN, add at least one program or service.'),
            'info'
          );
          return;
        }
        void writeNativeRoutingLog(
          'Пользователь запускает VPN подключение.',
          `${targetServer.country}, ${targetServer.city} | mode=${currentMode}`
        );
        setConnectionStateSafe('connecting');
        let response: ConnectResult;
        try {
          response = await remnawaveClient.connect(targetServer, {
            useSystemProxy: shouldUseSystemProxy(currentMode, currentSettings.useSystemProxy),
            probeAfterConnect: false,
            tunnelMode: currentMode,
            splitTunnelEntries: currentSplitTunnelEntries
          });
        } catch (error) {
          const message = normalizeNativeError(error, '').message;
          if (message.includes('Сервер не найден в активном профиле') && accessKey.trim()) {
            void writeNativeRoutingLog('Сервер выпал из кэша профиля. Выполняем тихую пересинхронизацию.', message);
            const syncResult = await handleSyncProfile(true);
            const recoveredServer = findMatchingServer(syncResult?.servers ?? await remnawaveClient.loadServers(), targetServer);
            if (!recoveredServer?.runtimeTemplate) {
              throw error;
            }

            targetServer = recoveredServer;
            if (targetServer.id !== selectedServerIdRef.current) {
              selectedServerIdRef.current = targetServer.id;
              setSelectedServerId(targetServer.id);
            }

            response = await remnawaveClient.connect(targetServer, {
              useSystemProxy: shouldUseSystemProxy(currentMode, currentSettings.useSystemProxy),
              probeAfterConnect: false,
              tunnelMode: currentMode,
              splitTunnelEntries: currentSplitTunnelEntries
            });
          } else {
            throw error;
          }
        }
        setErrorText('');
        setConnectivityProbe(response.probe ?? null);
        if (response.proxy) {
          setProxyStatus(response.proxy);
        }
        setSessionDuration(0);
        setConnectionStateSafe('connected');
        runPostConnectProbe(targetServer);
        void refreshDiagnosticsAndRuntime();
        void refreshVpnExternalIpWithRetry().then((resolvedVpnIp) => {
          if (!resolvedVpnIp) {
            setVpnExternalIp(response.probe?.publicIp ?? response.externalIp);
          }
        });
        pushToast(`${tr(language, 'Подключено', 'Connected')}: ${targetServer.country}, ${targetServer.city}`, 'success');
        void writeNativeRoutingLog('VPN подключён успешно.', `${targetServer.country}, ${targetServer.city} | mode=${currentMode}`);
      } catch (error) {
        const normalizedError = normalizeNativeError(error, tr(language, 'Ошибка подключения.', 'Connection failed.'));
        void writeNativeRoutingLog('Ошибка VPN подключения.', normalizedError.message);

        if (proxyStatusRef.current.enabled || shouldUseSystemProxy(settingsRef.current.tunnelMode, settingsRef.current.useSystemProxy)) {
          try {
            const restoredProxy = await remnawaveClient.applySystemProxy(false);
            setProxyStatus(restoredProxy);
          } catch {
            // Backend cleanup still runs on request_disconnect/app exit; this is best-effort UI recovery.
          }
        }

        setErrorText(normalizedError.message);
        setVpnExternalIp('—');
        setConnectivityProbe(null);
        setSessionDuration(0);
        setConnectionStateSafe('idle');
        await refreshDiagnosticsAndRuntime();
        await refreshPrimaryExternalIp();
        pushToast(normalizedError.message, 'error');
      }
    } finally {
      connectionActionLock.current = false;
      scheduleConnectionQueueFlush('after-connection-toggle');
    }
  }

  async function handleCheckUpdates(silent = false, autoInstall = false): Promise<UpdateInfo> {
    if (['checking', 'downloading', 'installing'].includes(updateInfoRef.current.status)) {
      return updateInfoRef.current;
    }

    setUpdateInfo((current: UpdateInfo) => ({
      ...current,
      status: 'checking',
      message: tr(language, 'Проверяем наличие новой версии…', 'Checking for updates…')
    }));

    const result = await checkForUpdates(settings.releaseChannel);
    setUpdateInfo(result);

    if (result.status === 'error') {
      if (!silent) {
        pushToast(result.message ?? tr(language, 'Не удалось проверить обновления.', 'Failed to check for updates.'), 'error');
      }
      return result;
    }

    if (result.available) {
      if (!silent) {
        pushToast(`${tr(language, 'Найдено обновление', 'Update found')} ${result.version}`, 'info');
      }

      if (autoInstall && isTauriRuntime) {
        await handleInstallUpdate(true);
      }

      return result;
    }

    if (!silent) {
      pushToast(tr(language, 'Новых обновлений нет.', 'No updates available.'), 'success');
    }

    return result;
  }

  async function handleInstallUpdate(silent = false) {
    if (updaterActionLock.current || connectionActionLock.current || ['checking', 'downloading', 'installing'].includes(updateInfoRef.current.status)) {
      return;
    }

    updaterActionLock.current = true;
    try {
      if (connectionStateRef.current === 'connected') {
        setUpdateInfo((current: UpdateInfo) => ({
          ...current,
          status: 'installing',
          message: tr(language, 'Отключаем VPN перед обновлением…', 'Disconnecting VPN before update…')
        }));
        try {
          setConnectionStateSafe('disconnecting');
          await remnawaveClient.disconnect({ useSystemProxy: proxyStatusRef.current.enabled || shouldUseSystemProxy(settingsRef.current.tunnelMode, settingsRef.current.useSystemProxy) });
          setVpnExternalIp('—');
          setSessionDuration(0);
          setConnectivityProbe(null);
          setConnectionStateSafe('idle');
          await refreshDiagnosticsAndRuntime();
        } catch (error) {
          setConnectionStateSafe('idle');
          const message = normalizeNativeError(error, tr(language, 'Не удалось остановить VPN перед обновлением.', 'Failed to stop VPN before update.')).message;
          setUpdateInfo((current: UpdateInfo) => ({
            ...current,
            status: 'error',
            message
          }));
          if (!silent) {
            pushToast(message, 'error');
          }
          return;
        }
      }

      setUpdateInfo((current: UpdateInfo) => ({
        ...current,
        status: 'downloading',
        downloadedPercent: 0,
        message: tr(language, 'Скачиваем обновление…', 'Downloading update…')
      }));

      const result = await installAvailableUpdate((percent) => {
        setUpdateInfo((current: UpdateInfo) => ({
          ...current,
          status: percent >= 100 ? 'installing' : 'downloading',
          downloadedPercent: percent,
          message: percent >= 100 ? tr(language, 'Файлы загружены, запускаем установку…', 'Files are ready, starting installation…') : tr(language, 'Скачиваем обновление…', 'Downloading update…')
        }));
      });

      if (!result.ok) {
        setUpdateInfo((current: UpdateInfo) => ({
          ...current,
          status: 'error',
          message: result.message
        }));
        if (!silent) {
          pushToast(result.message, 'error');
        }
        return;
      }

      setUpdateInfo((current: UpdateInfo) => ({
        ...current,
        available: false,
        status: 'updated',
        downloadedPercent: 100,
        message: isTauriRuntime
          ? tr(language, 'Обновление установлено встроенным updater. Перезапустите приложение, если новая версия не открылась автоматически.', 'The update was installed by the built-in updater. Restart the app if the new version did not open automatically.')
          : tr(language, 'Демо-установка завершена. В Tauri это действие поставит релиз пользователю.', 'Demo install completed. In Tauri this will install the release for the user.')
      }));
      if (!silent) {
        pushToast(tr(language, 'Обновление подготовлено.', 'Update prepared.'), 'success');
      }
    } finally {
      updaterActionLock.current = false;
    }
  }


  useEffect(() => {
    if (!settings.autoUpdate || hasAutoCheckedUpdates.current) {
      return;
    }

    hasAutoCheckedUpdates.current = true;
    void handleCheckUpdates(true, settings.autoInstallUpdates);
  }, [settings.autoUpdate, settings.autoInstallUpdates, settings.releaseChannel]);

  function toggleSetting(key: keyof Omit<AppSettings, 'releaseChannel' | 'protocolStrategy' | 'language' | 'allowDemoFallback' | 'tunnelMode'>) {
    setSettings((current: AppSettings) => {
      const next = { ...current, [key]: !current[key] };
      settingsRef.current = next;
      return next;
    });
  }

  async function handleExportDiagnosticsReport() {
    await runActionOnce('exportDiagnostics', async () => {
      const nativeLogLines = await readNativeRuntimeLog(120).catch(() => []);
      const payload = createSafeDiagnosticsPayload({
        appVersion,
        runtimeStatus,
        proxyStatus,
        connectivityProbe,
        diagnostics,
        profileSyncInfo,
        updateInfo: updateInfoRef.current,
        settings: settingsRef.current,
        session,
        nativeLogLines
      });

      downloadTextFile(buildDiagnosticsFilename(), payload);
      pushToast(tr(language, 'Безопасный диагностический отчёт сохранён.', 'Safe diagnostics report was saved.'), 'success');
      void writeNativeInterfaceLog('Пользователь экспортировал безопасный диагностический отчёт.');
    });
  }

  async function handleClearAccessKey() {
    await runActionOnce('logout', async () => {
      try {
        clearPendingConnectionQueue();

        if (isConnectionActionBusy()) {
          pendingDisconnectAfterBusyRef.current = true;
          scheduleConnectionQueueFlush('logout-queued-disconnect', 120);
          pushToast(
            tr(language, 'Выход выполнен. Активное подключение будет остановлено после текущего действия.', 'Signed out. The active connection will stop after the current action finishes.'),
            'info'
          );
        } else if (connectionStateRef.current === 'connected') {
          setConnectionStateSafe('disconnecting');
          await remnawaveClient.disconnect({ useSystemProxy: proxyStatusRef.current.enabled || shouldUseSystemProxy(settingsRef.current.tunnelMode, settingsRef.current.useSystemProxy) });
        }

        await clearStoredAccessKey();
        setAccessKey('');
        setIsAuthorized(false);
        setSession(null);
        setDevices([]);
        setSessionHistory([]);
        setDiagnostics(null);
        serversRef.current = [];
        setServers([]);
        selectedServerIdRef.current = '';
        setSelectedServerId('');
        setConnectivityProbe(null);
        setVpnExternalIp('—');
        setSessionDuration(0);
        if (!isConnectionActionBusy()) {
          setConnectionStateSafe('idle');
        }
        pushToast(tr(language, 'Ключ очищен, сессия завершена.', 'Key cleared and session ended.'), 'info');
      } catch (error) {
        setConnectionStateSafe('idle');
        pushToast(
          error instanceof Error
            ? error.message
            : tr(language, 'Не удалось полностью очистить сессию.', 'Failed to fully clear the session.'),
          'error'
        );
      }
    });
  }



  useEffect(() => {
    trayConnectActionRef.current = () => {
      void handleConnectionToggle();
    };
    trayRestartProxyActionRef.current = () => {
      void handleRestartSystemProxy();
    };
    trayLogoutActionRef.current = () => {
      void handleClearAccessKey();
    };
  });

  const diagnosticsStatus = diagnostics
    ? diagnostics.tunnelStatus === 'ok'
      ? tr(language, 'Диагностика в норме', 'Diagnostics are healthy')
      : tr(language, 'Есть сигналы к проверке', 'Some checks need attention')
    : tr(language, 'Диагностика загружается', 'Diagnostics are loading');

  if (!isAuthorized || !session) {
    return (
      <div className="shell auth-shell">
        <div className="window-frame desktop-frame">
          <WindowHeader
            session={null}
            currentVersion={updateInfo.currentVersion}
            updateInfo={updateInfo}
            language={language}
            minimizeToTray={settings.minimizeToTray}
            onToggleLanguage={() => setSettings((current: AppSettings) => ({ ...current, language: current.language === 'ru' ? 'en' : 'ru' }))}
            onCheckUpdates={() => void handleCheckUpdates()}
            onInstallUpdate={updateInfo.available ? () => void handleInstallUpdate() : undefined}
            onRequestHideToTray={() => void requestWindowHide()}
          />
          <AuthScreen
            accessKey={accessKey}
            authLoading={authLoading}
            errorText={errorText}
            integrationMeta={integrationMeta}
            language={language}
            onAccessKeyChange={setAccessKey}
            onAuthorize={handleAuthorize}
          />
        </div>
        <ToastViewport items={toasts} />
      </div>
    );
  }

  return (
    <div className={`shell app-shell ${settings.themeGlow ? 'glow-enabled' : 'glow-disabled'} ${isCheckingPing ? 'ping-background-active' : ''}`}>
      <div className="window-frame desktop-frame">
        <WindowHeader
          session={session}
          currentVersion={updateInfo.currentVersion}
          updateInfo={updateInfo}
          language={language}
          minimizeToTray={settings.minimizeToTray}
          onToggleLanguage={() => setSettings((current: AppSettings) => ({ ...current, language: current.language === 'ru' ? 'en' : 'ru' }))}
          onCheckUpdates={() => void handleCheckUpdates()}
          onInstallUpdate={updateInfo.available ? () => void handleInstallUpdate() : undefined}
          onRequestHideToTray={() => void requestWindowHide()}
        />

        <main className="workspace-grid">
          <SidebarNav
            activeTab={activeTab}
            onChange={setActiveTab}
            onExit={() => void handleClearAccessKey()}
            connectionState={connectionState}
            session={session}
            devices={devices}
            language={language}
            showDiagnostics={settings.showDiagnostics}
            onShowInfo={() => void handleOpenAppInfo()}
          />

          <section className={`content-area ${activeTab === 'overview' ? 'overview-content-area' : ''}`}>
            {activeTab === 'overview' ? (
              isBootstrapping && !servers.length ? (
                <StartupSkeleton language={language} />
              ) : (
              <OverviewTab
                connectionState={connectionState}
                connectLabel={connectLabel}
                selectedServer={selectedServer}
                selectedServerId={selectedServerId}
                servers={filteredServers}
                allServerCount={servers.length}
                searchValue={searchValue}
                sessionDurationText={sessionDurationText}
                language={language}
                showDiagnostics={settings.showDiagnostics}
                tunnelMode={settings.tunnelMode}
                onToggleConnection={handleConnectionToggle}
                onTunnelModeChange={(value) => void handleTunnelModeChange(value)}
                onSelectServer={(serverId) => void handleSelectServer(serverId)}
                onSearchChange={setSearchValue}
                onRefreshServers={() => void handleSyncProfile()}
                onRefreshPing={() => void handleRefreshPing()}
                onToggleFavoriteServer={handleToggleFavoriteServer}
                favoriteServerIds={favoriteServerIds}
                trafficReceivedText={formatTrafficBytes(trafficReceivedBytes)}
                trafficSentText={formatTrafficBytes(trafficSentBytes)}
                trafficChartBars={trafficChartBars}
                vpnExternalIp={connectionState === 'connected' ? vpnExternalIp : '—'}
                packetLossText={packetLossText}
                isCheckingPing={isCheckingPing}
                pingProgressText={pingProgress.active ? tr(language, `Пинг ${pingProgress.completed}/${pingProgress.total}`, `Ping ${pingProgress.completed}/${pingProgress.total}`) : ''}
                checkingPingServerIds={checkingPingServerIds}
                canConnect={canConnectSelectedServer}
                connectDisabledReason={connectionDisabledReason}
                isSyncingProfile={isSyncingProfile}
                activeSplitTunnelCount={activeSplitTunnelCount}
                onOpenSplitTunnel={handleOpenSplitTunnel}
              />
              )
            ) : null}

            {activeTab === 'support' ? (
              <TabErrorBoundary language={language} title={tr(language, 'Поддержка', 'Support')}>
                <SupportTab language={language} />
              </TabErrorBoundary>
            ) : null}

            {activeTab === 'diagnostics' && settings.showDiagnostics ? (
              <TabErrorBoundary language={language} title={tr(language, 'Состояние клиента', 'Client status')}>
                <DiagnosticsTab
                  diagnostics={diagnostics}
                  runtimeStatus={runtimeStatus}
                  proxyStatus={proxyStatus}
                  connectivityProbe={connectivityProbe}
                  profileSyncInfo={profileSyncInfo}
                  session={session}
                  integrationMeta={integrationMeta}
                  sessionHistory={sessionHistory}
                  updateInfo={updateInfo}
                  settings={settings}
                  language={language}
                  onEnableSystemProxy={handleEnableSystemProxy}
                  onDisableSystemProxy={handleDisableSystemProxy}
                  onRunConnectivityProbe={handleRunConnectivityProbe}
                  onSyncProfile={() => void handleSyncProfile()}
                  onCheckUpdates={() => void handleCheckUpdates()}
                  onInstallUpdate={updateInfo.available ? () => void handleInstallUpdate() : undefined}
                  onExportDiagnostics={() => void handleExportDiagnosticsReport()}
                  onClearAccessKey={handleClearAccessKey}
                  onReleaseChannelChange={(value) => setSettings((current: AppSettings) => ({ ...current, releaseChannel: value }))}
                  onProtocolStrategyChange={(value) => setSettings((current: AppSettings) => ({ ...current, protocolStrategy: value }))}
                  onTunnelModeChange={(value) => void handleTunnelModeChange(value)}
                  onLanguageChange={(value) => setSettings((current: AppSettings) => ({ ...current, language: value }))}
                  isProxyBusy={isActionBusy('proxy')}
                  isProbeBusy={isActionBusy('probe')}
                  isLogoutBusy={isActionBusy('logout')}
                  isSyncingProfile={isSyncingProfile}
                  isExportingDiagnostics={isActionBusy('exportDiagnostics')}
                />
              </TabErrorBoundary>
            ) : null}

            {activeTab === 'settings' ? (
              <SettingsTab
                settings={settings}
                language={language}
                onToggleSetting={toggleSetting}
                onTunnelModeChange={(value) => void handleTunnelModeChange(value)}
                onLanguageChange={(value) => setSettings((current: AppSettings) => ({ ...current, language: value }))}
              />
            ) : null}
          </section>
        </main>
      </div>

      <AppInfoModal
        open={isAppInfoOpen}
        language={language}
        info={nativeAppInfo}
        updateInfo={updateInfo}
        onCheckUpdates={() => void handleCheckUpdates()}
        onInstallUpdate={updateInfo.available ? () => void handleInstallUpdate() : undefined}
        onClose={() => setIsAppInfoOpen(false)}
      />
      <SplitTunnelModal
        open={isSplitTunnelOpen}
        language={language}
        entries={splitTunnelEntries}
        runningApps={runningApps}
        isLoadingApps={isLoadingRunningApps}
        isPickingExecutable={isActionBusy('pickExecutable')}
        onClose={() => setIsSplitTunnelOpen(false)}
        onAddEntry={handleAddSplitTunnelEntry}
        onToggleEntry={handleToggleSplitTunnelEntry}
        onRemoveEntry={handleRemoveSplitTunnelEntry}
        onPickExecutable={handlePickExecutableForSplitTunnel}
        onRefreshRunningApps={refreshRunningAppsForSplitTunnel}
      />

      <ToastViewport items={toasts} />
    </div>
  );
}
