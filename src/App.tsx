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
import { useConnectionStateController } from './hooks/useConnectionStateController';
import { useOperationManager } from './hooks/useOperationManager';
import { usePingManager } from './hooks/usePingManager';
import { useToastManager } from './hooks/useToastManager';
import { useSyncedRef } from './hooks/useSyncedRef';
import { buildDiagnosticsFilename, createSafeDiagnosticsPayload, downloadTextFile } from './utils/diagnosticsExport';
import { sleep } from './utils/async';
import { buildTrafficBars, formatTrafficBytes } from './utils/traffic';
import { assertNativeRuntimeServerMatches, runtimeConfirmsTargetServer } from './services/connectionGuards';
import { pickPreferredServer, rankServersForDisplay } from './utils/serverSorting';
import { buildServerRuntimeFingerprint, isVpnServerLike } from './utils/serverIdentity';
import { remnawaveClient } from './services/remnawave';
import {
  appVersion,
  ensureAdminLaunch,
  fetchPublicIpSnapshot,
  getIntegrationMeta,
  getNativeAppInfo,
  getNativeTrafficSnapshot,
  readNativeRuntimeLog,
  repairNativeRuntimeEnvironment,
  isTauriRuntime,
  listNativeRunningApps,
  pickNativeExecutablePath,
  requestWindowHide,
  setNativeLaunchOnStartup,
  setNativeSessionAuthorized,
  setNativeTrayUpdateState,
  writeNativeInterfaceLog,
  writeNativeRoutingLog,
  normalizeNativeError
} from './services/runtime';
import {
  clearLastKnownServers,
  clearStoredAccessKey,
  loadFavoriteServerIds,
  loadFavoriteServerIdsBackup,
  loadSelectedServerId,
  loadSelectedServerIdBackup,
  loadSettings,
  loadSettingsBackup,
  loadSplitTunnelEntries,
  loadSplitTunnelEntriesBackup,
  loadLastKnownServers,
  loadLastKnownServersBackup,
  loadStoredAccessKey,
  loadStoredAccessKeySecure,
  saveFavoriteServerIds,
  saveLastKnownServers,
  saveSelectedServerId,
  saveSettings,
  saveSplitTunnelEntries,
  saveStoredAccessKey
} from './services/storage';
import { checkForUpdates, installAvailableUpdate } from './services/updater';
import type { PendingServerSwitch } from './types/appState';
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
  UpdateInfo,
  VpnServer
} from './types/vpn';

const integrationMeta = getIntegrationMeta();



export default function App() {
  const [accessKey, setAccessKey] = useState(() => loadStoredAccessKey());
  const [settings, setSettings] = useState<AppSettings>(() => loadSettings());
  const language = settings.language;
  const [splitTunnelEntries, setSplitTunnelEntries] = useState<SplitTunnelEntry[]>(() => loadSplitTunnelEntries());
  const [activeTab, setActiveTab] = useState<AppTab>('overview');
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [authLoading, setAuthLoading] = useState(false);
  const { connectionState, connectionStateRef, connectionActionStartedAt, setConnectionStateSafe } = useConnectionStateController('idle');
  const [servers, setServers] = useState<VpnServer[]>([]);
  const [selectedServerId, setSelectedServerId] = useState(() => loadSelectedServerId());
  const [connectedServerId, setConnectedServerId] = useState('');
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
  const [searchValue, setSearchValue] = useState('');
  const [isSyncingProfile, setIsSyncingProfile] = useState(false);
  const operationManager = useOperationManager();
  const [persistentStateReady, setPersistentStateReady] = useState(!isTauriRuntime);
  const [isBootstrapping, setIsBootstrapping] = useState(true);
  const { toasts, pushToast } = useToastManager(settings.notifications);
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
  const updateInfoRef = useSyncedRef(updateInfo);
  const authorizedAccessKeyRef = useRef('');
  const persistentRestoreStarted = useRef(false);
  const hasAutoCheckedUpdates = useRef(false);

  const hasTriedFavoriteAutoConnect = useRef(false);
  const hasTriedAdminLaunch = useRef(false);
  const lastRuntimeTunnelActive = useRef(false);
  const lostRuntimePollCount = useRef(0);
  const lastNativeRuntimeStopToastAt = useRef(0);
  const lastAppliedSplitTunnelSignature = useRef('');
  const initialProtocolStrategy = useRef(settings.protocolStrategy);
  const connectionActionLock = useRef(false);
  const updaterActionLock = useRef(false);
  const selectedServerIdRef = useSyncedRef(selectedServerId);
  const connectedServerIdRef = useSyncedRef(connectedServerId);
  const overviewAutoRefreshAtRef = useRef(0);
  const serversRef = useSyncedRef(servers);
  const settingsRef = useSyncedRef(settings);
  const splitTunnelEntriesRef = useSyncedRef(splitTunnelEntries);
  const favoriteServerIdsRef = useSyncedRef(favoriteServerIds);
  const proxyStatusRef = useSyncedRef(proxyStatus);
  const runtimeStatusRef = useSyncedRef(runtimeStatus);
  const managedReconnectRef = useRef<{ targetServerId: string; previousServerId: string; startedAt: number } | null>(null);
  const runtimeStopIgnoreUntilRef = useRef(0);
  const connectionAttemptSeqRef = useRef(0);
  const vpnIpProbeSeqRef = useRef(0);
  const postConnectProbeSeqRef = useRef(0);
  const pendingServerSwitchRef = useRef<PendingServerSwitch | null>(null);
  const pendingTunnelModeRef = useRef<AppSettings['tunnelMode'] | null>(null);
  const pendingIpStackRef = useRef<AppSettings['ipStack'] | null>(null);
  const pendingSplitTunnelReconnectRef = useRef(false);
  const pendingDisconnectAfterBusyRef = useRef(false);
  const connectionQueueFlushScheduled = useRef(false);
  const connectionQueueFlushRunning = useRef(false);
  const runtimePollInFlight = useRef(false);
  const postConnectProbeInFlight = useRef(false);
  const manualRefreshInFlight = useRef(false);
  const profileSyncInFlightRef = useRef(false);
  const snapshotRefreshQueued = useRef(false);
  const trayConnectActionRef = useRef<() => void>(() => undefined);
  const trayRestartProxyActionRef = useRef<() => void>(() => undefined);
  const trayLogoutActionRef = useRef<() => void>(() => undefined);

  const {
    isCheckingPing,
    pingProgress,
    checkingPingServerIds,
    refreshPing: handleRefreshPing,
    scheduleAutoPing
  } = usePingManager({
    servers,
    setServers,
    connectionState,
    selectedServerId,
    connectedServerId,
    runtimeStatus,
    language,
    setConnectivityProbe,
    pushToast,
    refreshDiagnosticsAndRuntime
  });

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
      if (waitedMs < 78_000) {
        return;
      }

      connectionActionLock.current = false;
      connectionQueueFlushRunning.current = false;
      finishManagedReconnect();
      void writeNativeRoutingLog(
        'Watchdog разблокировал UI после долгого действия подключения.',
        `${observedState} | ${Math.round(waitedMs / 1000)}s`
      );

      void refreshDiagnosticsAndRuntime().then((runtime) => {
        if (connectionStateRef.current !== observedState) {
          return;
        }

        const runtimeServerId = runtime?.lastPreparedServerId || connectedServerIdRef.current || '';
        if (runtime?.tunnelActive && runtimeServerId) {
          connectedServerIdRef.current = runtimeServerId;
          setConnectedServerId(runtimeServerId);
          selectedServerIdRef.current = runtimeServerId;
          setSelectedServerId(runtimeServerId);
          setConnectionStateSafe('connected');
        } else {
          setConnectionStateSafe('idle');
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
    }, 80_000);

    return () => window.clearTimeout(timer);
  }, [connectionState, language, pushToast, setConnectionStateSafe]);


  useEffect(() => {
    const updateBusy = ['checking', 'downloading', 'installing'].includes(updateInfo.status);
    void setNativeTrayUpdateState(Boolean(updateInfo.available), updateBusy);
  }, [updateInfo.available, updateInfo.status]);

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
    if (!isAuthorized || activeTab !== 'overview' || !accessKey.trim()) {
      return;
    }

    const now = Date.now();
    if (now - overviewAutoRefreshAtRef.current < 120_000) {
      return;
    }

    overviewAutoRefreshAtRef.current = now;
    void handleSyncProfile(true);
  }, [accessKey, activeTab, isAuthorized]);

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

      const localLastKnownServers = loadLastKnownServers();
      if (localLastKnownServers.length) {
        remnawaveClient.hydrateCachedServers(localLastKnownServers);
        serversRef.current = localLastKnownServers;
        setServers(localLastKnownServers);
      }

      const [serversResult, historyResult, devicesResult, runtimeSnapshotResult, lastKnownBackupResult] = await Promise.allSettled([
        remnawaveClient.loadServers(),
        remnawaveClient.loadHistory(),
        remnawaveClient.loadDevices(),
        remnawaveClient.loadRuntimeSnapshot(),
        loadLastKnownServersBackup()
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

      const currentServersNeedSecureRuntimeCache = !serversRef.current.length || !serversRef.current.some((server: VpnServer) => server.runtimeTemplate);
      if (currentServersNeedSecureRuntimeCache && lastKnownBackupResult.status === 'fulfilled' && lastKnownBackupResult.value?.length) {
        const backupServers = lastKnownBackupResult.value;
        remnawaveClient.hydrateCachedServers(backupServers);
        serversRef.current = backupServers;
        setServers(backupServers);
        const preferredServer = pickPreferredServer(backupServers, initialProtocolStrategy.current);
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

          if (event.payload === 'check_updates') {
            setActiveTab('overview');
            void handleCheckUpdates();
            return;
          }

          if (event.payload === 'install_update') {
            setActiveTab('overview');
            void handleInstallUpdate();
            return;
          }

          if (event.payload === 'logout') {
            setActiveTab('overview');
            trayLogoutActionRef.current();
          }
        });

        const unlistenNativeDisconnect = await eventApi.listen<string>('vkarmani://native-disconnect', () => {
          if (shouldIgnoreNativeRuntimeStop()) {
            void writeNativeRoutingLog('Native runtime stop event проигнорирован во время управляемого переключения/действия подключения.');
            return;
          }

          const hadActiveRuntime = connectionStateRef.current === 'connected'
            || connectionStateRef.current === 'connecting'
            || Boolean(connectedServerIdRef.current)
            || lastRuntimeTunnelActive.current;

          if (!hadActiveRuntime) {
            void writeNativeRoutingLog('Native runtime stop event получен в idle-состоянии и не показывается пользователю как ошибка.');
            void refreshDiagnosticsAndRuntime();
            return;
          }

          lastRuntimeTunnelActive.current = false;
          lostRuntimePollCount.current = 0;
          setConnectedServerId('');
          connectedServerIdRef.current = '';
          setConnectionStateSafe('idle');
          setVpnExternalIp('—');
          setConnectivityProbe(null);
          setSessionDuration(0);
          void refreshDiagnosticsAndRuntime();
          void refreshPrimaryExternalIp();

          const now = Date.now();
          if (now - lastNativeRuntimeStopToastAt.current < 30000) {
            void writeNativeRoutingLog('Повторное уведомление о native runtime stop скрыто антиспам-защитой.');
            return;
          }
          lastNativeRuntimeStopToastAt.current = now;

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

        if (!nextRuntime.tunnelActive && shouldIgnoreNativeRuntimeStop()) {
          void writeNativeRoutingLog('Runtime snapshot временно неактивен во время управляемого подключения/переключения, состояние UI не сбрасываем.');
          return;
        }

        if (nextRuntime.tunnelActive) {
          lostRuntimePollCount.current = 0;
          lastRuntimeTunnelActive.current = true;
          const runtimeServerId = nextRuntime.lastPreparedServerId || connectedServerIdRef.current || selectedServerIdRef.current;
          setConnectedServerId(runtimeServerId);
          connectedServerIdRef.current = runtimeServerId;
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
        setConnectedServerId('');
        connectedServerIdRef.current = '';
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
        selectedServerIdRef.current = current;
        return current;
      }

      // Во время активного подключения/переключения нельзя автоматически прыгать
      // на preferred/первый сервер: так появлялась ложная галка и иногда
      // подключение уходило на США вместо выбранного избранного сервера.
      if (connectionStateRef.current !== 'idle' || connectedServerIdRef.current) {
        selectedServerIdRef.current = current;
        return current;
      }

      const nextId = pickPreferredServer(servers, settings.protocolStrategy)?.id ?? current;
      selectedServerIdRef.current = nextId;
      return nextId;
    });
  }, [servers, settings.protocolStrategy]);


  const selectedServer = useMemo(
    () => servers.find((server: VpnServer) => server.id === selectedServerId) ?? null,
    [servers, selectedServerId]
  );

  const activeConnectionServerId = connectionState === 'connected'
    ? connectedServerId || runtimeStatus.lastPreparedServerId || selectedServerId
    : selectedServerId;


  const visibleSelectedServer = useMemo(
    () => (connectionState === 'connected'
      ? servers.find((server: VpnServer) => server.id === activeConnectionServerId) ?? selectedServer
      : selectedServer),
    [activeConnectionServerId, connectionState, selectedServer, servers]
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
    const displayRankedServers = rankServersForDisplay(servers, settings.protocolStrategy, favoriteServerIds);

    if (!normalized) {
      return displayRankedServers;
    }

    return displayRankedServers.filter((server: VpnServer) => {
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
  }, [deferredSearchValue, servers, settings.protocolStrategy, favoriteServerIds]);

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
  const connectionDisabledReason = connectionState === 'idle'
    ? !selectedServer
      ? tr(language, 'Сначала синхронизируйте профиль и выберите сервер.', 'Sync the profile and choose a server first.')
      : !selectedServer.runtimeTemplate
        ? tr(language, 'У выбранного сервера ещё нет runtime-конфига.', 'The selected server has no runtime config yet.')
        : settings.tunnelMode === 'tun' && activeSplitTunnelCount === 0
          ? tr(language, 'Для TUN добавьте хотя бы одну программу или службу.', 'Add at least one app or service for TUN.')
          : ''
    : '';
  const canConnectSelectedServer = connectionState !== 'idle' || !connectionDisabledReason;

  useEffect(() => {
    if (!isTauriRuntime || connectionState !== 'idle' || runtimeStatus.coreInstalled) {
      return;
    }

    const timer = window.setTimeout(() => {
      void refreshDiagnosticsAndRuntime();
    }, 250);

    return () => {
      window.clearTimeout(timer);
    };
  }, [connectionState, runtimeStatus.coreInstalled]);

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
    if (!settingsRef.current.probeOnConnect) {
      return;
    }

    const expectedServerId = server?.id ?? connectedServerIdRef.current;
    const probeSeq = ++postConnectProbeSeqRef.current;
    postConnectProbeInFlight.current = true;

    void remnawaveClient.runConnectivityProbe()
      .then((probe) => {
        // Старый probe от предыдущего сервера не имеет права перезаписать IP/diagnostics
        // нового подключения. Это была одна из причин, почему после переключения в UI
        // часто оставался IP прежнего сервера.
        if (
          postConnectProbeSeqRef.current !== probeSeq ||
          connectionStateRef.current !== 'connected' ||
          (expectedServerId && connectedServerIdRef.current !== expectedServerId)
        ) {
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
        if (postConnectProbeSeqRef.current !== probeSeq) {
          return;
        }
        void writeNativeRoutingLog(
          'Фоновая проверка маршрута после подключения не выполнена.',
          normalizeNativeError(error, 'post-connect probe failed').message
        );
      })
      .finally(() => {
        if (postConnectProbeSeqRef.current === probeSeq) {
          postConnectProbeInFlight.current = false;
        }
      });
  }

  function invalidateConnectionProbes() {
    vpnIpProbeSeqRef.current += 1;
    postConnectProbeSeqRef.current += 1;
    postConnectProbeInFlight.current = false;
    setConnectivityProbe(null);
    setVpnExternalIp('—');
  }

  function scheduleVpnIpRefreshForServer(serverId: string, fallbackIp?: string) {
    const ipProbeId = ++vpnIpProbeSeqRef.current;
    void refreshVpnExternalIpWithRetry().then((resolvedVpnIp) => {
      if (vpnIpProbeSeqRef.current !== ipProbeId || connectedServerIdRef.current !== serverId) {
        return;
      }
      if (!resolvedVpnIp && fallbackIp) {
        setVpnExternalIp(fallbackIp);
      }
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

  function updateIpStackPreference(value: AppSettings['ipStack']) {
    settingsRef.current = {
      ...settingsRef.current,
      ipStack: value
    };

    setSettings((current: AppSettings) => ({
      ...current,
      ipStack: value
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

  function nextConnectionAttemptId() {
    connectionAttemptSeqRef.current += 1;
    return connectionAttemptSeqRef.current;
  }

  function isConnectionAttemptCurrent(attemptId: number) {
    return connectionAttemptSeqRef.current === attemptId;
  }

  function isNativeConnectStillRunningError(message: string) {
    return message.includes('Подключение заняло больше')
      || message.includes('UI разблокирован');
  }

  function isTransientReconnectStartError(message: string) {
    return message.includes('Runtime уже выполняет другое действие')
      || message.includes('Локальные порты VKarmani уже заняты')
      || message.includes('локальные порты не стали готовы')
      || message.includes('Xray runtime не стал готовым')
      || message.includes('Connection refused')
      || message.includes('operation')
      || message.includes('порт');
  }

  function shouldIgnoreNativeRuntimeStop() {
    return Boolean(managedReconnectRef.current) || Date.now() < runtimeStopIgnoreUntilRef.current || isConnectionActionBusy();
  }

  function beginManagedReconnect(targetServerId: string, previousServerId: string) {
    managedReconnectRef.current = {
      targetServerId,
      previousServerId,
      startedAt: Date.now()
    };
    runtimeStopIgnoreUntilRef.current = Date.now() + 20_000;
  }

  function finishManagedReconnect() {
    managedReconnectRef.current = null;
    runtimeStopIgnoreUntilRef.current = Date.now() + 2500;
  }

  function getConnectedRuntimeServerId() {
    return connectedServerIdRef.current || runtimeStatusRef.current.lastPreparedServerId || '';
  }

  function getConnectedRuntimeServer() {
    const runtimeServerId = getConnectedRuntimeServerId();
    return runtimeServerId ? getServerById(runtimeServerId) : null;
  }

  async function waitForConnectionActionToFinish(timeoutMs = 45_000) {
    const startedAt = Date.now();
    while (isConnectionActionBusy()) {
      if (Date.now() - startedAt >= timeoutMs) {
        return false;
      }
      await sleep(200);
    }
    return true;
  }

  function hasPendingConnectionActions() {
    return Boolean(
      pendingDisconnectAfterBusyRef.current ||
      pendingTunnelModeRef.current ||
      pendingIpStackRef.current ||
      pendingServerSwitchRef.current ||
      pendingSplitTunnelReconnectRef.current
    );
  }

  function clearPendingConnectionQueue() {
    pendingServerSwitchRef.current = null;
    pendingTunnelModeRef.current = null;
    pendingIpStackRef.current = null;
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
            setConnectedServerId('');
            connectedServerIdRef.current = '';
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
          const serverForReconnect = getConnectedRuntimeServer() ?? getServerById(selectedServerIdRef.current) ?? selectedServer;
          if (serverForReconnect?.runtimeTemplate) {
            void writeNativeRoutingLog('Применяем отложенное изменение режима маршрутизации.', `${reason} | mode=${queuedMode}`);
            await handleReconnectToServer(serverForReconnect, serverForReconnect);
            return;
          }
        }
      }

      const queuedIpStack = pendingIpStackRef.current;
      if (queuedIpStack) {
        pendingIpStackRef.current = null;

        if (connectionStateRef.current === 'connected') {
          const serverForReconnect = getConnectedRuntimeServer() ?? getServerById(selectedServerIdRef.current) ?? selectedServer;
          if (serverForReconnect?.runtimeTemplate) {
            void writeNativeRoutingLog('Применяем отложенное изменение IP-стека.', `${reason} | ipStack=${queuedIpStack}`);
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

        const nextRuntimeServer = await resolveServerForConnection(nextServer, false);
        if (!nextRuntimeServer?.runtimeTemplate || nextRuntimeServer.id !== nextServer.id) {
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
          void writeNativeRoutingLog('Выполняем отложенное переключение сервера.', `${reason} | ${nextRuntimeServer.country}, ${nextRuntimeServer.city}`);
          await handleReconnectToServer(nextRuntimeServer, previousServer ?? nextRuntimeServer);
          return;
        }
      }

      if (pendingSplitTunnelReconnectRef.current) {
        pendingSplitTunnelReconnectRef.current = false;

        if (settingsRef.current.tunnelMode === 'tun' && connectionStateRef.current === 'connected') {
          const serverForReconnect = getConnectedRuntimeServer() ?? getServerById(selectedServerIdRef.current) ?? selectedServer;
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


  async function handleRepairRuntimeEnvironment() {
    await runActionOnce('repairRuntime', async () => {
      try {
        const runtime = await repairNativeRuntimeEnvironment();
        setRuntimeStatus(runtime);
        setConnectivityProbe(null);
        setVpnExternalIp('—');
        await refreshDiagnosticsAndRuntime();
        pushToast(
          tr(language, 'Runtime окружение восстановлено: proxy, TUN-маршруты и временные конфиги очищены.', 'Runtime environment repaired: proxy, TUN routes, and temporary configs were cleaned.'),
          'success'
        );
        void writeNativeRoutingLog('Пользователь запустил восстановление runtime окружения.');
      } catch (error) {
        pushToast(
          normalizeNativeError(error, tr(language, 'Не удалось восстановить runtime окружение.', 'Failed to repair runtime environment.')).message,
          'error'
        );
      }
    });
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
    let managedModeReconnectStarted = false;
    try {
      const previousMode = currentSettings.tunnelMode;
      const previousUseSystemProxy = currentSettings.useSystemProxy;
      const serverForReconnect = getConnectedRuntimeServer() ?? getServerById(selectedServerIdRef.current) ?? selectedServer;
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

      beginManagedReconnect(serverForReconnect.id, serverForReconnect.id);
      managedModeReconnectStarted = true;

      try {
        setConnectionStateSafe('disconnecting');
        await sleep(30);
        await remnawaveClient.disconnect({ useSystemProxy: proxyStatusRef.current.enabled || (previousMode !== 'tun' && previousUseSystemProxy) });
        setVpnExternalIp('—');
        setConnectivityProbe(null);
        setSessionDuration(0);

        invalidateConnectionProbes();

        setConnectionStateSafe('connecting');
        await sleep(30);
        const response = await remnawaveClient.connect(serverForReconnect, {
          useSystemProxy: shouldUseSystemProxy(nextMode, previousUseSystemProxy),
          probeAfterConnect: false,
          tunnelMode: nextMode,
          splitTunnelEntries: splitTunnelEntriesRef.current,
          ipStack: settingsRef.current.ipStack,
              routingExclusions: settingsRef.current.routingExclusions
        });
        setConnectivityProbe(response.probe ?? null);
        if (response.proxy) {
          setProxyStatus(response.proxy);
        }
        setSessionDuration(0);
        setConnectedServerId(serverForReconnect.id);
        connectedServerIdRef.current = serverForReconnect.id;
        setConnectionStateSafe('connected');
        runPostConnectProbe(serverForReconnect);
        void refreshDiagnosticsAndRuntime();
        scheduleVpnIpRefreshForServer(serverForReconnect.id, response.probe?.publicIp ?? response.externalIp);
        void writeNativeRoutingLog('Режим маршрутизации переключён.', `${previousMode} -> ${nextMode} | сервер ${serverForReconnect.country}, ${serverForReconnect.city}`);
        pushToast(
          nextMode === 'tun'
            ? tr(language, 'Режим переключён на TUN.', 'The mode was switched to TUN.')
            : tr(language, 'Режим переключён на proxy.', 'The mode was switched to proxy.'),
          'success'
        );
      } catch (error) {
        const modeError = normalizeNativeError(
          error,
          tr(language, 'Не удалось переключить режим туннеля.', 'Failed to switch the tunnel mode.')
        );
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
        void writeNativeRoutingLog('Ошибка при переключении режима маршрутизации.', modeError.message);

        let rollbackSucceeded = false;
        if (serverForReconnect?.runtimeTemplate) {
          try {
            void writeNativeRoutingLog('Пробуем вернуть прежний режим маршрутизации.', `${previousMode} | ${serverForReconnect.country}, ${serverForReconnect.city}`);
            invalidateConnectionProbes();
            setConnectionStateSafe('connecting');
            await sleep(120);
            const rollbackResponse = await remnawaveClient.connect(serverForReconnect, {
              useSystemProxy: shouldUseSystemProxy(previousMode, previousUseSystemProxy),
              probeAfterConnect: false,
              tunnelMode: previousMode,
              splitTunnelEntries: splitTunnelEntriesRef.current,
              ipStack: settingsRef.current.ipStack,
              routingExclusions: settingsRef.current.routingExclusions
            });
            setConnectivityProbe(rollbackResponse.probe ?? null);
            if (rollbackResponse.proxy) {
              setProxyStatus(rollbackResponse.proxy);
            }
            setSessionDuration(0);
            setConnectedServerId(serverForReconnect.id);
            connectedServerIdRef.current = serverForReconnect.id;
            setConnectionStateSafe('connected');
            rollbackSucceeded = true;
            runPostConnectProbe(serverForReconnect);
            void refreshDiagnosticsAndRuntime();
            scheduleVpnIpRefreshForServer(serverForReconnect.id, rollbackResponse.probe?.publicIp ?? rollbackResponse.externalIp);
            pushToast(
              tr(language, 'Новый режим не запустился, прежнее подключение восстановлено.', 'The new mode failed, the previous connection was restored.'),
              'info'
            );
          } catch (rollbackError) {
            void writeNativeRoutingLog(
              'Rollback на прежний режим тоже не удался.',
              normalizeNativeError(rollbackError, 'mode rollback failed').message
            );
          }
        }

        if (!rollbackSucceeded) {
          setConnectionStateSafe('idle');
          setConnectedServerId('');
          connectedServerIdRef.current = '';
          setVpnExternalIp('—');
          setConnectivityProbe(null);
          setSessionDuration(0);
          await refreshDiagnosticsAndRuntime();
          await refreshPrimaryExternalIp();
          pushToast(modeError.message, 'error');
        }
      }
    } finally {
      if (managedModeReconnectStarted) {
        finishManagedReconnect();
      }
      connectionActionLock.current = false;
      scheduleConnectionQueueFlush('after-tunnel-mode-change');
    }
  }

  async function handleIpStackChange(nextStack: AppSettings['ipStack']) {
    const currentSettings = settingsRef.current;

    if (nextStack === currentSettings.ipStack && !pendingIpStackRef.current) {
      return;
    }

    if (isConnectionActionBusy()) {
      updateIpStackPreference(nextStack);
      pendingIpStackRef.current = nextStack;
      pushToast(
        tr(language, 'IP-режим выбран. Применим его после завершения текущего действия подключения.', 'IP mode selected. It will be applied after the current connection action finishes.'),
        'info'
      );
      void writeNativeRoutingLog('Изменение IP-стека поставлено в очередь.', `${currentSettings.ipStack} -> ${nextStack}`);
      scheduleConnectionQueueFlush('queued-ip-stack-change');
      return;
    }

    const serverForReconnect = getConnectedRuntimeServer() ?? getServerById(selectedServerIdRef.current) ?? selectedServer;
    const previousStack = currentSettings.ipStack;
    updateIpStackPreference(nextStack);
    void writeNativeInterfaceLog('Пользователь меняет IP-стек Xray.', `${previousStack} -> ${nextStack}`);

    if (connectionStateRef.current !== 'connected' || !serverForReconnect?.runtimeTemplate) {
      pushToast(
        nextStack === 'ipv6'
          ? tr(language, 'Выбран IPv6. Он применится при следующем подключении.', 'IPv6 selected. It will apply on the next connection.')
          : tr(language, 'Выбран IPv4. Он применится при следующем подключении.', 'IPv4 selected. It will apply on the next connection.'),
        'info'
      );
      return;
    }

    await handleReconnectToServer(serverForReconnect, serverForReconnect, { ipStack: previousStack });
  }

  async function handleSyncProfile(silent = false, accessKeyOverride?: string) {
    const normalizedAccessKey = (accessKeyOverride ?? accessKey).trim();
    if (!normalizedAccessKey) {
      return null;
    }

    if (profileSyncInFlightRef.current) {
      return null;
    }

    if (isConnectionActionBusy()) {
      if (!silent) {
        pushToast(
          tr(language, 'Сейчас идёт подключение или переключение сервера. Обновление серверов можно запустить сразу после завершения.', 'A connection or server switch is in progress. Refresh servers after it finishes.'),
          'info'
        );
      }
      return null;
    }

    profileSyncInFlightRef.current = true;

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
      saveLastKnownServers(result.servers);
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
        if (connectionStateRef.current !== 'idle') {
          const activeId = connectedServerIdRef.current || runtimeStatusRef.current.lastPreparedServerId || current;
          selectedServerIdRef.current = activeId;
          return activeId;
        }

        const nextId = result.servers.some((item: VpnServer) => item.id === current)
          ? current
          : preferredServer?.id ?? current;
        selectedServerIdRef.current = nextId;
        return nextId;
      });

      if (!isConnectionActionBusy()) {
        await refreshDiagnosticsAndRuntime();
      }
      void writeNativeInterfaceLog(
        'Профиль Remnawave синхронизирован.',
        `${result.profile.configCount} конфигов | источник: ${result.profile.sourceLabel}`
      );

      scheduleAutoPing(silent ? 'silent-profile-sync' : 'manual-profile-sync');

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
      profileSyncInFlightRef.current = false;
      setIsSyncingProfile(false);
    }
  }

  async function authorizeWithAccessKey(rawAccessKey: string, connectFavoriteAfterLaunch = false) {
    const normalizedAccessKey = rawAccessKey.trim();

    if (!normalizedAccessKey) {
      setErrorText(tr(language, 'Сначала вставьте ключ доступа.', 'Paste the access key first.'));
      return;
    }

    if (!normalizedAccessKey.toLowerCase().startsWith('https://sub.vkarmani.com/')) {
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
      authorizedAccessKeyRef.current = normalizedAccessKey;
      setSession(response);
      const nextDevices = await remnawaveClient.loadDevices();
      setDevices(nextDevices);
      const keyPersisted = await saveStoredAccessKey(normalizedAccessKey);
      setIsAuthorized(true);
      const nativeSessionReady = await setNativeSessionAuthorized(true);

      if (!connectFavoriteAfterLaunch) {
        pushToast(tr(language, 'Ключ доступа принят.', 'Access key accepted.'), 'success');
        if (!keyPersisted) {
          pushToast(
            tr(language, 'Ключ принят, но не сохранён: защищённое хранилище Windows временно недоступно.', 'The key was accepted but not saved: Windows secure storage is temporarily unavailable.'),
            'error'
          );
        }
        if (!nativeSessionReady) {
          pushToast(
            tr(language, 'Native-сессия не подтверждена через защищённое хранилище Windows. Перезапустите приложение и войдите по ключу ещё раз.', 'Native session was not confirmed through Windows secure storage. Restart the app and sign in again.'),
            'error'
          );
        }
      }
      void writeNativeInterfaceLog('Авторизация по ключу доступа завершена успешно.');

      overviewAutoRefreshAtRef.current = Date.now();
      let serverPool = await remnawaveClient.loadServers();
      if (serverPool.length) {
        serversRef.current = serverPool;
        setServers(serverPool);
        saveLastKnownServers(serverPool);
        setFavoriteServerIds((current) => current.filter((id) => serverPool.some((server: VpnServer) => server.id === id)));
        setProfileSyncInfo(remnawaveClient.getProfileSyncInfo());

        const preferredServer = pickPreferredServer(serverPool, currentSettings.protocolStrategy);
        setSelectedServerId((current: string) => {
          const nextId = serverPool.some((item: VpnServer) => item.id === current)
            ? current
            : preferredServer?.id ?? current;
          selectedServerIdRef.current = nextId;
          return nextId;
        });
      } else {
        serverPool = serversRef.current;
      }

      let preferredServerForAutoConnect = serverPool.find((server: VpnServer) => server.id === selectedServerIdRef.current)
        ?? pickPreferredServer(serverPool, currentSettings.protocolStrategy)
        ?? selectedServer;

      const shouldRunLoginSync = currentSettings.profileSyncOnLogin && !serverPool.length;
      const syncResult = shouldRunLoginSync
        ? await handleSyncProfile(true, normalizedAccessKey)
        : null;
      if (syncResult?.servers) {
        serverPool = syncResult.servers;
        saveLastKnownServers(syncResult.servers);
        preferredServerForAutoConnect = pickPreferredServer(syncResult.servers, currentSettings.protocolStrategy);
      } else if (!currentSettings.profileSyncOnLogin && !connectFavoriteAfterLaunch && !serverPool.length) {
        setProfileSyncInfo((current: ProfileSyncInfo) => ({
          ...current,
          status: 'idle',
          message: tr(language, 'Автосинхронизация профиля отключена. Нажмите «Обновить профиль», когда нужно загрузить серверы.', 'Profile auto-sync is disabled. Click “Refresh profile” when you need to load servers.')
        }));
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

  async function handleReconnectToServer(nextServer: VpnServer, previousServer: VpnServer | null, rollbackSettings?: Partial<AppSettings>) {
    const currentConnectedServer = getConnectedRuntimeServer();
    const rollbackServer = currentConnectedServer ?? previousServer;

    if (isConnectionActionBusy()) {
      pendingServerSwitchRef.current = {
        nextServerId: nextServer.id,
        previousServerId: rollbackServer?.id ?? selectedServerIdRef.current
      };
      scheduleConnectionQueueFlush('queued-reconnect');
      return;
    }

    connectionActionLock.current = true;
    const attemptId = nextConnectionAttemptId();
    beginManagedReconnect(nextServer.id, rollbackServer?.id ?? '');
    let pendingTargetServer = nextServer;

    try {
      const currentSettings = settingsRef.current;
      const currentSplitTunnelEntries = splitTunnelEntriesRef.current;
      let targetServer = await resolveServerForConnection(nextServer);

      if (!targetServer?.runtimeTemplate) {
        if (rollbackServer?.id) {
          selectedServerIdRef.current = rollbackServer.id;
          setSelectedServerId(rollbackServer.id);
        }
        pushToast(
          tr(language, 'Для выбранного сервера нет готового live-конфига. Переключение отменено.', 'The selected server has no ready live config. Switching was cancelled.'),
          'info'
        );
        setConnectionStateSafe(rollbackServer ? 'connected' : 'idle');
        return;
      }

      if (targetServer.id !== nextServer.id) {
        throw new Error('Подготовлен не тот сервер. Переключение остановлено, чтобы не выбрать случайный узел.');
      }
      pendingTargetServer = targetServer;

      if (currentSettings.tunnelMode === 'tun' && getActiveSplitTunnelEntries(currentSplitTunnelEntries).length === 0) {
        if (rollbackServer?.id) {
          selectedServerIdRef.current = rollbackServer.id;
          setSelectedServerId(rollbackServer.id);
        }
        pushToast(
          tr(language, 'Для TUN сначала добавьте хотя бы одну программу или службу.', 'For TUN, add at least one program or service first.'),
          'info'
        );
        setConnectionStateSafe(rollbackServer ? 'connected' : 'idle');
        return;
      }

      void writeNativeRoutingLog(
        'Начато управляемое переключение сервера.',
        `${rollbackServer ? `${rollbackServer.country}, ${rollbackServer.city}` : 'нет активного сервера'} → ${targetServer.country}, ${targetServer.city} | mode=${currentSettings.tunnelMode}`
      );

      invalidateConnectionProbes();

      setConnectionStateSafe('connecting');
      await sleep(30);

      const reconnectOptions = {
        useSystemProxy: shouldUseSystemProxy(currentSettings.tunnelMode, currentSettings.useSystemProxy),
        probeAfterConnect: false,
        tunnelMode: currentSettings.tunnelMode,
        splitTunnelEntries: currentSplitTunnelEntries,
        ipStack: currentSettings.ipStack,
        routingExclusions: currentSettings.routingExclusions,
        reconnect: true
      };
      let response: ConnectResult | null = null;
      let lastStartError: unknown = null;

      for (let attemptIndex = 0; attemptIndex < 3; attemptIndex += 1) {
        try {
          response = await remnawaveClient.connect(targetServer, reconnectOptions);
          break;
        } catch (startError) {
          lastStartError = startError;
          const startMessage = normalizeNativeError(startError, '').message;
          if (isNativeConnectStillRunningError(startMessage) || !isTransientReconnectStartError(startMessage) || attemptIndex >= 2) {
            throw startError;
          }

          void writeNativeRoutingLog(
            'Запуск выбранного сервера временно сорвался, повторяем без rollback.',
            `attempt=${attemptIndex + 1}/3 | ${startMessage}`
          );
          await sleep(attemptIndex === 0 ? 550 : 1250);
          await refreshDiagnosticsAndRuntime();
        }
      }

      if (!response) {
        throw lastStartError ?? new Error('Не удалось получить ответ runtime после переключения сервера.');
      }

      if (!isConnectionAttemptCurrent(attemptId)) {
        void writeNativeRoutingLog('Устаревший результат переключения сервера проигнорирован.', `${targetServer.country}, ${targetServer.city}`);
        return;
      }

      const nativeServerId = response.runtime?.lastPreparedServerId;
      assertNativeRuntimeServerMatches(
        nativeServerId,
        targetServer.id,
        response.runtime?.lastPreparedServerFingerprint,
        buildServerRuntimeFingerprint(targetServer)
      );

      setErrorText('');
      setRuntimeStatus((current: RuntimeStatus) => response.runtime ?? current);
      setConnectivityProbe(response.probe ?? null);
      if (response.proxy) {
        setProxyStatus(response.proxy);
      }
      setSessionDuration(0);
      setConnectedServerId(targetServer.id);
      connectedServerIdRef.current = targetServer.id;
      selectedServerIdRef.current = targetServer.id;
      setSelectedServerId(targetServer.id);
      lastRuntimeTunnelActive.current = true;
      lostRuntimePollCount.current = 0;
      setConnectionStateSafe('connected');
      runPostConnectProbe(targetServer);
      void refreshDiagnosticsAndRuntime();
      scheduleVpnIpRefreshForServer(targetServer.id, response.probe?.publicIp ?? response.externalIp);
      pushToast(
        `${tr(language, 'Переподключено к серверу', 'Reconnected to server')}: ${targetServer.country}, ${targetServer.city}`,
        'success'
      );
      void writeNativeRoutingLog('Управляемое переключение сервера завершено успешно.', `${targetServer.country}, ${targetServer.city} | mode=${currentSettings.tunnelMode}`);
    } catch (error) {
      const switchError = normalizeNativeError(
        error,
        tr(language, 'Не удалось переключить сервер.', 'Failed to switch server.')
      );
      let rollbackSucceeded = false;

      if (rollbackSettings && Object.keys(rollbackSettings).length > 0) {
        settingsRef.current = {
          ...settingsRef.current,
          ...rollbackSettings
        };
        setSettings((current: AppSettings) => ({
          ...current,
          ...rollbackSettings
        }));
      }

      if (isNativeConnectStillRunningError(switchError.message)) {
        void writeNativeRoutingLog('Native connect ещё выполняется после frontend timeout, rollback не запускаем чтобы не конфликтовать с Xray.', switchError.message);
        let runtimeAfterTimeout: RuntimeStatus | null = null;
        for (let waitStep = 0; waitStep < 6; waitStep += 1) {
          await sleep(1500);
          runtimeAfterTimeout = await refreshDiagnosticsAndRuntime();
          if (runtimeAfterTimeout?.tunnelActive) {
            break;
          }
        }
        const runtimeServerId = runtimeAfterTimeout?.lastPreparedServerId || '';

        if (runtimeConfirmsTargetServer(runtimeAfterTimeout, pendingTargetServer.id, buildServerRuntimeFingerprint(pendingTargetServer))) {
          setConnectedServerId(pendingTargetServer.id);
          connectedServerIdRef.current = pendingTargetServer.id;
          selectedServerIdRef.current = pendingTargetServer.id;
          setSelectedServerId(pendingTargetServer.id);
          lastRuntimeTunnelActive.current = true;
          lostRuntimePollCount.current = 0;
          setConnectionStateSafe('connected');
          pushToast(
            `${tr(language, 'Переключение завершилось после ожидания Xray', 'Switch completed after waiting for Xray')}: ${pendingTargetServer.country}, ${pendingTargetServer.city}`,
            'success'
          );
          return;
        }

        if (runtimeAfterTimeout?.tunnelActive && rollbackServer?.id && runtimeServerId === rollbackServer.id) {
          setConnectedServerId(rollbackServer.id);
          connectedServerIdRef.current = rollbackServer.id;
          selectedServerIdRef.current = rollbackServer.id;
          setSelectedServerId(rollbackServer.id);
          lastRuntimeTunnelActive.current = true;
          lostRuntimePollCount.current = 0;
          setConnectionStateSafe('connected');
          pushToast(
            tr(language, 'Xray не подтвердил новый сервер. Оставлено прежнее подключение.', 'Xray did not confirm the new server. The previous connection was kept.'),
            'info'
          );
          return;
        }

        setConnectivityProbe(null);
        setVpnExternalIp('—');
        setSessionDuration(0);
        setConnectedServerId('');
        connectedServerIdRef.current = '';
        setConnectionStateSafe('idle');
        pushToast(switchError.message, 'error');
        return;
      }

      if (rollbackServer?.id) {
        selectedServerIdRef.current = rollbackServer.id;
        setSelectedServerId(rollbackServer.id);
      }

      if (rollbackServer?.runtimeTemplate) {
        try {
          void writeNativeRoutingLog('Переключение сервера сорвалось, пробуем вернуть прежний сервер.', `${rollbackServer.country}, ${rollbackServer.city}`);
          invalidateConnectionProbes();
          setConnectionStateSafe('connecting');
          await sleep(120);
          const rollbackResponse = await remnawaveClient.connect(rollbackServer, {
            useSystemProxy: shouldUseSystemProxy(settingsRef.current.tunnelMode, settingsRef.current.useSystemProxy),
            probeAfterConnect: false,
            tunnelMode: settingsRef.current.tunnelMode,
            splitTunnelEntries: splitTunnelEntriesRef.current,
            ipStack: settingsRef.current.ipStack,
            routingExclusions: settingsRef.current.routingExclusions,
            reconnect: true
          });

          const rollbackNativeServerId = rollbackResponse.runtime?.lastPreparedServerId;
          assertNativeRuntimeServerMatches(
            rollbackNativeServerId,
            rollbackServer.id,
            rollbackResponse.runtime?.lastPreparedServerFingerprint,
            buildServerRuntimeFingerprint(rollbackServer)
          );

          setRuntimeStatus((current: RuntimeStatus) => rollbackResponse.runtime ?? current);
          setConnectivityProbe(rollbackResponse.probe ?? null);
          if (rollbackResponse.proxy) {
            setProxyStatus(rollbackResponse.proxy);
          }
          setSessionDuration(0);
          setConnectedServerId(rollbackServer.id);
          connectedServerIdRef.current = rollbackServer.id;
          setConnectionStateSafe('connected');
          rollbackSucceeded = true;
          lastRuntimeTunnelActive.current = true;
          lostRuntimePollCount.current = 0;
          runPostConnectProbe(rollbackServer);
          void refreshDiagnosticsAndRuntime();
          scheduleVpnIpRefreshForServer(rollbackServer.id, rollbackResponse.probe?.publicIp ?? rollbackResponse.externalIp);
          pushToast(
            tr(language, 'Новый сервер не подключился, прежнее подключение восстановлено.', 'The new server failed, the previous connection was restored.'),
            'info'
          );
        } catch (rollbackError) {
          void writeNativeRoutingLog(
            'Rollback на прежний сервер тоже не удался.',
            normalizeNativeError(rollbackError, 'rollback failed').message
          );
        }
      }

      if (!rollbackSucceeded) {
        if (proxyStatusRef.current.enabled || shouldUseSystemProxy(settingsRef.current.tunnelMode, settingsRef.current.useSystemProxy)) {
          try {
            const restoredProxy = await remnawaveClient.applySystemProxy(false);
            setProxyStatus(restoredProxy);
          } catch {
            // ignore follow-up proxy restore failure
          }
        }

        setConnectivityProbe(null);
        setVpnExternalIp('—');
        setSessionDuration(0);
        setConnectedServerId('');
        connectedServerIdRef.current = '';
        setConnectionStateSafe('idle');
        await refreshDiagnosticsAndRuntime();
        await refreshPrimaryExternalIp();
        pushToast(switchError.message, 'error');
      }
    } finally {
      finishManagedReconnect();
      connectionActionLock.current = false;
      scheduleConnectionQueueFlush('after-reconnect');
    }
  }

  function findMatchingServer(candidates: VpnServer[], baseServer: VpnServer | null, allowPreferredFallback = false): VpnServer | null {
    if (!baseServer) {
      return allowPreferredFallback ? pickPreferredServer(candidates, settingsRef.current.protocolStrategy) : null;
    }

    // Защита от подключения к "рандомному" серверу.
    // Несколько Remnawave-конфигов могут иметь одинаковый host:port или старый id,
    // но разный UUID, путь, SNI, publicKey или flow. Поэтому endpoint-fallback запрещён,
    // а при нескольких совпадениях по id сначала сверяем raw URI/runtime fingerprint.
    const exactMatches = candidates.filter((server: VpnServer) => server.id === baseServer.id);
    const baseRawUri = baseServer.rawUri?.trim();
    if (baseRawUri) {
      const rawMatch = exactMatches.find((server: VpnServer) => server.rawUri?.trim() === baseRawUri)
        ?? candidates.find((server: VpnServer) => server.rawUri?.trim() === baseRawUri);
      if (rawMatch) {
        return rawMatch;
      }
    }

    const baseFingerprint = buildServerRuntimeFingerprint(baseServer);
    if (baseFingerprint) {
      const runtimeMatch = exactMatches.find((server: VpnServer) => buildServerRuntimeFingerprint(server) === baseFingerprint)
        ?? candidates.find((server: VpnServer) => buildServerRuntimeFingerprint(server) === baseFingerprint);
      if (runtimeMatch) {
        return runtimeMatch;
      }
    }

    if (exactMatches.length === 1) {
      return exactMatches[0];
    }

    return null;
  }

  async function resolveServerForConnection(baseServer: VpnServer | null, allowPreferredFallback = false): Promise<VpnServer | null> {
    let resolvedServer: VpnServer | null = baseServer ?? (allowPreferredFallback ? pickPreferredServer(serversRef.current, settingsRef.current.protocolStrategy) : null);

    if (resolvedServer?.runtimeTemplate) {
      return resolvedServer;
    }

    const cachedServers = await remnawaveClient.loadServers();
    resolvedServer = findMatchingServer(cachedServers, resolvedServer, allowPreferredFallback);
    if (resolvedServer?.runtimeTemplate) {
      return resolvedServer;
    }

    if (accessKey.trim()) {
      const syncResult = await handleSyncProfile(true);
      const syncedServers = syncResult?.servers ?? await remnawaveClient.loadServers();
      resolvedServer = findMatchingServer(syncedServers, resolvedServer, allowPreferredFallback);
      if (resolvedServer?.runtimeTemplate) {
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
    const previousServer = connectionStateRef.current === 'connected'
      ? getConnectedRuntimeServer() ?? getServerById(selectedServerIdRef.current) ?? selectedServer
      : getServerById(selectedServerIdRef.current) ?? selectedServer;
    if (nextServer) {
      void writeNativeInterfaceLog('Выбран сервер.', `${nextServer.country}, ${nextServer.city}`);
    }

    if (!nextServer) {
      return;
    }

    if (connectionStateRef.current === 'idle') {
      selectedServerIdRef.current = nextServerId;
      setSelectedServerId(nextServerId);
      return;
    }

    if (isConnectionActionBusy()) {
      pendingServerSwitchRef.current = {
        nextServerId,
        previousServerId: previousServer?.id ?? connectedServerIdRef.current ?? selectedServerIdRef.current
      };
      pushToast(
        tr(language, 'Сервер запомнил. Переключим VPN после завершения текущего действия.', 'Server switch queued. The VPN will switch after the current action finishes.'),
        'info'
      );
      void writeNativeRoutingLog('Переключение сервера поставлено в очередь без смены активной галки.', `${nextServer.country}, ${nextServer.city}`);
      scheduleConnectionQueueFlush('queued-server-select');
      return;
    }

    if (connectionStateRef.current === 'connected') {
      const nextRuntimeServer = await resolveServerForConnection(nextServer, false);
      if (!nextRuntimeServer?.runtimeTemplate || nextRuntimeServer.id !== nextServer.id) {
        pushToast(
          tr(language, 'Для этого сервера ещё нет live-конфига. Текущее подключение оставлено без изменений.', 'This server is not runtime-ready yet. The current connection was left unchanged.'),
          'info'
        );
        return;
      }

      pushToast(
        `${tr(language, 'Переключаем сервер', 'Switching server')}: ${nextRuntimeServer.country}, ${nextRuntimeServer.city}`,
        'info'
      );
      await handleReconnectToServer(nextRuntimeServer, previousServer);
    }
  }
  async function handleConnectionToggle(serverOverride: VpnServer | null = null) {
    const currentState = connectionStateRef.current;
    const explicitServerOverride = isVpnServerLike(serverOverride) ? serverOverride : null;

    if (serverOverride && !explicitServerOverride) {
      void writeNativeRoutingLog("Игнорируем невалидный аргумент кнопки подключения.", "connect-click-event");
    }

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
    const attemptId = nextConnectionAttemptId();
    try {
      const currentSettings = settingsRef.current;
      const currentMode = currentSettings.tunnelMode;
      const currentSplitTunnelEntries = splitTunnelEntriesRef.current;
      const selectedId = selectedServerIdRef.current.trim();
      const requestedServer = explicitServerOverride ?? (selectedId ? getServerById(selectedId) : null);
      const allowPreferredFallback = Boolean(explicitServerOverride) || !selectedId;
      let targetServer = await resolveServerForConnection(requestedServer, allowPreferredFallback);
      if (!targetServer) {
        const message = requestedServer
          ? tr(language, 'Для выбранного сервера нет готового live-конфига. Обновите профиль или выберите другой сервер.', 'The selected server has no ready live config. Sync the profile or choose another server.')
          : tr(language, 'Сервер пока не выбран. Синхронизируйте профиль и выберите узел.', 'Server is not selected yet. Sync the profile and choose a node.');
        setErrorText(message);
        void writeNativeRoutingLog(
          'Подключение остановлено: runtime-ready сервер не найден.',
          requestedServer ? getServerPrimaryLabelForToast(requestedServer) : 'server-not-selected'
        );
        pushToast(message, 'info');
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
          await sleep(30);
          await remnawaveClient.disconnect({ useSystemProxy: proxyStatusRef.current.enabled || shouldUseSystemProxy(currentMode, currentSettings.useSystemProxy) });
          setVpnExternalIp('—');
          setSessionDuration(0);
          setConnectivityProbe(null);
          setConnectedServerId('');
          connectedServerIdRef.current = '';
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
        invalidateConnectionProbes();
        setConnectionStateSafe('connecting');
        await sleep(30);
        let response: ConnectResult;
        try {
          response = await remnawaveClient.connect(targetServer, {
            useSystemProxy: shouldUseSystemProxy(currentMode, currentSettings.useSystemProxy),
            probeAfterConnect: false,
            tunnelMode: currentMode,
            splitTunnelEntries: currentSplitTunnelEntries,
            ipStack: currentSettings.ipStack,
              routingExclusions: currentSettings.routingExclusions
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
              splitTunnelEntries: currentSplitTunnelEntries,
              ipStack: currentSettings.ipStack,
              routingExclusions: currentSettings.routingExclusions
            });
          } else {
            throw error;
          }
        }
        if (!isConnectionAttemptCurrent(attemptId)) {
          void writeNativeRoutingLog('Устаревший результат подключения проигнорирован.', `${targetServer.country}, ${targetServer.city}`);
          return;
        }

        const nativeServerId = response.runtime?.lastPreparedServerId;
        assertNativeRuntimeServerMatches(
          nativeServerId,
          targetServer.id,
          response.runtime?.lastPreparedServerFingerprint,
          buildServerRuntimeFingerprint(targetServer)
        );

        setErrorText('');
        setRuntimeStatus((current: RuntimeStatus) => response.runtime ?? current);
        setConnectivityProbe(response.probe ?? null);
        if (response.proxy) {
          setProxyStatus(response.proxy);
        }
        setSessionDuration(0);
        setConnectedServerId(targetServer.id);
        connectedServerIdRef.current = targetServer.id;
        selectedServerIdRef.current = targetServer.id;
        setSelectedServerId(targetServer.id);
        lastRuntimeTunnelActive.current = true;
        lostRuntimePollCount.current = 0;
        setConnectionStateSafe('connected');
        runPostConnectProbe(targetServer);
        void refreshDiagnosticsAndRuntime();
        scheduleVpnIpRefreshForServer(targetServer.id, response.probe?.publicIp ?? response.externalIp);
        pushToast(`${tr(language, 'Подключено', 'Connected')}: ${targetServer.country}, ${targetServer.city}`, 'success');
        void writeNativeRoutingLog('VPN подключён успешно.', `${targetServer.country}, ${targetServer.city} | mode=${currentMode}`);
      } catch (error) {
        const normalizedError = normalizeNativeError(error, tr(language, 'Ошибка подключения.', 'Connection failed.'));
        void writeNativeRoutingLog('Ошибка VPN подключения.', normalizedError.message);

        if (isNativeConnectStillRunningError(normalizedError.message)) {
          let runtimeAfterTimeout: RuntimeStatus | null = null;
          for (let waitStep = 0; waitStep < 6; waitStep += 1) {
            await sleep(1500);
            runtimeAfterTimeout = await refreshDiagnosticsAndRuntime();
            if (runtimeAfterTimeout?.tunnelActive) {
              break;
            }
          }
          const runtimeServerId = runtimeAfterTimeout?.lastPreparedServerId || '';

          if (runtimeConfirmsTargetServer(runtimeAfterTimeout, targetServer.id, buildServerRuntimeFingerprint(targetServer))) {
            setErrorText('');
            setConnectedServerId(runtimeServerId);
            connectedServerIdRef.current = runtimeServerId;
            selectedServerIdRef.current = runtimeServerId;
            setSelectedServerId(runtimeServerId);
            lastRuntimeTunnelActive.current = true;
            lostRuntimePollCount.current = 0;
            setConnectionStateSafe('connected');
            pushToast(tr(language, 'Xray ответил с задержкой. Состояние подключения обновлено.', 'Xray answered with a delay. Connection state was refreshed.'), 'info');
            return;
          }
        }

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
        setConnectedServerId('');
        connectedServerIdRef.current = '';
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
    void setNativeTrayUpdateState(Boolean(updateInfoRef.current.available), true);

    const result = await checkForUpdates(settings.releaseChannel);
    setUpdateInfo(result);
    void setNativeTrayUpdateState(Boolean(result.available), false);

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
    let installSucceeded = false;
    void setNativeTrayUpdateState(Boolean(updateInfoRef.current.available), true);
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

      installSucceeded = true;
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
      void setNativeTrayUpdateState(installSucceeded ? false : Boolean(updateInfoRef.current.available), false);
    }
  }


  useEffect(() => {
    if (!settings.autoUpdate || hasAutoCheckedUpdates.current) {
      return;
    }

    hasAutoCheckedUpdates.current = true;
    void handleCheckUpdates(true, settings.autoInstallUpdates);
  }, [settings.autoUpdate, settings.autoInstallUpdates, settings.releaseChannel]);

  function toggleSetting(key: keyof Omit<AppSettings, 'releaseChannel' | 'protocolStrategy' | 'language' | 'allowDemoFallback' | 'tunnelMode' | 'ipStack' | 'routingExclusions'>) {
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
            tr(language, 'Сначала останавливаем активное VPN-действие, потом завершим сессию.', 'Stopping the active VPN action first, then signing out.'),
            'info'
          );
          const finished = await waitForConnectionActionToFinish();
          if (!finished) {
            void writeNativeRoutingLog('Logout waited too long for active VPN action; refreshing runtime before cleanup.');
          }
        }

        const runtimeBeforeLogout = await refreshDiagnosticsAndRuntime();
        const shouldDisconnectBeforeLogout = connectionStateRef.current === 'connected'
          || Boolean(runtimeBeforeLogout?.tunnelActive)
          || proxyStatusRef.current.enabled;

        if (shouldDisconnectBeforeLogout) {
          setConnectionStateSafe('disconnecting');
          await remnawaveClient.disconnect({ useSystemProxy: proxyStatusRef.current.enabled || shouldUseSystemProxy(settingsRef.current.tunnelMode, settingsRef.current.useSystemProxy) });
          setConnectedServerId('');
          connectedServerIdRef.current = '';
          setConnectivityProbe(null);
          setVpnExternalIp('—');
          setSessionDuration(0);
          await refreshDiagnosticsAndRuntime();
          await refreshPrimaryExternalIp();
        }

        clearPendingConnectionQueue();
        await clearStoredAccessKey();
        await clearLastKnownServers();
        authorizedAccessKeyRef.current = '';
        await setNativeSessionAuthorized(false);
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
        setConnectionStateSafe('idle');
        pushToast(tr(language, 'VPN остановлен, ключ очищен, сессия завершена.', 'VPN stopped, key cleared and session ended.'), 'info');
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
                selectedServer={visibleSelectedServer}
                selectedServerId={selectedServerId}
                activeServerId={activeConnectionServerId}
                servers={filteredServers}
                allServerCount={servers.length}
                searchValue={searchValue}
                sessionDurationText={sessionDurationText}
                language={language}
                showDiagnostics={settings.showDiagnostics}
                tunnelMode={settings.tunnelMode}
                onToggleConnection={() => void handleConnectionToggle()}
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
                  onRepairRuntimeEnvironment={handleRepairRuntimeEnvironment}
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
                  isRepairBusy={isActionBusy('repairRuntime')}
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
                onIpStackChange={(value) => void handleIpStackChange(value)}
                onLanguageChange={(value) => setSettings((current: AppSettings) => ({ ...current, language: value }))}
                onRoutingExclusionsChange={(value) => {
                  settingsRef.current = { ...settingsRef.current, routingExclusions: value };
                  setSettings((current: AppSettings) => ({ ...current, routingExclusions: value }));
                }}
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
