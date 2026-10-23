import {ConnectionController,type ConnectionOptions,type ConnectionOutcome,type ConnectionRequest} from './services/connectionController';
import {nativeMutations} from './services/nativeTransport';
import {restoreConnectionPreferences} from './utils/connectionPreferences';
import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
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
import { useSessionHistory } from './hooks/useSessionHistory';
import { confirmLogout } from './utils/logoutConsent';
import {type AutostartStatus,NativeOperationError} from './utils/nativeErrors';
import { useSyncedRef } from './hooks/useSyncedRef';
import { buildDiagnosticsFilename, createSafeDiagnosticsPayload, downloadTextFile } from './utils/diagnosticsExport';
import { sleep } from './utils/async';
import { activePolicyEntries, isSelectedTunPolicyEmpty, insertRule, rulesOverlap } from './utils/appPolicies';
import { appendTrafficSample, buildTrafficBars, formatTrafficBytes, validTrafficSnapshot, type TrafficSample } from './utils/traffic';
import { runtimeConfirmsTargetServer } from './services/connectionGuards';
import { pickPreferredServer, rankServersForDisplay } from './utils/serverSorting';
import { resolveConnectedProfile, buildServerRuntimeFingerprint, isVpnServerLike, resolveServerReference, migrateServerReferences } from './utils/serverIdentity';
import { remnawaveClient } from './services/remnawave';
import { mergeServerMeasurements } from './utils/serverMeasurements';
import { canAutoInstallUpdate, updateNeedsOwnedCleanup } from './utils/updateSafety';
import {
  appVersion,
  ensureAdminLaunch,
  fetchPublicIpSnapshot,
  getIntegrationMeta,
  getNativeAppInfo,
  getNativeDiagnosticsSnapshot,
  getNativeRuntimeObservation,
  getNativeTrafficSnapshot,
  beginNativeTrafficSession,
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
  flushPersistentWrites,
  loadPersistentSnapshot,
  reloadPersistentSnapshot,
  prepareLegacyRollbackExport,
  loadFavoriteServerIds,
  loadSelectedServerId,
  loadSettings,
  loadSplitTunnelEntries,
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
import { approveUpdateExit, listenForStateHandoff, releaseUpdateState, sealUpdateState } from './services/stateHandoff';
import type { PendingServerSwitch } from './types/appState';
import type {
  AppSettings,
  AppTab,
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
  TrafficSnapshot,
  SplitTunnelEntry,
  RoutingPolicy,
  UpdateInfo,
  VpnServer
} from './types/vpn';

const integrationMeta = getIntegrationMeta();



export default function App() {
  const [accessKey, setAccessKey] = useState(() => loadStoredAccessKey());
  const [settings, setSettings] = useState<AppSettings>(() => loadSettings());
  const settingsRef = useSyncedRef(settings);
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
  const [diagnostics, setDiagnostics] = useState<DiagnosticsSnapshot | null>(null);
  const [profileSyncInfo, setProfileSyncInfo] = useState<ProfileSyncInfo>(remnawaveClient.getProfileSyncInfo());
  const [runtimeStatus, setRuntimeStatusState] = useState<RuntimeStatus>({
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
  const [storageErrorText, setStorageErrorText] = useState('');
  const [primaryExternalIp, setPrimaryExternalIp] = useState('—');
  const [vpnExternalIp, setVpnExternalIp] = useState('—');
  const [sessionDuration, setSessionDuration] = useState(0);
  const [connectedAt, setConnectedAt] = useState<number | null>(null);
  const trafficSessionRef = useRef<Promise<number> | null>(null);
  const [trafficHistory, setTrafficHistory] = useState<TrafficSample[]>([]);
  const [trafficCurrent, setTrafficCurrent] = useState<TrafficSnapshot | null>(null);
  const [searchValue, setSearchValue] = useState('');
  const [isSyncingProfile, setIsSyncingProfile] = useState(false);
  const operationManager = useOperationManager();
  const [persistentStateReady, setPersistentStateReady] = useState(!isTauriRuntime);
  const [isBootstrapping, setIsBootstrapping] = useState(true);
  useEffect(()=>{
    if(!isBootstrapping&&persistentStateReady)window.dispatchEvent(new Event('vkarmani:frontend-ready'));
  },[isBootstrapping,persistentStateReady]);
  const { toasts, pushToast, dismissToast } = useToastManager(settings.notifications);
  const toastWriterRef=useSyncedRef(pushToast);
  const [autostartStatus,setAutostartStatus]=useState<AutostartStatus>(isTauriRuntime?'unknown':'not-managed');
  const {records:sessionHistory} = useSessionHistory(persistentStateReady,connectionState,
    runtimeStatus.networkMode==='tun'?'tun':runtimeStatus.networkMode==='proxy'?'proxy':settings.tunnelMode,error=>pushToast(normalizeNativeError(error,tr(settings.language,'История подключений недоступна.','Connection history unavailable.')).message,'error'));
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
  const hasAutoCheckedUpdates = useRef(false);

  useEffect(() => {
    if (!isTauriRuntime) return;
    let disposed = false;
    let unlisten: (() => void) | undefined;
    void listenForStateHandoff({
      quiesce: () => { if (!disposed) setPersistentStateReady(false); },
      resume: () => { if (!disposed) setPersistentStateReady(true); },
      error: error => { if (!disposed) setStorageErrorText(normalizeNativeError(error, tr(settingsRef.current.language, 'Завершение приложения отменено.', 'Application shutdown was cancelled.')).message); }
    }).then(stop => { if (disposed) stop(); else unlisten = stop; }).catch(error => {
      if (!disposed) setStorageErrorText(normalizeNativeError(error, tr(settingsRef.current.language, 'Обработчик безопасного завершения недоступен.', 'Safe shutdown handler is unavailable.')).message);
    });
    return () => { disposed = true; unlisten?.(); };
  }, [language, settingsRef]);

  useEffect(() => {
    const onStorageError = (event: Event) => {
      const failure = (event as CustomEvent<unknown>).detail;
      const message = normalizeNativeError(failure, tr(settingsRef.current.language, 'Не удалось сохранить данные. Проверьте хранилище.', 'Data could not be saved. Check storage.')).message;
      setErrorText(message);
      setStorageErrorText(message);
    };
    window.addEventListener('vkarmani:storage-error', onStorageError);
    return () => window.removeEventListener('vkarmani:storage-error', onStorageError);
  }, [language, settingsRef]);

  const hasTriedFavoriteAutoConnect = useRef(false);
  const hasTriedAdminLaunch = useRef(false);
  const lastRuntimeTunnelActive = useRef(false);
  const lostRuntimePollCount = useRef(0);
  const lastAppliedSplitTunnelSignature = useRef('');
  const initialProtocolStrategy = useRef(settings.protocolStrategy);
  const activeRuntimeProfileRef = useRef<VpnServer | null>(null);
  const controllerRef=useRef<ConnectionController|null>(null);
  if(!controllerRef.current)controllerRef.current=new ConnectionController(()=>nativeMutations.pending());
  const connectionController=controllerRef.current;
  const updaterActionLock = useRef(false);
  const selectedServerIdRef = useSyncedRef(selectedServerId);
  const connectedServerIdRef = useSyncedRef(connectedServerId);
  const overviewAutoRefreshAtRef = useRef(0);
  const serversRef = useSyncedRef(servers);
  const splitTunnelEntriesRef = useSyncedRef(splitTunnelEntries);
  const favoriteServerIdsRef = useSyncedRef(favoriteServerIds);
  const proxyStatusRef = useSyncedRef(proxyStatus);
  const runtimeStatusRef = useRef(runtimeStatus);
  const setRuntimeStatus = useCallback((value: RuntimeStatus | ((current: RuntimeStatus)=>RuntimeStatus)) => {
    const current = runtimeStatusRef.current;
    const next = controllerRef.current!.accept(current, typeof value === 'function' ? value(current) : value);
    runtimeStatusRef.current = next;
    setRuntimeStatusState(next);
  }, []);
  const managedReconnectRef = useRef<{ targetServerId: string; previousServerId: string; startedAt: number } | null>(null);
  const runtimeStopIgnoreUntilRef = useRef(0);
  const vpnIpProbeSeqRef = useRef(0);
  const postConnectProbeSeqRef = useRef(0);
  const pendingServerSwitchRef = useRef<PendingServerSwitch | null>(null);
  const pendingTunnelModeRef = useRef<AppSettings['tunnelMode'] | null>(null);
  const pendingIpStackRef = useRef<AppSettings['ipStack'] | null>(null);
  const pendingSplitTunnelReconnectRef = useRef(false);
  const pendingDisconnectAfterBusyRef = useRef(false);
  const connectionQueueFlushScheduled = useRef(false);
  const connectionQueueTimer=useRef<number|undefined>(undefined);
  const connectionQueueFlushRunning = useRef(false);
  const runtimePollInFlight = useRef(false);
  const postConnectProbeInFlight = useRef(false);
  const manualRefreshInFlight = useRef(false);
  const profileSyncInFlightRef = useRef(false);
  const profileSyncGenerationRef = useRef(0);
  useEffect(() => () => { profileSyncGenerationRef.current++; remnawaveClient.invalidateProfileSync(); }, []);
  const snapshotRefreshQueued = useRef(false);
  const trayConnectActionRef = useRef<() => void>(() => undefined);
  const trayRestartProxyActionRef = useRef<() => void>(() => undefined);
  const trayLogoutActionRef = useRef<() => void>(() => undefined);

  // Long-lived effects call the latest committed actions without repeating
  // hydration/listener registration when an action closure changes.
  const lifecycleActions = useSyncedRef({refreshDiagnosticsAndRuntime,
    scheduleConnectionQueueFlush,applyPersistentSnapshot,authorizeWithAccessKey,handleSyncProfile,
    handleCheckUpdates,handleInstallUpdate,shouldIgnoreNativeRuntimeStop,commitObservedConnection,pushToast});
  useEffect(()=>{
    const controller=controllerRef.current!;controller.activate();
    const settled=()=>{void lifecycleActions.current.refreshDiagnosticsAndRuntime().then(runtime=>{
      if(runtime&&controller.reconcile(runtime)!=='pending')lifecycleActions.current.scheduleConnectionQueueFlush('native-settled');
    });};
    window.addEventListener('vkarmani:native-mutation-settled',settled);
    return()=>{controller.dispose();window.removeEventListener('vkarmani:native-mutation-settled',settled);
      if(connectionQueueTimer.current!==undefined)window.clearTimeout(connectionQueueTimer.current);
      connectionQueueFlushScheduled.current=false;};
  },[lifecycleActions]);

  const refreshRuntimeForPing = useCallback(()=>lifecycleActions.current.refreshDiagnosticsAndRuntime(),[lifecycleActions]);
  const getConnectedRuntimeServer = useCallback(()=>{
    const id=connectedServerIdRef.current||runtimeStatusRef.current.lastPreparedServerId||'';
    return resolveConnectedProfile(serversRef.current,id,runtimeStatusRef.current.lastPreparedServerFingerprint,activeRuntimeProfileRef.current);
  },[connectedServerIdRef,serversRef]);

  const {
    isCheckingPing,
    pingProgress,
    checkingPingServerIds,
    refreshPing: handleRefreshPing,
    scheduleAutoPing,
    cancelPing
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
    refreshDiagnosticsAndRuntime: refreshRuntimeForPing,
    onMeasurementsCommitted: (measured, snapshot) => {
      if (serversRef.current !== snapshot) return false;
      serversRef.current = measured;
      remnawaveClient.updateCachedMeasurements(measured);
      saveLastKnownServers(measured);
      return true;
    }
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

      lifecycleActions.current.pushToast(normalizeNativeError(new NativeOperationError('NATIVE_COMMAND_TIMEOUT','bridge',false,'Outcome unknown.',true),tr(settingsRef.current.language,'Исход операции неизвестен.','Operation outcome unknown.')).message,'error');
      void lifecycleActions.current.refreshDiagnosticsAndRuntime();
    }, 80_000);

    return () => window.clearTimeout(timer);
  }, [connectionState, language, lifecycleActions, setConnectionStateSafe, connectionActionStartedAt, connectionStateRef, connectedServerIdRef, selectedServerIdRef, settingsRef]);


  useEffect(() => {
    const updateBusy = ['checking', 'downloading', 'installing'].includes(updateInfo.status);
    void setNativeTrayUpdateState(Boolean(updateInfo.available), updateBusy);
  }, [updateInfo.available, updateInfo.status]);

  function applyPersistentSnapshot(restored: Awaited<ReturnType<typeof loadPersistentSnapshot>>) {
    settingsRef.current = restored.settings;
    setSettings(restored.settings);
    initialProtocolStrategy.current = restored.settings.protocolStrategy;
    splitTunnelEntriesRef.current = restored.entries;
    setSplitTunnelEntries(restored.entries);
    favoriteServerIdsRef.current = restored.favorites;
    setFavoriteServerIds(restored.favorites);
    selectedServerIdRef.current = restored.selected;
    setSelectedServerId(restored.selected);
    setPersistentStateReady(true);
  }

  async function handleStorageRecovery() {
    if (!window.confirm(tr(language, 'Загрузить проверенное native-состояние или резервную копию? Неподтверждённые изменения интерфейса будут отменены. Повреждённый оригинал будет сохранён.', 'Load verified native state or its backup? Unconfirmed interface edits will be discarded. The damaged original will be preserved.'))) return;
    setPersistentStateReady(false);
    try {
      applyPersistentSnapshot(await reloadPersistentSnapshot());
      setStorageErrorText('');
      setErrorText('');
    } catch (error) {
      setStorageErrorText(normalizeNativeError(error, tr(language, 'Восстановление не завершено.', 'Recovery did not complete.')).message);
    }
  }

  useEffect(() => {
    if (!isTauriRuntime) {
      setPersistentStateReady(true);
      return;
    }

    let cancelled = false;

    void loadPersistentSnapshot().then(restored => {
      if (cancelled) return;
      lifecycleActions.current.applyPersistentSnapshot(restored);
    }).catch(error => {
      if (cancelled) return;
      const message = normalizeNativeError(error, tr(settingsRef.current.language, 'Не удалось восстановить настройки. Сохранённые данные не сбрасывались.', 'Settings could not be restored. Saved data was not reset.')).message;
      setErrorText(message);
      setStorageErrorText(message);
      void writeNativeInterfaceLog('STATE_RESTORE_BLOCKED: native state v2 requires recovery or retry.');
    });

    return () => {
      cancelled = true;
    };
  }, [lifecycleActions, settingsRef]);

  useEffect(() => {
    if (isTauriRuntime && !persistentStateReady) return;
    let cancelled = false;

    void loadStoredAccessKeySecure()
      .then((storedKey) => {
        if (!cancelled && storedKey.trim()) {
          const normalizedStoredKey = storedKey.trim();
          setAccessKey(normalizedStoredKey);

          if (settingsRef.current.autoConnectFavorite && !hasTriedFavoriteAutoConnect.current) {
            hasTriedFavoriteAutoConnect.current = true;
            void lifecycleActions.current.authorizeWithAccessKey(normalizedStoredKey, true);
          }
        }
      })
      .catch((error) => {
        void writeNativeInterfaceLog('Не удалось загрузить ключ из защищённого хранилища.', normalizeNativeError(error, 'secure storage error').message);
      });

    return () => {
      cancelled = true;
    };
  }, [persistentStateReady, settingsRef, lifecycleActions]);


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
    void lifecycleActions.current.handleSyncProfile(true);
  }, [accessKey, activeTab, isAuthorized, lifecycleActions]);

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
    document.documentElement.lang = settingsRef.current.language;
    document.title = tr(settingsRef.current.language, 'VKarmani Desktop', 'VKarmani Desktop');
  }, [language, settingsRef]);

  useEffect(() => {
    void writeNativeInterfaceLog('VKarmani Desktop запущен.', `Версия ${appVersion}`);
  }, []);

  useEffect(() => {
    void writeNativeInterfaceLog('Активная вкладка изменена.', activeTab);
  }, [activeTab]);

  useEffect(() => {
    if (!persistentStateReady || !settings.runAsAdmin || hasTriedAdminLaunch.current) {
      return;
    }

    hasTriedAdminLaunch.current = true;
    void flushPersistentWrites().then(() => ensureAdminLaunch(settings.runAsAdmin)).catch((error) => {
      setErrorText(normalizeNativeError(error, tr(settingsRef.current.language, 'Сначала необходимо сохранить настройки.', 'Settings must be saved first.')).message);
    });
  }, [settings.runAsAdmin, persistentStateReady, settingsRef]);

  useEffect(() => {
    if (!isTauriRuntime || !persistentStateReady) {
      return;
    }

    let disposed=false;setAutostartStatus('pending');
    void flushPersistentWrites().then(()=>setNativeLaunchOnStartup(settings.launchOnStartup)).then(actual=>{
      if(!disposed)setAutostartStatus(actual?'enabled':'disabled');
    }).catch(error=>{
      if(disposed)return;
      const failure=normalizeNativeError(error,tr(settingsRef.current.language,'Автозапуск Windows не подтверждён.','Windows startup was not confirmed.'));
      if(failure instanceof NativeOperationError&&failure.code==='AUTOSTART_BUILD_UNSUPPORTED'){setAutostartStatus('not-managed');return;}
      setAutostartStatus('unconfirmed');toastWriterRef.current(failure.message,'error');
    });
    return()=>{disposed=true;};
  }, [settings.launchOnStartup, persistentStateReady,settingsRef,toastWriterRef]);

  useEffect(() => {
    if (!settings.showDiagnostics && activeTab === 'diagnostics') {
      setActiveTab('settings');
    }
  }, [settings.showDiagnostics, activeTab]);

  useEffect(() => {
    if (connectionState === 'connected') {
      setConnectedAt((current) => current ?? performance.now());
      return;
    }

    if (connectionState === 'idle') { setConnectedAt(null); setSessionDuration(0); }
  }, [connectionState]);

  useEffect(() => {
    if (connectionState !== 'connected' || !connectedAt) {
      return undefined;
    }

    const updateDuration = () => {
      setSessionDuration(Math.max(0, Math.floor((performance.now() - connectedAt) / 1000)));
    };

    updateDuration();
    const timer = window.setInterval(updateDuration, 1000);

    return () => window.clearInterval(timer);
  }, [connectionState, connectedAt]);


  useEffect(() => {
    let cancelled = false, inFlight = false;
    if (connectionState === 'idle') {
      trafficSessionRef.current = null;
      setTrafficCurrent(null); setTrafficHistory([]);
      return;
    }
    if (connectionState !== 'connected') { setTrafficCurrent(null); return; }
    // Native monotonic token survives clock changes and UI/runtime transitions.
    const session = trafficSessionRef.current ?? beginNativeTrafficSession();
    trafficSessionRef.current = session;
    const runtimeId = runtimeStatus.runtimeId;
    const updateTraffic = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const sessionId = await session;
        if (cancelled || trafficSessionRef.current !== session) return;
        const snapshot = await getNativeTrafficSnapshot(sessionId);
        if (cancelled || trafficSessionRef.current !== session) return;
        if (snapshot.sessionId !== sessionId || (runtimeId && snapshot.runtimeId !== runtimeId)) {
          setTrafficCurrent(null); return;
        }
        setTrafficCurrent(snapshot);
        if (validTrafficSnapshot(snapshot)) setTrafficHistory(history => appendTrafficSample(history, snapshot, performance.now()));
      } catch { if (!cancelled) setTrafficCurrent(null); }
      finally { inFlight = false; }
    };
    void updateTraffic();
    // One bounded CLI query in Proxy; native GetIfEntry2 in TUN. No overlapping polls.
    const timer = window.setInterval(() => void updateTraffic(), 30000);
    return () => { cancelled = true; window.clearInterval(timer); };
  }, [connectionState, runtimeStatus.runtimeId]);

  useEffect(() => {
    if (isTauriRuntime && !persistentStateReady) return;
    let cancelled = false;

    const bootstrap = async () => {
      setIsBootstrapping(true);

      const localLastKnownServers = loadLastKnownServers();
      if (localLastKnownServers.length) {
        remnawaveClient.hydrateCachedServers(localLastKnownServers);
        serversRef.current = localLastKnownServers;
        setServers(localLastKnownServers);
      }

      const [serversResult, devicesResult, runtimeSnapshotResult, lastKnownBackupResult] = await Promise.allSettled([
        remnawaveClient.loadServers(),
        remnawaveClient.loadDevices(),
        remnawaveClient.loadRuntimeSnapshot(),
        loadLastKnownServersBackup()
      ]);

      if (cancelled) {
        return;
      }

      if (lastKnownBackupResult.status === 'rejected') {
        const message = normalizeNativeError(lastKnownBackupResult.reason, tr(settingsRef.current.language, 'Не удалось восстановить кэш профилей. Сохранённые данные не сбрасывались.', 'Profile cache could not be restored. Saved data was not reset.')).message;
        setErrorText(message);
        setStorageErrorText(message);
      }

      if (serversResult.status === 'fulfilled' && serversResult.value.length) {
        const result = mergeServerMeasurements(serversResult.value, serversRef.current);
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
        const backupServers = mergeServerMeasurements(lastKnownBackupResult.value, serversRef.current);
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

      if (devicesResult.status === 'fulfilled') {
        setDevices(devicesResult.value);
      }

      if (runtimeSnapshotResult.status === 'fulfilled') {
        const { runtime, diagnostics: nextDiagnostics, proxyStatus: nextProxy } = runtimeSnapshotResult.value;
        setRuntimeStatus(runtime);
        setDiagnostics(nextDiagnostics);
        setProxyStatus(nextProxy);
        if(connectionController.reconcile(runtime)!=='pending')setConnectionStateSafe(runtime.tunnelActive ? 'connected' : 'idle');
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
  }, [persistentStateReady, serversRef, settingsRef, selectedServerIdRef, setRuntimeStatus, setConnectionStateSafe,connectionController]);

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
            void lifecycleActions.current.handleCheckUpdates();
            return;
          }

          if (event.payload === 'install_update') {
            setActiveTab('overview');
            void lifecycleActions.current.handleInstallUpdate();
            return;
          }

          if (event.payload === 'logout') {
            setActiveTab('overview');
            trayLogoutActionRef.current();
          }
        });

        const unlistenNativeDisconnect = await eventApi.listen<string>('vkarmani://native-disconnect', () => {
          if (lifecycleActions.current.shouldIgnoreNativeRuntimeStop()) {
            void writeNativeRoutingLog('Native runtime stop event проигнорирован во время управляемого переключения/действия подключения.');
            return;
          }

          const hadActiveRuntime = connectionStateRef.current === 'connected'
            || connectionStateRef.current === 'connecting'
            || Boolean(connectedServerIdRef.current)
            || lastRuntimeTunnelActive.current;

          if (!hadActiveRuntime) {
            void writeNativeRoutingLog('Native runtime stop event получен в idle-состоянии и не показывается пользователю как ошибка.');
            void lifecycleActions.current.refreshDiagnosticsAndRuntime();
            return;
          }

          void lifecycleActions.current.refreshDiagnosticsAndRuntime();

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
  }, [connectionStateRef, lifecycleActions, connectedServerIdRef, setConnectionStateSafe, settingsRef]);

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
        const epoch=nativeMutations.revision,wasPending=nativeMutations.pending();
        const { runtime: nextRuntime, diagnostics: nextDiagnostics, proxyStatus: nextProxy } = await remnawaveClient.loadRuntimeSnapshot();
        if(wasPending||epoch!==nativeMutations.revision)return;

        if (disposed) {
          return;
        }

        if (!connectionController.accepts(runtimeStatusRef.current, nextRuntime)) return;
        const lostTunnel = lastRuntimeTunnelActive.current && !nextRuntime.tunnelActive;

        setRuntimeStatus(nextRuntime);
        setDiagnostics(nextDiagnostics);
        setProxyStatus(nextProxy);

        if (connectionController.reconcile(nextRuntime)==='pending') {
          void writeNativeRoutingLog('Runtime snapshot временно неактивен во время управляемого подключения/переключения, состояние UI не сбрасываем.');
          return;
        }

        if (nextRuntime.tunnelActive) {
          lostRuntimePollCount.current = 0;
          lastRuntimeTunnelActive.current = true;
          lifecycleActions.current.commitObservedConnection(nextRuntime);
          return;
        }

        if (lostTunnel && connectionStateRef.current === 'connected') {
          lostRuntimePollCount.current += 1;
          if (lostRuntimePollCount.current < 4) {
            void writeNativeRoutingLog('Runtime snapshot временно неактивен, ждём дополнительные проверки/автовосстановление без сброса UI.', `miss=${lostRuntimePollCount.current}`);
            return;
          }
        } else {
          lostRuntimePollCount.current = 0;
        }

        lastRuntimeTunnelActive.current = false;
        setConnectedServerId('');
        connectedServerIdRef.current = '';
        setConnectionStateSafe('idle');

        if (!lostTunnel || connectionStateRef.current === 'disconnecting') {
          return;
        }

        setVpnExternalIp('—');
        setConnectivityProbe(null);
        setSessionDuration(0);
        void refreshPrimaryExternalIp();
        lifecycleActions.current.pushToast(tr(settingsRef.current.language, 'Runtime остановился или потерял соединение после попыток автовосстановления. Состояние клиента обновлено.', 'Runtime stopped or lost connectivity after recovery attempts. Client state was refreshed.'), 'error');
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
  }, [connectionState, language, setRuntimeStatus, connectedServerIdRef, selectedServerIdRef, setConnectionStateSafe, connectionStateRef, lifecycleActions, settingsRef,connectionController]);

  useEffect(() => {
    if (persistentStateReady) {
      setFavoriteServerIds((current) => {
        const migrated = migrateServerReferences(servers, current);
        if (migrated.join('\0') === current.join('\0')) return current;
        favoriteServerIdsRef.current = migrated;
        return migrated;
      });
    }
    setSelectedServerId((current: string) => {
      const resolved = resolveServerReference(servers, current);
      if (resolved) {
        selectedServerIdRef.current = resolved.id;
        return resolved.id;
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
  }, [servers, settings.protocolStrategy, persistentStateReady, favoriteServerIdsRef, selectedServerIdRef, connectionStateRef, connectedServerIdRef]);


  const selectedServer = useMemo(
    () => resolveServerReference(servers, selectedServerId),
    [servers, selectedServerId]
  );

  const activeConnectionServerId = connectionState === 'connected'
    ? connectedServerId || runtimeStatus.lastPreparedServerId || selectedServerId
    : selectedServerId;


  const visibleSelectedServer = useMemo(
    () => (connectionState === 'connected'
      ? resolveConnectedProfile(servers,activeConnectionServerId,runtimeStatus.lastPreparedServerFingerprint,activeRuntimeProfileRef.current) ?? selectedServer
      : selectedServer),
    [activeConnectionServerId, connectionState, selectedServer, servers, runtimeStatus.lastPreparedServerFingerprint]
  );
  const splitTunnelSignature = useMemo(
    () => JSON.stringify([settings.tunRoutingMode, splitTunnelEntries.map((entry: SplitTunnelEntry) => ({
      id: entry.id,
      kind: entry.kind,
      value: entry.value.trim(),
      enabled: entry.enabled,
      policy: entry.policy ?? 'VPN'
    }))]),
    [splitTunnelEntries, settings.tunRoutingMode]
  );

  const activeSplitTunnelCount = useMemo(
    () => activePolicyEntries(splitTunnelEntries, settings.tunRoutingMode).length,
    [splitTunnelEntries, settings.tunRoutingMode]
  );

  const favoriteServerIdSet = useMemo(() => new Set(favoriteServerIds), [favoriteServerIds]);
  const deferredSearchValue = useDeferredValue(searchValue);

  const trafficReceivedBytes = validTrafficSnapshot(trafficCurrent) ? trafficCurrent.receivedBytes : null;
  const trafficSentBytes = validTrafficSnapshot(trafficCurrent) ? trafficCurrent.sentBytes : null;
  const trafficChartBars = useMemo(() => validTrafficSnapshot(trafficCurrent) ? buildTrafficBars(trafficHistory) : [], [trafficCurrent, trafficHistory]);
  // No end-to-end loss measurement exists. HTTP/TCP success is not packet loss.
  const packetLossText = '—';

  const filteredServers = useMemo(() => {
    const normalized = deferredSearchValue.trim().toLowerCase();
    const displayRankedServers = rankServersForDisplay(servers, settings.protocolStrategy, favoriteServerIds, settings.sortServersByPing);

    if (!normalized) {
      return displayRankedServers;
    }

    return displayRankedServers.filter((server: VpnServer) => {
      const haystack = [
        server.country,
        server.city,
        server.description,
        server.protocol,
        server.host,
        server.transportLabel,
        ...(server.tags ?? [])
      ]
        .join(' ')
        .toLowerCase();

      return haystack.includes(normalized);
    });
  }, [deferredSearchValue, servers, settings.protocolStrategy, favoriteServerIds, settings.sortServersByPing]);

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
      lifecycleActions.current.pushToast(
        tr(settingsRef.current.language, 'Список TUN обновлён. Новые правила применятся при следующем ручном переподключении.', 'The TUN list was updated. New rules will apply on the next manual reconnect.'),
        'info'
      );
      void writeNativeRoutingLog('TUN правила изменены без автоматического переподключения.', 'apply-on-next-manual-reconnect');
      return;
    }

    if (connectionState === 'connecting' || connectionState === 'disconnecting' || controllerRef.current!.busy) {
      lifecycleActions.current.pushToast(
        tr(settingsRef.current.language, 'Список TUN обновлён. Текущее действие подключения не прерываем.', 'The TUN list was updated. The current connection action will not be interrupted.'),
        'info'
      );
    }
  }, [connectionState, settings.tunnelMode, selectedServer, splitTunnelSignature, lifecycleActions, settingsRef]);

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
        : settings.tunnelMode === 'tun' && isSelectedTunPolicyEmpty(splitTunnelEntries, settings.tunRoutingMode)
          ? tr(language, 'Для TUN добавьте хотя бы одну программу или службу.', 'Add at least one app or service for TUN.')
          : ''
    : '';
  const canConnectSelectedServer = connectionState !== 'idle' || !connectionDisabledReason;

  useEffect(() => {
    if (!isTauriRuntime || connectionState !== 'idle' || runtimeStatus.coreInstalled) {
      return;
    }

    const timer = window.setTimeout(() => {
      void lifecycleActions.current.refreshDiagnosticsAndRuntime();
    }, 250);

    return () => {
      window.clearTimeout(timer);
    };
  }, [connectionState, runtimeStatus.coreInstalled, lifecycleActions]);

  async function refreshDiagnosticsAndRuntime() {
    if (manualRefreshInFlight.current) {
      snapshotRefreshQueued.current = true;
      return null;
    }

    manualRefreshInFlight.current = true;
    try {
      const epoch=nativeMutations.revision,wasPending=nativeMutations.pending();
      const { runtime, diagnostics: nextDiagnostics, proxyStatus: nextProxy } = await remnawaveClient.loadRuntimeSnapshot();
      if(wasPending||epoch!==nativeMutations.revision)return null;

      if (!connectionController.accepts(runtimeStatusRef.current, runtime)) return null;
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

  function getServerById(serverId: string) {
    return resolveServerReference(serversRef.current, serverId);
  }

  function isActionBusy(action: string) {
    return operationManager.isBusy(action);
  }

  async function runActionOnce<T>(action: string, operation: () => Promise<T>): Promise<T | null> {
    if(['proxy','repairRuntime'].includes(action)&&(isConnectionActionBusy()||updaterActionLock.current))return null;
    return operationManager.run(action, operation);
  }

  function isConnectionActionBusy() {
    return connectionController.busy;
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
    connectionQueueTimer.current=window.setTimeout(() => {
      connectionQueueTimer.current=undefined;
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

        await executeConnection({kind:'disconnect',options:connectionOptions()});
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

        if(connectionStateRef.current==='connected'){
          await handleReconnectToServer(nextServer,previousServer);return;
        }
        selectedServerIdRef.current=nextServer.id;setSelectedServerId(nextServer.id);
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

  function handleAddSplitTunnelEntry(kind: SplitTunnelEntry['kind'], rawValue: string, policy: RoutingPolicy = 'VPN') {
    try {
      const next = insertRule(splitTunnelEntriesRef.current, kind, rawValue, policy, crypto.randomUUID());
      splitTunnelEntriesRef.current = next;
      setSplitTunnelEntries(next);
      pushToast(tr(language, 'Правило добавлено.', 'Rule added.'), 'success');
      return true;
    } catch {
      pushToast(tr(language, 'Проверьте exe/имя службы, лимит 256 и пересечение существующих правил.', 'Check the exe/service identity, the 256-rule limit and overlapping rules.'), 'info');
      return false;
    }
  }

  function handleChangeSplitTunnelPolicy(entryId: string, policy: RoutingPolicy) {
    const current = splitTunnelEntriesRef.current;
    const selected = current.find(entry => entry.id === entryId);
    if (!selected) return;
    if (current.some(entry => entry.id !== entryId && entry.enabled && selected.enabled && (entry.policy ?? 'VPN') !== policy && rulesOverlap(entry, selected))) {
      pushToast(tr(language, 'Правила «Через VPN» и «Напрямую» пересекаются для этой программы.', 'Through VPN and Direct rules overlap for this application.'), 'info');
      return;
    }
    const next = current.map(entry => entry.id === entryId ? { ...entry, policy } : entry);
    splitTunnelEntriesRef.current = next;
    setSplitTunnelEntries(next);
  }

  function handleToggleSplitTunnelEntry(entryId: string) {
    const nextEntry = splitTunnelEntriesRef.current.find((entry: SplitTunnelEntry) => entry.id === entryId) ?? null;
    if (nextEntry?.invalidReason) return;
    if (nextEntry) {
      void writeNativeInterfaceLog(
        nextEntry.enabled ? 'Правило TUN отключено.' : 'Правило TUN включено.',
        `target=${nextEntry.kind}; rule=${splitTunnelEntriesRef.current.indexOf(nextEntry) + 1}`
      );
    }

    const next = splitTunnelEntriesRef.current.map(entry=>entry.id===entryId?{...entry,enabled:!entry.enabled}:entry);
    splitTunnelEntriesRef.current=next;
    setSplitTunnelEntries(next);
  }

  function handleRemoveSplitTunnelEntry(entryId: string) {
    const removedEntry = splitTunnelEntriesRef.current.find((entry: SplitTunnelEntry) => entry.id === entryId) ?? null;
    if (removedEntry) {
      void writeNativeInterfaceLog('Запись удалена из TUN списка.', `target=${removedEntry.kind}; rule=${splitTunnelEntriesRef.current.indexOf(removedEntry) + 1}`);
    }

    const next=splitTunnelEntriesRef.current.filter(entry=>entry.id!==entryId);
    splitTunnelEntriesRef.current=next;
    setSplitTunnelEntries(next);
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

  async function handlePickExecutableForSplitTunnel(policy: RoutingPolicy = 'VPN') {
    await runActionOnce('pickExecutable', async () => {
      try {
        const pickedPath = await pickNativeExecutablePath();
        if (pickedPath) {
          handleAddSplitTunnelEntry('app', pickedPath, policy);
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
          normalizeNativeError(error,tr(language,'Не удалось включить системный proxy.','Failed to enable the system proxy.')).message,
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
          normalizeNativeError(error,tr(language,'Не удалось выключить системный proxy.','Failed to disable system proxy.')).message,
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
          normalizeNativeError(error,tr(language,'Не удалось перезапустить proxy.','Failed to restart proxy.')).message,
          'error'
        );
      }
    });
  }

  async function handleRunConnectivityProbe() {
    await runActionOnce('probe', async () => {
      setConnectivityProbe(null);
      try {
        const probe = await remnawaveClient.runConnectivityProbe();
        setConnectivityProbe(probe);
        void refreshDiagnosticsAndRuntime();
        pushToast(
          probe.success
              ? tr(language, 'HTTP egress через собственный Xray отвечает. TUN, UDP и DNS leak не проверены.', 'HTTP egress through the owned Xray responded. TUN, UDP and DNS leaks were not tested.')
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


  async function handleRepairRuntimeEnvironment(planId:string):Promise<boolean> {
    let completed=false;
    await runActionOnce('repairRuntime', async () => {
      try {
        const runtime = await repairNativeRuntimeEnvironment(planId);
        setRuntimeStatus(runtime);
        setConnectivityProbe(null);
        setVpnExternalIp('—');
        await refreshDiagnosticsAndRuntime();
        pushToast(
            tr(language, 'Подтверждённые настройки proxy и маршруты VKarmani восстановлены.', 'Confirmed VKarmani proxy settings and routes were restored.'),
          'success'
        );
        void writeNativeRoutingLog('Пользователь запустил восстановление runtime окружения.');
        completed=true;
      } catch (error) {
        pushToast(
          normalizeNativeError(error, tr(language, 'Не удалось восстановить runtime окружение.', 'Failed to repair runtime environment.')).message,
          'error'
        );
      }
    });
    return completed;
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

    if (nextMode === currentSettings.tunnelMode && !pendingTunnelModeRef.current) {
      return;
    }

    if (currentConnectionState !== 'idle' && nextMode === 'tun' && isSelectedTunPolicyEmpty(splitTunnelEntriesRef.current, settingsRef.current.tunRoutingMode)) {
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

    const previousMode=currentSettings.tunnelMode;
    updateTunnelModePreference(nextMode);
    const server=getConnectedRuntimeServer();
    if(currentConnectionState==='connected'&&server){
      await handleReconnectToServer(server,server,{tunnelMode:previousMode});
    }else{
      pushToast(tr(language,'Режим сохранён для следующего подключения.','Mode saved for the next connection.'),'info');
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
    const syncGeneration = ++profileSyncGenerationRef.current;
    cancelPing();

    try {
      void writeNativeInterfaceLog('Запущена синхронизация профиля Remnawave.');
      setIsSyncingProfile(true);
      setProfileSyncInfo((current: ProfileSyncInfo) => ({
        ...current,
        status: 'syncing',
        message: tr(language, 'Синхронизируем профиль Remnawave…', 'Syncing Remnawave profile…')
      }));

      const result = await remnawaveClient.syncProfile(normalizedAccessKey, settingsRef.current.allowDemoFallback);
      if (syncGeneration !== profileSyncGenerationRef.current) return null;
      result.servers = mergeServerMeasurements(result.servers, serversRef.current);
      remnawaveClient.updateCachedMeasurements(result.servers);
      const connectedProfile = getConnectedRuntimeServer();
      if (connectedProfile) activeRuntimeProfileRef.current = connectedProfile;
      serversRef.current = result.servers;
      setServers(result.servers);
      saveLastKnownServers(result.servers);
      setFavoriteServerIds((current) => migrateServerReferences(result.servers, current).filter((id) => result.servers.some((server: VpnServer) => server.id === id)));
      setProfileSyncInfo(result.profile);
      const refreshedSession = remnawaveClient.getCachedSession();
      if (refreshedSession) {
        setSession(refreshedSession);
      }
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

      // The catalog is committed: auxiliary device/diagnostic refresh must not
      // prevent the canonical full batch after a successful subscription sync.
      if (result.profile.status === 'ready') scheduleAutoPing(silent ? 'silent-profile-sync' : 'manual-profile-sync');
      try {
        setDevices(await remnawaveClient.loadDevices());
      } catch (error) {
        void writeNativeInterfaceLog('Не удалось обновить список устройств после синхронизации.', normalizeNativeError(error, 'Device refresh failed.').message);
      }

      if (!isConnectionActionBusy()) {
        await refreshDiagnosticsAndRuntime();
      }
      void writeNativeInterfaceLog(
        'Профиль Remnawave синхронизирован.',
        `${result.profile.configCount} конфигов | источник: ${result.profile.sourceLabel}`
      );

      if (!silent) {
        pushToast(result.profile.message ?? tr(language, 'Профиль синхронизирован.', 'Profile synced.'), 'success');
      }

      return result;
    } catch (error) {
      if (syncGeneration !== profileSyncGenerationRef.current) return null;
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
      if (syncGeneration === profileSyncGenerationRef.current) { profileSyncInFlightRef.current = false; setIsSyncingProfile(false); }
    }
  }

  async function authorizeWithAccessKey(rawAccessKey: string, connectFavoriteAfterLaunch = false) {
    if (isTauriRuntime && !persistentStateReady) { setStorageErrorText(tr(language, 'Сначала необходимо восстановить native-состояние.', 'Restore native state first.')); return; }
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
      let serverPool = mergeServerMeasurements(await remnawaveClient.loadServers(), serversRef.current);
      if (serverPool.length) {
        serversRef.current = serverPool;
        setServers(serverPool);
        saveLastKnownServers(serverPool);
        setFavoriteServerIds((current) => migrateServerReferences(serverPool, current).filter((id) => serverPool.some((server: VpnServer) => server.id === id)));
        setProfileSyncInfo(remnawaveClient.getProfileSyncInfo());

        const preferredServer = pickPreferredServer(serverPool, currentSettings.protocolStrategy);
        setSelectedServerId((current: string) => {
          const nextId = resolveServerReference(serverPool, current)?.id ?? preferredServer?.id ?? current;
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

  function connectionOptions(value:AppSettings=settingsRef.current):ConnectionOptions {
    return structuredClone({useSystemProxy:shouldUseSystemProxy(value.tunnelMode,value.useSystemProxy),probeAfterConnect:false,
      tunnelMode:value.tunnelMode,tunRoutingMode:value.tunRoutingMode,splitTunnelEntries:splitTunnelEntriesRef.current,
      ipStack:value.ipStack,routingExclusions:value.routingExclusions});
  }

  function commitObservedConnection(runtime:RuntimeStatus) {
    if(!runtime.tunnelActive){
      setConnectedServerId('');connectedServerIdRef.current='';activeRuntimeProfileRef.current=null;
      setConnectivityProbe(null);setVpnExternalIp('—');setSessionDuration(0);setConnectionStateSafe('idle');return;
    }
    const server=resolveConnectedProfile(serversRef.current,runtime.lastPreparedServerId??'',runtime.lastPreparedServerFingerprint,activeRuntimeProfileRef.current);
    connectedServerIdRef.current=server?.id??'';setConnectedServerId(server?.id??'');
    activeRuntimeProfileRef.current=server;
    setConnectionStateSafe('connected');
  }

  async function executeConnection(request:ConnectionRequest,rollbackSettings?:Partial<AppSettings>):Promise<boolean>{
    if(connectionController.busy)return false;
    const requestedSettings=settingsRef.current;
    const previousRuntimeHash=runtimeStatusRef.current.runtimeConfigHash;
    cancelPing();invalidateConnectionProbes();
    const operation=connectionController.run(request,{
      native:isTauriRuntime,resolve:server=>resolveServerForConnection(server,!server&&!selectedServerIdRef.current),
      connect:(server,options)=>remnawaveClient.connect(server,options),
      disconnect:()=>remnawaveClient.disconnect({useSystemProxy:proxyStatusRef.current.enabled}),
      observe:async()=>{
        const epoch=nativeMutations.revision;
        if(nativeMutations.pending())return null;
        const observed=await getNativeRuntimeObservation();
        if(epoch!==nativeMutations.revision||nativeMutations.pending()||!connectionController.accepts(runtimeStatusRef.current,observed))return null;
        setRuntimeStatus(observed);return observed;
      },disconnectRequested:()=>pendingDisconnectAfterBusyRef.current,
      phase:phase=>setConnectionStateSafe(phase==='disconnecting'?'disconnecting':'connecting')
    });
    const generation=connectionController.generation;const outcome:ConnectionOutcome=await operation;
    if(!connectionController.current(generation)||outcome.kind==='busy'||outcome.kind==='stale')return false;
    const restorePreferences=()=>{
      if(!rollbackSettings)return;
      // A later queued preference is a separate intent and must survive this result.
      setSettings(current=>{const next=restoreConnectionPreferences(current,requestedSettings,rollbackSettings);settingsRef.current=next;return next;});
    };
    if(outcome.kind==='connected'){
      const {server,response,rolledBack}=outcome;
      if(rolledBack)restorePreferences();
      if(response.runtime)setRuntimeStatus(response.runtime);
      setConnectivityProbe(response.probe??null);if(response.proxy)setProxyStatus(response.proxy);
      setSessionDuration(0);activeRuntimeProfileRef.current=server;
      connectedServerIdRef.current=server.id;setConnectedServerId(server.id);
      selectedServerIdRef.current=server.id;setSelectedServerId(server.id);
      lastRuntimeTunnelActive.current=true;lostRuntimePollCount.current=0;setConnectionStateSafe('connected');
      setErrorText('');runPostConnectProbe(server);scheduleVpnIpRefreshForServer(server.id,response.probe?.publicIp??response.externalIp);
      pushToast(rolledBack?tr(language,'Прежнее подключение восстановлено.','The previous connection was restored.'):`${tr(language,'Подключено','Connected')}: ${server.country}, ${server.city}`,rolledBack?'info':'success');
    }else{
      if(outcome.kind==='rejected'){
        restorePreferences();const observed=await refreshDiagnosticsAndRuntime();
        if(!connectionController.current(generation))return false;
        if(observed&&connectionController.reconcile(observed)!=='pending')commitObservedConnection(observed);
      }else if(outcome.kind!=='pending'&&outcome.runtime){
        setRuntimeStatus(outcome.runtime);commitObservedConnection(outcome.runtime);
        if(outcome.kind==='idle'||Boolean(previousRuntimeHash&&outcome.runtime.runtimeConfigHash===previousRuntimeHash&&outcome.runtime.lastPreparedServerId===request.previous?.id))restorePreferences();
      }
      if('error' in outcome&&outcome.error){
        const message=normalizeNativeError(outcome.error,tr(language,'Операция не подтверждена. Проверьте диагностику.','Operation not confirmed. Review diagnostics.')).message;
        setErrorText(message);pushToast(message,'error');
      }else if(outcome.kind==='idle')pushToast(tr(language,'VPN отключён.','VPN disconnected.'),'info');
    }
    finishManagedReconnect();scheduleConnectionQueueFlush('controller-settled');
    return outcome.kind==='connected'?!outcome.rolledBack:request.kind==='disconnect'&&outcome.kind==='idle';
  }

  async function handleReconnectToServer(nextServer:VpnServer,previousServer:VpnServer|null,rollbackSettings?:Partial<AppSettings>){
    if(updaterActionLock.current)return;
    const previous=getConnectedRuntimeServer()??previousServer;
    if(isConnectionActionBusy()){
      pendingServerSwitchRef.current={nextServerId:nextServer.id,previousServerId:previous?.id??''};scheduleConnectionQueueFlush('queued-reconnect');return;
    }
    if(operationManager.hasConflict('connect'))return;
    beginManagedReconnect(nextServer.id,previous?.id??'');
    await executeConnection({kind:'switch',target:nextServer,previous,options:connectionOptions(),
      rollbackOptions:connectionOptions({...settingsRef.current,...rollbackSettings})},rollbackSettings);
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
      await handleReconnectToServer(nextServer,previousServer);
    }
  }
  async function handleConnectionToggle(serverOverride:VpnServer|null=null){
    if(updaterActionLock.current||operationManager.isBusy('logout')||operationManager.isBusy('repairRuntime'))return;
    if(isConnectionActionBusy()){
      if(connectionStateRef.current!=='disconnecting'){
        pendingDisconnectAfterBusyRef.current=true;scheduleConnectionQueueFlush('queued-disconnect');
        pushToast(tr(language,'Отключение ожидает подтверждённого завершения native-операции.','Disconnect is waiting for confirmed native operation completion.'),'info');
      }
      return;
    }
    if(operationManager.hasConflict('connect'))return;
    if(connectionStateRef.current==='connected'||runtimeStatusRef.current.tunnelActive){
      await executeConnection({kind:'disconnect',options:connectionOptions()});return;
    }
    const target=isVpnServerLike(serverOverride)?serverOverride:getServerById(selectedServerIdRef.current);
    await executeConnection({kind:'connect',target,options:connectionOptions()});
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
        const observed = await refreshDiagnosticsAndRuntime();
        if (canAutoInstallUpdate(observed, connectionStateRef.current)) {
          await handleInstallUpdate(true);
        } else {
          setUpdateInfo(current => ({ ...current, message: tr(language, 'Обновление доступно. Для установки при активном или неподтверждённом состоянии VPN требуется ручное подтверждение.', 'An update is available. Installation with an active or unconfirmed VPN requires manual confirmation.') }));
        }
      }

      return result;
    }

    if (!silent) {
      pushToast(tr(language, 'Новых обновлений нет.', 'No updates available.'), 'success');
    }

    return result;
  }

  async function handleInstallUpdate(silent = false) {
    if (!persistentStateReady || updaterActionLock.current || operationManager.hasConflict('updateInstall') || connectionController.busy || ['checking', 'downloading', 'installing'].includes(updateInfoRef.current.status)) {
      return;
    }

    updaterActionLock.current = true;
    let installSucceeded = false;
    let updateTicket: string | null = null;
    void setNativeTrayUpdateState(Boolean(updateInfoRef.current.available), true);
    try {
      await flushPersistentWrites();

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
          message: percent >= 100 ? tr(language, 'Загрузка завершена. Подготавливаем установку…', 'Download complete. Preparing installation…') : tr(language, 'Скачиваем обновление…', 'Downloading update…')
        }));
      }, async () => {
        const observed = isTauriRuntime ? await refreshDiagnosticsAndRuntime() : null;
        if (isTauriRuntime && (!observed || observed.operation)) {
          throw new Error(tr(language, 'Установка отложена: состояние runtime не подтверждено или выполняется операция.', 'Installation deferred: runtime state is unconfirmed or an operation is in progress.'));
        }
        // Recheck after verified download: a connection may have started since
        // the first update check. Automatic installation never disconnects it.
        if (silent && !canAutoInstallUpdate(observed, connectionStateRef.current)) {
          throw new Error(tr(language, 'Установка отложена до ручного подтверждения. VPN не отключался.', 'Installation deferred until manual confirmation. The VPN was not disconnected.'));
        }
        const needsCleanup = observed ? updateNeedsOwnedCleanup(observed) : connectionStateRef.current === 'connected';
        if (needsCleanup && !window.confirm(tr(language, 'Для установки обновления потребуется временно отключить VPN и перезапустить приложение. Продолжить?', 'Installing the update will temporarily disconnect the VPN and restart the app. Continue?'))) {
          throw new Error(tr(language, 'Установка отменена пользователем. VPN не отключался.', 'Installation cancelled by the user. The VPN was not disconnected.'));
        }
        if (isTauriRuntime) {
          setPersistentStateReady(false);
          updateTicket = await sealUpdateState();
        }
        if (needsCleanup) {
          setUpdateInfo((current: UpdateInfo) => ({
            ...current,
            status: 'installing',
            message: tr(language, 'Отключаем VPN перед обновлением…', 'Disconnecting VPN before update…')
          }));
          try {
            if(!await executeConnection({kind:'disconnect',options:connectionOptions()}))throw new NativeOperationError('RUNTIME_DISCONNECT_FAILED','network',false,'Stop unconfirmed.');
          } catch (error) {
            await refreshDiagnosticsAndRuntime().catch(() => undefined);
            const message = normalizeNativeError(error, tr(language, 'Не удалось остановить VPN перед обновлением.', 'Failed to stop VPN before update.')).message;
            setUpdateInfo((current: UpdateInfo) => ({ ...current, status: 'error', message }));
            if (!silent) pushToast(message, 'error');
            throw error;
          }
        }

        if (isTauriRuntime && updateTicket) await approveUpdateExit(updateTicket);
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
    } catch (error) {
      const message = normalizeNativeError(error, tr(language, 'Не удалось подготовить обновление.', 'The update could not be prepared.')).message;
      setUpdateInfo((current: UpdateInfo) => ({ ...current, status: 'error', message }));
      if (!silent) pushToast(message, 'error');
    } finally {
      if (isTauriRuntime && !installSucceeded) {
        try { await releaseUpdateState(updateTicket); setPersistentStateReady(true); }
        catch (error) { setStorageErrorText(normalizeNativeError(error, tr(language, 'Не подтверждено снятие блокировки записи.', 'Storage write seal release was not confirmed.')).message); }
      }
      updaterActionLock.current = false;
      void setNativeTrayUpdateState(installSucceeded ? false : Boolean(updateInfoRef.current.available), false);
    }
  }


  useEffect(() => {
    if (!persistentStateReady || !settings.autoUpdate || hasAutoCheckedUpdates.current) {
      return;
    }

    hasAutoCheckedUpdates.current = true;
    void lifecycleActions.current.handleCheckUpdates(true, settings.autoInstallUpdates);
  }, [settings.autoUpdate, settings.autoInstallUpdates, settings.releaseChannel, persistentStateReady, lifecycleActions]);

  function toggleSetting(key: keyof Omit<AppSettings, 'releaseChannel' | 'protocolStrategy' | 'language' | 'allowDemoFallback' | 'tunnelMode' | 'ipStack' | 'routingExclusions' | 'tunRoutingMode'>) {
    setSettings((current: AppSettings) => {
      const next = { ...current, [key]: !current[key] };
      settingsRef.current = next;
      return next;
    });
  }

  async function handleExportDiagnosticsReport() {
    await runActionOnce('exportDiagnostics', async () => {
      const nativeLogLines = await readNativeRuntimeLog(120).catch(() => []);
      const diagnosticObservation=isTauriRuntime?await getNativeDiagnosticsSnapshot().catch(()=>null):null;
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
        nativeLogLines,
        trafficSnapshot: trafficCurrent, trafficSampleCount: trafficHistory.length,diagnosticObservation
      });

      downloadTextFile(buildDiagnosticsFilename(), payload);
      pushToast(tr(language, 'Безопасный диагностический отчёт сохранён.', 'Safe diagnostics report was saved.'), 'success');
      void writeNativeInterfaceLog('Пользователь экспортировал безопасный диагностический отчёт.');
    });
  }

  async function handleExportLegacyState() {
    if (!persistentStateReady || !window.confirm(tr(language,
      'Подготовить зашифрованный пакет отката на 0.13.76? Он содержит данные авторизации. Активация выполняется отдельно после закрытия обеих версий; текущие данные не заменяются.',
      'Prepare an encrypted rollback package for 0.13.76? It contains authorization data. Activate it separately after both versions are closed; current data will not be replaced.'))) return;
    await runActionOnce('exportLegacyState', async () => {
      try {
        const receipt = await prepareLegacyRollbackExport();
        pushToast(tr(language, `Зашифрованный пакет сохранён: ${receipt.directory}`, `Encrypted package saved: ${receipt.directory}`), 'success');
      } catch (error) {
        setStorageErrorText(normalizeNativeError(error, tr(language, 'Экспорт отката не завершён.', 'Rollback export did not complete.')).message);
      }
    });
  }

  async function handleClearAccessKey() {
    if (!confirmLogout(language, message=>window.confirm(message))) return;
    profileSyncGenerationRef.current++; remnawaveClient.invalidateProfileSync(); cancelPing();
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
            throw new NativeOperationError('RUNTIME_BUSY','network',false,'Logout did not stop the running operation.');
          }
        }

        const runtimeBeforeLogout = await refreshDiagnosticsAndRuntime();
        if(!runtimeBeforeLogout||connectionController.reconcile(runtimeBeforeLogout)==='pending')throw new NativeOperationError('RUNTIME_SNAPSHOT_INVALID','network',false,'Logout state unconfirmed.');
        const shouldDisconnectBeforeLogout = connectionStateRef.current === 'connected'
          || Boolean(runtimeBeforeLogout?.tunnelActive)
          || proxyStatusRef.current.enabled;

        if (shouldDisconnectBeforeLogout) {
          if(!await executeConnection({kind:'disconnect',options:connectionOptions()}))throw new NativeOperationError('RUNTIME_DISCONNECT_FAILED','network',false,'Stop unconfirmed.');
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
        pushToast(
          normalizeNativeError(error,tr(language,'Не удалось полностью очистить сессию.','Failed to fully clear the session.')).message,
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
        <ToastViewport items={toasts} language={language} onDismiss={dismissToast} criticalMessage={storageErrorText} dismissLabel={tr(language, 'Закрыть уведомление', 'Dismiss notification')} onDismissCritical={() => setStorageErrorText('')} actionLabel={tr(language, 'Восстановить / перечитать', 'Recover / reload')} onCriticalAction={() => void handleStorageRecovery()} />
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
                trafficReceivedText={formatTrafficBytes(trafficReceivedBytes, settings.language)}
                trafficSentText={formatTrafficBytes(trafficSentBytes, settings.language)}
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
                  connectionError={errorText}
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
                  onExportLegacyState={isTauriRuntime ? () => void handleExportLegacyState() : undefined}
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
                  isExportingLegacyState={isActionBusy('exportLegacyState') || !persistentStateReady}
                />
              </TabErrorBoundary>
            ) : null}

            {activeTab === 'settings' ? (
              <SettingsTab
                autostartStatus={autostartStatus}
                settings={settings}
                language={language}
                onToggleSetting={toggleSetting}
                onTunnelModeChange={(value) => void handleTunnelModeChange(value)}
                onIpStackChange={(value) => void handleIpStackChange(value)}
                onTunRoutingModeChange={value => { settingsRef.current = { ...settingsRef.current, tunRoutingMode: value }; setSettings(current => ({ ...current, tunRoutingMode: value })); }}
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
        onCopyFeedback={(success) => pushToast(success ? tr(language, 'Информация скопирована', 'Information copied') : tr(language, 'Не удалось скопировать информацию', 'Could not copy information'), success ? 'success' : 'error', { key: 'copy-info', force: true })}
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
        onChangePolicy={handleChangeSplitTunnelPolicy}
        tunnelMode={settings.tunnelMode}
        tunRoutingMode={settings.tunRoutingMode}
        onRemoveEntry={handleRemoveSplitTunnelEntry}
        onPickExecutable={handlePickExecutableForSplitTunnel}
        onRefreshRunningApps={refreshRunningAppsForSplitTunnel}
      />

      <ToastViewport items={toasts} language={language} onDismiss={dismissToast} criticalMessage={storageErrorText} dismissLabel={tr(language, 'Закрыть уведомление', 'Dismiss notification')} onDismissCritical={() => setStorageErrorText('')} actionLabel={tr(language, 'Восстановить / перечитать', 'Recover / reload')} onCriticalAction={() => void handleStorageRecovery()} />
    </div>
  );
}
