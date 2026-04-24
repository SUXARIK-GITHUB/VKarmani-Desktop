import { useEffect, useMemo, useRef, useState } from 'react';
import { AuthScreen } from './components/AuthScreen';
import { DevicesTab } from './components/DevicesTab';
import { DiagnosticsTab } from './components/DiagnosticsTab';
import { OverviewTab } from './components/OverviewTab';
import { ServersTab } from './components/ServersTab';
import { SettingsTab } from './components/SettingsTab';
import { SidebarNav } from './components/SidebarNav';
import { ToastViewport } from './components/ToastViewport';
import { TabErrorBoundary } from './components/TabErrorBoundary';
import { WindowHeader } from './components/WindowHeader';
import { tr } from './i18n';
import { remnawaveClient } from './services/remnawave';
import {
  appVersion,
  ensureAdminLaunch,
  fetchPublicIpSnapshot,
  getIntegrationMeta,
  isTauriRuntime,
  requestWindowHide,
  setNativeLaunchOnStartup,
  setNativeRunAsAdminPreference,
  writeNativeInterfaceLog,
  writeNativeRoutingLog,
  normalizeNativeError
} from './services/runtime';
import {
  clearStoredAccessKey,
  loadSettings,
  loadSplitTunnelEntries,
  loadStoredAccessKey,
  loadStoredAccessKeySecure,
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
  ProfileSyncInfo,
  ProxyStatus,
  RemnawaveSession,
  RuntimeStatus,
  SessionRecord,
  SplitTunnelEntry,
  ToastItem,
  UpdateInfo,
  VpnServer
} from './types/vpn';

function createToast(title: string, tone: ToastItem['tone']): ToastItem {
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    title,
    tone
  };
}

const integrationMeta = getIntegrationMeta();
const sleep = (ms: number) => new Promise<void>((resolve) => window.setTimeout(resolve, ms));

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
  const [splitTunnelEntries, setSplitTunnelEntries] = useState<SplitTunnelEntry[]>(() => loadSplitTunnelEntries());
  const [activeTab, setActiveTab] = useState<AppTab>('overview');
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [authLoading, setAuthLoading] = useState(false);
  const [connectionState, setConnectionState] = useState<ConnectionState>('idle');
  const [servers, setServers] = useState<VpnServer[]>([]);
  const [selectedServerId, setSelectedServerId] = useState('');
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
  const [searchValue, setSearchValue] = useState('');
  const [isSyncingProfile, setIsSyncingProfile] = useState(false);
  const [isBusySystemAction, setIsBusySystemAction] = useState(false);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo>({
    available: false,
    currentVersion: appVersion,
    source: isTauriRuntime ? 'tauri' : 'mock',
    status: 'idle',
    message: 'Проверка обновлений ещё не запускалась.'
  });
  const hasAutoCheckedUpdates = useRef(false);
  const hasTriedAdminLaunch = useRef(false);
  const lastRuntimeTunnelActive = useRef(false);
  const lastAppliedSplitTunnelSignature = useRef('');

  useEffect(() => {
    let cancelled = false;

    void loadStoredAccessKeySecure()
      .then((storedKey) => {
        if (!cancelled && storedKey.trim()) {
          setAccessKey(storedKey.trim());
        }
      })
      .catch((error) => {
        void writeNativeInterfaceLog('Не удалось загрузить ключ из защищённого хранилища.', normalizeNativeError(error, 'secure storage error').message);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const language = settings.language;

  useEffect(() => {
    saveSettings(settings);
  }, [settings]);

  useEffect(() => {
    saveSplitTunnelEntries(splitTunnelEntries);
  }, [splitTunnelEntries]);

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
    if (!isTauriRuntime) {
      return;
    }

    void setNativeRunAsAdminPreference(settings.runAsAdmin).catch((error) => {
      void writeNativeInterfaceLog(
        'Не удалось сохранить настройку запуска от администратора.',
        normalizeNativeError(error, 'admin preference error').message
      );
    });

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
    let timer: number | undefined;
    if (connectionState === 'connected') {
      timer = window.setInterval(() => setSessionDuration((value: number) => value + 1), 1000);
    }
    return () => {
      if (timer) {
        window.clearInterval(timer);
      }
    };
  }, [connectionState]);

  useEffect(() => {
    remnawaveClient.loadServers().then((result) => {
      setServers(result);
      const preferredServer = pickPreferredServer(result, settings.protocolStrategy);
      if (preferredServer) {
        setSelectedServerId((current: string) => current || preferredServer.id);
      }
    }).catch(() => undefined);
    remnawaveClient.loadHistory().then(setSessionHistory).catch(() => undefined);
    remnawaveClient.loadDevices().then(setDevices).catch(() => undefined);
    remnawaveClient.loadDiagnostics().then(setDiagnostics).catch(() => undefined);
    remnawaveClient.loadRuntimeStatus().then((nextRuntime: RuntimeStatus) => {
      setRuntimeStatus(nextRuntime);
      setConnectionState(nextRuntime.tunnelActive ? 'connected' : 'idle');
      lastRuntimeTunnelActive.current = nextRuntime.tunnelActive;
    }).catch(() => undefined);
    remnawaveClient.loadProxyStatus().then(setProxyStatus).catch(() => undefined);
    setProfileSyncInfo(remnawaveClient.getProfileSyncInfo());
    void refreshPrimaryExternalIp();
  }, [settings.protocolStrategy]);

  useEffect(() => {
    if (!isTauriRuntime) {
      return;
    }

    let disposed = false;
    let unlistenFn: (() => void) | undefined;

    void (async () => {
      try {
        const eventApi = await import('@tauri-apps/api/event');
        const unlisten = await eventApi.listen<string>('vkarmani://tray-action', (event: { payload: string }) => {
          if (event.payload === 'show') {
            setActiveTab('overview');
          }

          if (event.payload === 'connect') {
            setActiveTab('overview');
            void handleConnectionToggle();
          }

          if (event.payload === 'disconnect' && connectionState === 'connected') {
            void handleConnectionToggle();
          }

          if (event.payload === 'restart_proxy') {
            void handleRestartSystemProxy();
          }
        });

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
  }, [connectionState, selectedServerId, servers]);

  useEffect(() => {
    if (!isTauriRuntime) {
      return;
    }

    let disposed = false;

    const syncRuntime = async () => {
      try {
        const [nextRuntime, nextProxy] = await Promise.all([
          remnawaveClient.loadRuntimeStatus(),
          remnawaveClient.loadProxyStatus()
        ]);

        if (disposed) {
          return;
        }

        const lostTunnel = lastRuntimeTunnelActive.current && !nextRuntime.tunnelActive;
        lastRuntimeTunnelActive.current = nextRuntime.tunnelActive;

        setRuntimeStatus(nextRuntime);
        setProxyStatus(nextProxy);

        if (nextRuntime.tunnelActive) {
          setConnectionState((current: ConnectionState) => current === 'disconnecting' ? current : 'connected');
          return;
        }

        setConnectionState((current: ConnectionState) => current === 'connecting' || current === 'disconnecting' ? current : 'idle');

        if (!lostTunnel || connectionState === 'disconnecting') {
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
      }
    };

    void syncRuntime();
    const timer = window.setInterval(() => {
      void syncRuntime();
    }, connectionState === 'connected' ? 4000 : 12000);

    return () => {
      disposed = true;
      window.clearInterval(timer);
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

    const toast = createToast(title, tone);
    setToasts((items: ToastItem[]) => [...items, toast]);

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

  const filteredServers = useMemo(() => {
    const normalized = searchValue.trim().toLowerCase();
    const strategyApplied = rankServers(servers, settings.protocolStrategy);

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
  }, [searchValue, servers, settings.protocolStrategy]);

  useEffect(() => {
    if (connectionState !== 'connected' || settings.tunnelMode !== 'tun' || !selectedServer) {
      lastAppliedSplitTunnelSignature.current = splitTunnelSignature;
      return;
    }

    if (splitTunnelSignature === lastAppliedSplitTunnelSignature.current) {
      return;
    }

    lastAppliedSplitTunnelSignature.current = splitTunnelSignature;
    pushToast(
      tr(language, 'Список TUN обновлён. Переподключаем VPN, чтобы сразу применить новые правила.', 'The TUN list was updated. Reconnecting the VPN to apply the new rules immediately.'),
      'info'
    );
    void handleReconnectToServer(selectedServer, selectedServer);
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
  const hasRuntimeReadyServer = Boolean(selectedServer?.runtimeTemplate || servers.some((server: VpnServer) => Boolean(server.runtimeTemplate)) || accessKey.trim());
  const canConnectSelectedServer = connectionState === 'connected' || Boolean(selectedServer && hasRuntimeReadyServer && (!isTauriRuntime || runtimeStatus.coreInstalled));
  const isUpdateChecking = updateInfo.status === 'checking';

  async function refreshDiagnosticsAndRuntime() {
    const [runtime, nextDiagnostics, nextProxy] = await Promise.all([
      remnawaveClient.loadRuntimeStatus(),
      remnawaveClient.loadDiagnostics(),
      remnawaveClient.loadProxyStatus()
    ]);

    setRuntimeStatus(runtime);
    setDiagnostics(nextDiagnostics);
    setProxyStatus(nextProxy);
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

  function updateTunnelModePreference(value: AppSettings['tunnelMode']) {
    setSettings((current: AppSettings) => ({
      ...current,
      tunnelMode: value
    }));
  }

  function shouldUseSystemProxy(mode: AppSettings['tunnelMode'], enabledBySettings = settings.useSystemProxy) {
    return mode === 'proxy' && enabledBySettings;
  }

  function getActiveSplitTunnelEntries() {
    return splitTunnelEntries.filter((entry: SplitTunnelEntry) => entry.enabled && entry.value.trim());
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



  async function handleEnableSystemProxy() {
    if (isBusySystemAction) {
      return;
    }

    setIsBusySystemAction(true);
    try {
      const nextProxy = await remnawaveClient.applySystemProxy(true);
      setProxyStatus(nextProxy);
      await refreshDiagnosticsAndRuntime();
      pushToast(tr(language, 'Системный proxy включён.', 'System proxy enabled.'), 'success');
      void writeNativeRoutingLog('Системный proxy включён вручную.', nextProxy.server ?? '127.0.0.1:10809');
    } catch (error) {
      pushToast(
        error instanceof Error
          ? error.message
          : tr(language, 'Не удалось включить системный proxy.', 'Failed to enable the system proxy.'),
        'error'
      );
    } finally {
      setIsBusySystemAction(false);
    }
  }

  async function handleDisableSystemProxy() {
    if (isBusySystemAction) {
      return;
    }

    setIsBusySystemAction(true);
    try {
      const nextProxy = await remnawaveClient.applySystemProxy(false);
      setProxyStatus(nextProxy);
      await refreshDiagnosticsAndRuntime();
      pushToast(tr(language, 'Системный proxy выключен.', 'System proxy disabled.'), 'info');
      void writeNativeRoutingLog('Системный proxy выключен вручную.');
    } catch (error) {
      pushToast(
        error instanceof Error
          ? error.message
          : tr(language, 'Не удалось выключить системный proxy.', 'Failed to disable the system proxy.'),
        'error'
      );
    } finally {
      setIsBusySystemAction(false);
    }
  }

  async function handleRestartSystemProxy() {
    if (isBusySystemAction) {
      return;
    }

    setIsBusySystemAction(true);
    try {
      await remnawaveClient.applySystemProxy(false);
      await sleep(350);
      const nextProxy = await remnawaveClient.applySystemProxy(true);
      setProxyStatus(nextProxy);
      await refreshDiagnosticsAndRuntime();
      pushToast(tr(language, 'Прокси перезапущен.', 'Proxy restarted.'), 'success');
      void writeNativeRoutingLog('Системный proxy перезапущен из меню tray.', nextProxy.server ?? '127.0.0.1:10809');
    } catch (error) {
      pushToast(
        error instanceof Error
          ? error.message
          : tr(language, 'Не удалось перезапустить proxy.', 'Failed to restart proxy.'),
        'error'
      );
    } finally {
      setIsBusySystemAction(false);
    }
  }

  async function handleRunConnectivityProbe() {
    if (isBusySystemAction) {
      return;
    }

    setIsBusySystemAction(true);
    try {
      const probe = await remnawaveClient.runConnectivityProbe();
      setConnectivityProbe(probe);
      await refreshDiagnosticsAndRuntime();
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
    } finally {
      setIsBusySystemAction(false);
    }
  }

  async function handleRevokeDevice(deviceId: string) {
    if (!deviceId) {
      return;
    }

    setIsBusySystemAction(true);
    try {
      const nextDevices = await remnawaveClient.revokeDevice(deviceId);
      setDevices(Array.isArray(nextDevices) ? nextDevices : []);
      await refreshDiagnosticsAndRuntime();
      pushToast(tr(language, 'Устройство отключено.', 'Device revoked.'), 'info');
      void writeNativeInterfaceLog('Устройство отключено пользователем.', deviceId);
    } catch (error) {
      pushToast(
        error instanceof Error
          ? error.message
          : tr(language, 'Не удалось отключить устройство.', 'Failed to revoke the device.'),
        'error'
      );
    } finally {
      setIsBusySystemAction(false);
    }
  }

  async function handleTunnelModeChange(nextMode: AppSettings['tunnelMode']) {
    if (nextMode === settings.tunnelMode || connectionState === 'connecting' || connectionState === 'disconnecting') {
      return;
    }

    const previousMode = settings.tunnelMode;
    const previousUseSystemProxy = settings.useSystemProxy;
    const activeSplitEntries = getActiveSplitTunnelEntries();
    void writeNativeInterfaceLog('Пользователь меняет режим маршрутизации.', `${previousMode} -> ${nextMode}`);

    if (connectionState === 'connected' && nextMode === 'tun' && activeSplitEntries.length === 0) {
      pushToast(
        tr(language, 'Для TUN сначала добавьте хотя бы одну программу или службу. Текущее подключение оставлено без изменений.', 'For TUN, add at least one program or service first. The current connection was left unchanged.'),
        'info'
      );
      return;
    }

    updateTunnelModePreference(nextMode);

    if (nextMode === 'tun' && activeSplitEntries.length === 0) {
      pushToast(
        tr(language, 'Выбран TUN режим. Сначала добавьте программы или службы, затем подключайтесь.', 'TUN mode selected. Add apps or services first, then connect.'),
        'info'
      );
    }

    if (connectionState !== 'connected' || !selectedServer) {
      pushToast(
        nextMode === 'tun'
          ? tr(language, 'Выбран TUN режим.', 'TUN mode selected.')
          : tr(language, 'Выбран proxy режим.', 'Proxy mode selected.'),
        'info'
      );
      return;
    }

    try {
      setConnectionState('disconnecting');
      await remnawaveClient.disconnect({ useSystemProxy: proxyStatus.enabled || (previousMode !== 'tun' && previousUseSystemProxy) });
      setVpnExternalIp('—');
      setConnectivityProbe(null);
      setSessionDuration(0);

      setConnectionState('connecting');
      const response = await remnawaveClient.connect(selectedServer, {
        useSystemProxy: shouldUseSystemProxy(nextMode),
        probeAfterConnect: settings.probeOnConnect,
        tunnelMode: nextMode,
        splitTunnelEntries
      });
      setConnectivityProbe(response.probe ?? null);
      if (response.proxy) {
        setProxyStatus(response.proxy);
      }
      setSessionDuration(0);
      await refreshDiagnosticsAndRuntime();
      const resolvedVpnIp = await refreshVpnExternalIpWithRetry();
      if (!resolvedVpnIp) {
        setVpnExternalIp(response.probe?.publicIp ?? response.externalIp);
      }
      setConnectionState('connected');
      void writeNativeRoutingLog('Режим маршрутизации переключён.', `${previousMode} -> ${nextMode} | сервер ${selectedServer.country}, ${selectedServer.city}`);
      pushToast(
        nextMode === 'tun'
          ? tr(language, 'Режим переключён на TUN.', 'The mode was switched to TUN.')
          : tr(language, 'Режим переключён на proxy.', 'The mode was switched to proxy.'),
        'success'
      );
    } catch (error) {
      setSettings((current: AppSettings) => ({
        ...current,
        tunnelMode: previousMode,
        useSystemProxy: previousUseSystemProxy
      }));
      void writeNativeRoutingLog(
        'Ошибка при переключении режима маршрутизации.',
        normalizeNativeError(error, 'unknown-error').message
      );
      setConnectionState('idle');
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
  }

  async function handleSyncProfile(silent = false) {
    const normalizedAccessKey = accessKey.trim();
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

      const result = await remnawaveClient.syncProfile(normalizedAccessKey, settings.allowDemoFallback);
      setServers(result.servers);
      setProfileSyncInfo(result.profile);
      const refreshedSession = remnawaveClient.getCachedSession();
      if (refreshedSession) {
        setSession(refreshedSession);
      }
      const refreshedDevices = await remnawaveClient.loadDevices();
      setDevices(refreshedDevices);

      const preferredServer = pickPreferredServer(result.servers, settings.protocolStrategy);
      setSelectedServerId((current: string) => {
        if (result.servers.some((item: VpnServer) => item.id === current)) {
          return current;
        }

        return preferredServer?.id ?? current;
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

  async function handleAuthorize() {
    const normalizedAccessKey = accessKey.trim();

    if (!normalizedAccessKey) {
      setErrorText(tr(language, 'Сначала вставьте ключ доступа.', 'Paste the access key first.'));
      return;
    }

    try {
      void writeNativeInterfaceLog('Начата авторизация по ключу доступа.');
      setAuthLoading(true);
      setErrorText('');
      setAccessKey(normalizedAccessKey);
      const response = await remnawaveClient.authorizeByAccessKey(normalizedAccessKey, settings.allowDemoFallback);
      setSession(response);
      const nextDevices = await remnawaveClient.loadDevices();
      setDevices(nextDevices);
      setIsAuthorized(true);
      await saveStoredAccessKey(normalizedAccessKey);
      pushToast(tr(language, 'Ключ доступа принят.', 'Access key accepted.'), 'success');
      void writeNativeInterfaceLog('Авторизация по ключу доступа завершена успешно.');

      let preferredServerForAutoConnect = selectedServer;

      if (settings.profileSyncOnLogin) {
        const syncResult = await handleSyncProfile(true);
        preferredServerForAutoConnect = syncResult?.servers
          ? pickPreferredServer(syncResult.servers, settings.protocolStrategy)
          : preferredServerForAutoConnect;
      }

      if (settings.autoConnect && preferredServerForAutoConnect) {
        await handleConnectionToggle(preferredServerForAutoConnect);
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

  async function handleReconnectToServer(nextServer: VpnServer, previousServer: VpnServer | null) {
    if (settings.tunnelMode === 'tun' && getActiveSplitTunnelEntries().length === 0) {
      if (previousServer?.id) {
        setSelectedServerId(previousServer.id);
        setConnectionState('connected');
      } else {
        setConnectionState('idle');
      }
      pushToast(
        tr(language, 'Для TUN сначала добавьте хотя бы одну программу или службу.', 'For TUN, add at least one program or service first.'),
        'info'
      );
      return;
    }

    try {
      setConnectionState('connecting');

      const response = await remnawaveClient.connect(nextServer, {
        useSystemProxy: shouldUseSystemProxy(settings.tunnelMode),
        probeAfterConnect: settings.probeOnConnect,
        tunnelMode: settings.tunnelMode,
        splitTunnelEntries
      });
      setConnectivityProbe(response.probe ?? null);
      if (response.proxy) {
        setProxyStatus(response.proxy);
      }
      setSessionDuration(0);
      await refreshDiagnosticsAndRuntime();
      const resolvedVpnIp = await refreshVpnExternalIpWithRetry();
      if (!resolvedVpnIp) {
        setVpnExternalIp(response.probe?.publicIp ?? response.externalIp);
      }
      setConnectionState('connected');
      pushToast(
        `${tr(language, 'Мягкое переподключение', 'Soft reconnect')}: ${nextServer.country}, ${nextServer.city}`,
        'success'
      );
    } catch (error) {
      if (proxyStatus.enabled || shouldUseSystemProxy(settings.tunnelMode)) {
        try {
          const restoredProxy = await remnawaveClient.applySystemProxy(false);
          setProxyStatus(restoredProxy);
        } catch {
          // ignore follow-up proxy restore failure
        }
      }

      if (previousServer?.id) {
        setSelectedServerId(previousServer.id);
      }

      setConnectivityProbe(null);
      setVpnExternalIp('—');
      setSessionDuration(0);
      setConnectionState('idle');
      await refreshDiagnosticsAndRuntime();
      await refreshPrimaryExternalIp();
      pushToast(
        error instanceof Error
          ? error.message
          : tr(language, 'Не удалось переключить сервер без разрыва соединения.', 'Failed to switch server without disconnecting.'),
        'error'
      );
    }
  }


  function findMatchingServer(candidates: VpnServer[], baseServer: VpnServer | null) {
    if (!baseServer) {
      return pickPreferredServer(candidates, settings.protocolStrategy);
    }

    return candidates.find((server: VpnServer) => server.id === baseServer.id)
      ?? candidates.find((server: VpnServer) => {
        const sameRuntime = JSON.stringify(server.runtimeTemplate ?? null) === JSON.stringify(baseServer.runtimeTemplate ?? null);
        const sameEndpoint = server.host === baseServer.host && (server.port ?? 443) === (baseServer.port ?? 443);
        const sameLabel = server.country === baseServer.country && server.city === baseServer.city && server.protocol === baseServer.protocol;
        return sameRuntime || sameEndpoint || sameLabel;
      })
      ?? pickPreferredServer(candidates, settings.protocolStrategy);
  }

  async function resolveServerForConnection(baseServer: VpnServer | null) {
    let resolvedServer = baseServer ?? pickPreferredServer(servers, settings.protocolStrategy);

    if (resolvedServer?.runtimeTemplate) {
      return resolvedServer;
    }

    const cachedServers = await remnawaveClient.loadServers();
    resolvedServer = findMatchingServer(cachedServers, resolvedServer);
    if (resolvedServer?.runtimeTemplate) {
      if (resolvedServer.id !== selectedServerId) {
        setSelectedServerId(resolvedServer.id);
      }
      return resolvedServer;
    }

    if (accessKey.trim()) {
      const syncResult = await handleSyncProfile(true);
      const syncedServers = syncResult?.servers ?? await remnawaveClient.loadServers();
      resolvedServer = findMatchingServer(syncedServers, resolvedServer);
      if (resolvedServer?.runtimeTemplate) {
        if (resolvedServer.id !== selectedServerId) {
          setSelectedServerId(resolvedServer.id);
        }
        return resolvedServer;
      }
    }

    return resolvedServer ?? null;
  }

  async function handleSelectServer(nextServerId: string) {
    if (nextServerId === selectedServerId) {
      return;
    }

    const nextServer = servers.find((server: VpnServer) => server.id === nextServerId) ?? null;
    const previousServer = selectedServer;
    if (nextServer) {
      void writeNativeInterfaceLog('Выбран сервер.', `${nextServer.country}, ${nextServer.city}`);
    }
    setSelectedServerId(nextServerId);

    if (!nextServer) {
      return;
    }

    if (connectionState !== 'connected') {
      return;
    }

    if (!nextServer.runtimeTemplate) {
      if (previousServer?.id) {
        setSelectedServerId(previousServer.id);
      }
      pushToast(
        tr(language, 'Для этого сервера ещё нет live-конфига. Текущее подключение оставлено без изменений.', 'This server is not runtime-ready yet. The current connection was left unchanged.'),
        'info'
      );
      return;
    }

    await handleReconnectToServer(nextServer, previousServer);
  }

  async function handleConnectionToggle(serverOverride: VpnServer | null = null) {
    if (connectionState === 'connecting' || connectionState === 'disconnecting') {
      return;
    }

    let targetServer = await resolveServerForConnection(serverOverride ?? selectedServer ?? null);
    if (!targetServer) {
      setErrorText(tr(language, 'Сервер пока не выбран. Синхронизируйте профиль и выберите узел.', 'Server is not selected yet. Sync the profile and choose a node.'));
      void writeNativeRoutingLog('Подключение остановлено: активный сервер не выбран.');
      return;
    }

    if (!targetServer.runtimeTemplate && connectionState !== 'connected') {
      setErrorText(tr(language, 'Не удалось найти готовый сервер в активном профиле. Обновите профиль и попробуйте ещё раз.', 'No runtime-ready server was found in the active profile. Sync the profile and try again.'));
      void writeNativeRoutingLog('Подключение остановлено: runtime-ready сервер не найден.', `${targetServer.country}, ${targetServer.city}`);
      pushToast(tr(language, 'Сначала обновите профиль или выберите другой сервер.', 'Sync the profile or choose another server first.'), 'info');
      return;
    }

    try {
      if (connectionState === 'connected') {
        void writeNativeRoutingLog('Пользователь отключает VPN.', `${targetServer.country}, ${targetServer.city}`);
        setConnectionState('disconnecting');
        await remnawaveClient.disconnect({ useSystemProxy: proxyStatus.enabled || shouldUseSystemProxy(settings.tunnelMode) });
        setVpnExternalIp('—');
        setSessionDuration(0);
        setConnectivityProbe(null);
        setConnectionState('idle');
        await refreshDiagnosticsAndRuntime();
        await refreshPrimaryExternalIp();
        pushToast(tr(language, 'VPN отключён.', 'VPN disconnected.'), 'info');
        void writeNativeRoutingLog('VPN отключён.', `${targetServer.country}, ${targetServer.city}`);
        return;
      }

      await refreshPrimaryExternalIp();
      if (settings.tunnelMode === 'tun' && getActiveSplitTunnelEntries().length === 0) {
        pushToast(
          tr(language, 'Для TUN сначала добавьте хотя бы одну программу или службу.', 'For TUN, add at least one program or service.'),
          'info'
        );
        return;
      }
      void writeNativeRoutingLog(
        'Пользователь запускает VPN подключение.',
        `${targetServer.country}, ${targetServer.city} | mode=${settings.tunnelMode}`
      );
      setConnectionState('connecting');
      let response: ConnectResult;
      try {
        response = await remnawaveClient.connect(targetServer, {
          useSystemProxy: shouldUseSystemProxy(settings.tunnelMode),
          probeAfterConnect: settings.probeOnConnect,
          tunnelMode: settings.tunnelMode,
          splitTunnelEntries
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
          if (targetServer.id !== selectedServerId) {
            setSelectedServerId(targetServer.id);
          }

          response = await remnawaveClient.connect(targetServer, {
            useSystemProxy: shouldUseSystemProxy(settings.tunnelMode),
            probeAfterConnect: settings.probeOnConnect,
            tunnelMode: settings.tunnelMode,
            splitTunnelEntries
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
      setConnectionState('connected');
      await refreshDiagnosticsAndRuntime();
      const resolvedVpnIp = await refreshVpnExternalIpWithRetry();
      if (!resolvedVpnIp) {
        setVpnExternalIp(response.probe?.publicIp ?? response.externalIp);
      }
      pushToast(`${tr(language, 'Подключено', 'Connected')}: ${targetServer.country}, ${targetServer.city}`, 'success');
      void writeNativeRoutingLog('VPN подключён успешно.', `${targetServer.country}, ${targetServer.city} | mode=${settings.tunnelMode}`);
    } catch (error) {
      void writeNativeRoutingLog(
        'Ошибка VPN подключения.',
        normalizeNativeError(error, 'unknown-error').message
      );
      setErrorText(normalizeNativeError(error, tr(language, 'Ошибка подключения.', 'Connection failed.')).message);
      setConnectionState('idle');
      pushToast(normalizeNativeError(error, tr(language, 'Не удалось подключиться.', 'Failed to connect.')).message, 'error');
    }
  }

  async function handleCheckUpdates(silent = false, autoInstall = false): Promise<UpdateInfo> {
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
  }


  useEffect(() => {
    if (!settings.autoUpdate || hasAutoCheckedUpdates.current) {
      return;
    }

    hasAutoCheckedUpdates.current = true;
    void handleCheckUpdates(true, false);
  }, [settings.autoUpdate, settings.releaseChannel]);

  function toggleSetting(key: keyof Omit<AppSettings, 'releaseChannel' | 'protocolStrategy' | 'language' | 'allowDemoFallback' | 'tunnelMode'>) {
    setSettings((current: AppSettings) => ({ ...current, [key]: !current[key] }));
  }

  function handleClearAccessKey() {
    void clearStoredAccessKey();
    setAccessKey('');
    pushToast(tr(language, 'Сохранённый ключ очищен.', 'Stored key cleared.'), 'info');
  }

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
          {isUpdateChecking ? (
            <div className="startup-update-check" role="status" aria-live="polite">
              <span className="startup-update-spinner" />
              <span>{tr(language, 'Проверяем обновления… Вход и работа доступны.', 'Checking updates… Sign-in and app use are available.')}</span>
            </div>
          ) : null}
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
    <div className={`shell app-shell ${settings.themeGlow ? 'glow-enabled' : 'glow-disabled'}`}>
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
        {isUpdateChecking ? (
          <div className="startup-update-check" role="status" aria-live="polite">
            <span className="startup-update-spinner" />
            <span>{tr(language, 'Проверяем обновления… Приложение не заблокировано.', 'Checking updates… The app is not blocked.')}</span>
          </div>
        ) : null}

        <main className="workspace-grid">
          <SidebarNav
            activeTab={activeTab}
            onChange={setActiveTab}
            connectionState={connectionState}
            session={session}
            devices={devices}
            language={language}
            showDiagnostics={settings.showDiagnostics}
          />

          <section className={`content-area ${activeTab === 'overview' ? 'overview-content-area' : ''}`}>
            {activeTab === 'overview' ? (
              <OverviewTab
                connectionState={connectionState}
                connectLabel={connectLabel}
                statusText={statusText}
                selectedServer={selectedServer}
                primaryExternalIp={primaryExternalIp}
                vpnExternalIp={vpnExternalIp}
                sessionDurationText={sessionDurationText}
                diagnosticsStatus={diagnosticsStatus}
                runtimeStatus={runtimeStatus}
                language={language}
                showDiagnostics={settings.showDiagnostics}
                tunnelMode={settings.tunnelMode}
                splitTunnelEntries={splitTunnelEntries}
                onToggleConnection={handleConnectionToggle}
                onTunnelModeChange={(value) => void handleTunnelModeChange(value)}
                onAddSplitTunnelEntry={handleAddSplitTunnelEntry}
                onToggleSplitTunnelEntry={handleToggleSplitTunnelEntry}
                onRemoveSplitTunnelEntry={handleRemoveSplitTunnelEntry}
                profileSyncMessage={profileSyncInfo.message}
                isBusy={connectionState === 'connecting' || connectionState === 'disconnecting'}
                canConnect={canConnectSelectedServer}
                isSyncingProfile={isSyncingProfile}
              />
            ) : null}

            {activeTab === 'servers' ? (
              <ServersTab
                servers={filteredServers}
                allServerCount={servers.length}
                selectedServerId={selectedServerId}
                onSelectServer={(serverId) => void handleSelectServer(serverId)}
                searchValue={searchValue}
                language={language}
                syncMessage={profileSyncInfo.message}
                showDiagnostics={settings.showDiagnostics}
                connectionState={connectionState}
                onSearchChange={setSearchValue}
              />
            ) : null}

            {activeTab === 'devices' ? (
              <TabErrorBoundary language={language} title={tr(language, 'Устройства', 'Devices')}>
                <DevicesTab devices={devices} language={language} onRevokeDevice={handleRevokeDevice} />
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
                  onClearAccessKey={handleClearAccessKey}
                  onReleaseChannelChange={(value) => setSettings((current: AppSettings) => ({ ...current, releaseChannel: value }))}
                  onProtocolStrategyChange={(value) => setSettings((current: AppSettings) => ({ ...current, protocolStrategy: value }))}
                  onTunnelModeChange={(value) => void handleTunnelModeChange(value)}
                  onLanguageChange={(value) => setSettings((current: AppSettings) => ({ ...current, language: value }))}
                  isBusy={isBusySystemAction}
                  isSyncingProfile={isSyncingProfile}
                />
              </TabErrorBoundary>
            ) : null}

            {activeTab === 'settings' ? (
              <SettingsTab
                settings={settings}
                language={language}
                onToggleSetting={toggleSetting}
                onTunnelModeChange={(value) => void handleTunnelModeChange(value)}
              />
            ) : null}
          </section>
        </main>
      </div>

      <ToastViewport items={toasts} />
    </div>
  );
}
