import { useCallback, useEffect, useRef, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import { tr } from '../i18n';
import { getServerPingEndpoint, pingNativeServer, writeNativeInterfaceLog, writeNativeRoutingLog } from '../services/runtime';
import { sleep } from '../utils/async';
import { EMPTY_PING_PROGRESS, type PingProgressState } from '../types/appState';
import type { AppSettings, ConnectivityProbe, ConnectionState, RuntimeStatus, ToastItem, VpnServer } from '../types/vpn';

interface UsePingManagerArgs {
  servers: VpnServer[];
  setServers: Dispatch<SetStateAction<VpnServer[]>>;
  connectionState: ConnectionState;
  selectedServerId: string;
  connectedServerId: string;
  runtimeStatus: RuntimeStatus;
  language: AppSettings['language'];
  setConnectivityProbe: (probe: ConnectivityProbe | null) => void;
  pushToast: (title: string, tone: ToastItem['tone']) => void;
  refreshDiagnosticsAndRuntime: () => Promise<RuntimeStatus | null>;
}

interface PingOptions {
  silent?: boolean;
  reason?: string;
}

function getServerPrimaryLabelForToast(server: VpnServer) {
  return [server.country, server.city].filter(Boolean).join(', ') || server.rawLabel || server.id;
}

function patchServerPingState(
  items: VpnServer[],
  serverId: string,
  patch: Pick<VpnServer, 'latency' | 'latencyCheckedAt' | 'latencyStatus'>
) {
  return items.map((server) => (server.id === serverId ? { ...server, ...patch } : server));
}

export function usePingManager({
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
}: UsePingManagerArgs) {
  const [isCheckingPing, setIsCheckingPing] = useState(false);
  const [pingProgress, setPingProgress] = useState<PingProgressState>(EMPTY_PING_PROGRESS);
  const [checkingPingServerIds, setCheckingPingServerIds] = useState<string[]>([]);

  const serversRef = useRef(servers);
  const connectionStateRef = useRef(connectionState);
  const selectedServerIdRef = useRef(selectedServerId);
  const connectedServerIdRef = useRef(connectedServerId);
  const runtimeStatusRef = useRef(runtimeStatus);
  const languageRef = useRef(language);
  const runIdRef = useRef(0);
  const autoRunIdRef = useRef(0);
  const inFlightRef = useRef(false);

  useEffect(() => {
    serversRef.current = servers;
  }, [servers]);

  useEffect(() => {
    connectionStateRef.current = connectionState;
  }, [connectionState]);

  useEffect(() => {
    selectedServerIdRef.current = selectedServerId;
  }, [selectedServerId]);

  useEffect(() => {
    connectedServerIdRef.current = connectedServerId;
  }, [connectedServerId]);

  useEffect(() => {
    runtimeStatusRef.current = runtimeStatus;
  }, [runtimeStatus]);

  useEffect(() => {
    languageRef.current = language;
  }, [language]);

  const getPingableServers = useCallback(() => {
    // Проверяем все серверы с endpoint. Менеджер пинга не выбирает сервер,
    // не переключает VPN и не блокирует reconnect — он только обновляет latency.
    return serversRef.current.filter((server) => Boolean(getServerPingEndpoint(server)));
  }, []);

  const updateServerPingState = useCallback((
    serverId: string,
    patch: Pick<VpnServer, 'latency' | 'latencyCheckedAt' | 'latencyStatus'>
  ) => {
    setServers((current) => {
      const next = patchServerPingState(current, serverId, patch);
      serversRef.current = patchServerPingState(serversRef.current, serverId, patch);
      return next;
    });
  }, [setServers]);

  const cancelPing = useCallback(() => {
    runIdRef.current += 1;
    autoRunIdRef.current += 1;
    inFlightRef.current = false;
    setIsCheckingPing(false);
    setCheckingPingServerIds([]);
    setPingProgress(EMPTY_PING_PROGRESS);
  }, []);

  const refreshPing = useCallback(async (options: PingOptions = {}) => {
    if (inFlightRef.current) {
      if (!options.silent) {
        pushToast(tr(languageRef.current, 'Проверка пинга уже идёт. Остальные кнопки можно использовать.', 'Ping check is already running. Other buttons remain available.'), 'info');
      }
      return;
    }

    const targets = getPingableServers();
    if (!targets.length) {
      if (!options.silent) {
        pushToast(tr(languageRef.current, 'Нет серверов с host/port для проверки пинга. Обновите серверы.', 'No servers with host/port are available for ping check. Refresh servers.'), 'info');
      }
      return;
    }

    const runId = runIdRef.current + 1;
    runIdRef.current = runId;

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

    inFlightRef.current = true;
    setIsCheckingPing(true);
    setPingProgress({ active: true, total: targets.length, completed: 0, success: 0, failed: 0 });
    void writeNativeInterfaceLog(`Запущена проверка пинга всех серверов: ${targets.length}.`, options.reason ?? 'manual');

    let cursor = 0;
    let completed = 0;
    let success = 0;
    let failed = 0;
    const currentConnectionState = connectionStateRef.current;
    const concurrency = Math.min(currentConnectionState === 'connected' ? 1 : 4, Math.max(1, targets.length));
    const probeTargetServerId = currentConnectionState === 'connected'
      ? connectedServerIdRef.current || runtimeStatusRef.current.lastPreparedServerId || selectedServerIdRef.current
      : selectedServerIdRef.current;

    const updateProgress = () => {
      setPingProgress({ active: true, total: targets.length, completed, success, failed });
    };

    const worker = async () => {
      while (runIdRef.current === runId) {
        const index = cursor;
        cursor += 1;
        const targetServer = targets[index];

        if (!targetServer) {
          return;
        }

        markActive(targetServer.id);

        try {
          const probe = await pingNativeServer(targetServer);

          if (runIdRef.current !== runId) {
            return;
          }

          const measuredLatency = Number.isFinite(probe.latencyMs) && probe.latencyMs !== undefined && probe.latencyMs !== null
            ? Math.max(1, Math.round(probe.latencyMs))
            : null;
          const packetLoss = probe.packetLossPct ?? (probe.success ? 0 : 100);

          if (measuredLatency) {
            if (probe.success) {
              success += 1;
            } else {
              failed += 1;
            }
            updateServerPingState(targetServer.id, {
              latency: measuredLatency,
              latencyCheckedAt: new Date().toLocaleString('ru-RU'),
              latencyStatus: probe.success ? 'ok' : 'failed'
            });
          } else {
            failed += 1;
            updateServerPingState(targetServer.id, {
              latency: null,
              latencyCheckedAt: new Date().toLocaleString('ru-RU'),
              latencyStatus: 'failed'
            });
          }

          const currentActiveServerId = connectionStateRef.current === 'connected'
            ? connectedServerIdRef.current || runtimeStatusRef.current.lastPreparedServerId || selectedServerIdRef.current
            : selectedServerIdRef.current;
          if (targetServer.id === probeTargetServerId && targetServer.id === currentActiveServerId) {
            setConnectivityProbe({ ...probe, packetLossPct: packetLoss });
          }

          void writeNativeRoutingLog(
            'Проверка пинга сервера завершена.',
            `${getServerPrimaryLabelForToast(targetServer)} · ${probe.success && measuredLatency ? `${measuredLatency} мс` : 'нет ответа'}`
          );
        } catch (error) {
          if (runIdRef.current !== runId) {
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
          if (runIdRef.current === runId) {
            completed += 1;
            markInactive(targetServer.id);
            updateProgress();
          }

          await sleep(connectionStateRef.current === 'connected' ? 70 : 0);
        }
      }
    };

    try {
      await Promise.all(Array.from({ length: concurrency }, () => worker()));

      if (runIdRef.current !== runId) {
        return;
      }

      void refreshDiagnosticsAndRuntime();
      if (!options.silent) {
        pushToast(
          tr(
            languageRef.current,
            `Пинг проверен: ${success}/${targets.length} серверов ответили, ${failed} без ответа.`,
            `Ping checked: ${success}/${targets.length} servers responded, ${failed} did not respond.`
          ),
          success > 0 ? 'success' : 'info'
        );
      }
    } catch (error) {
      if (options.silent) {
        return;
      }
      pushToast(
        error instanceof Error
          ? error.message
          : tr(languageRef.current, 'Не удалось проверить пинг.', 'Failed to check ping.'),
        'error'
      );
    } finally {
      if (runIdRef.current === runId) {
        inFlightRef.current = false;
        setIsCheckingPing(false);
        setCheckingPingServerIds([]);
        setPingProgress(EMPTY_PING_PROGRESS);
      }
    }
  }, [getPingableServers, pushToast, refreshDiagnosticsAndRuntime, setConnectivityProbe, updateServerPingState]);

  const scheduleAutoPing = useCallback((reason = 'auto-main-refresh', delayMs = 450) => {
    const runId = autoRunIdRef.current + 1;
    autoRunIdRef.current = runId;

    window.setTimeout(() => {
      if (autoRunIdRef.current !== runId || inFlightRef.current || !serversRef.current.length) {
        return;
      }

      void writeNativeInterfaceLog('Автоматическая проверка пинга запланирована.', reason);
      void refreshPing({ silent: true, reason });
    }, delayMs);
  }, [refreshPing]);

  useEffect(() => () => cancelPing(), [cancelPing]);

  return {
    isCheckingPing,
    pingProgress,
    checkingPingServerIds,
    refreshPing,
    scheduleAutoPing,
    cancelPing
  };
}
