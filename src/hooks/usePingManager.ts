import { useCallback, useEffect, useRef, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import { tr } from '../i18n';
import { getServerPingEndpoint, pingNativeServer, writeNativeInterfaceLog, writeNativeRoutingLog } from '../services/runtime';
import { applyPingBatch, runPingBatch } from '../utils/pingBatch';
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
  activeOnly?: boolean;
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
  const controllerRef = useRef<AbortController | null>(null);
  const autoTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);
  const lastActiveRuntimeRef = useRef(runtimeStatus.runtimeId);
  const pendingRuntimeRefreshRef = useRef(false);

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
    return serversRef.current.filter((server) => server.runtimeTemplate?.profileKind === 'auto' || Boolean(getServerPingEndpoint(server)));
  }, []);

  const cancelPing = useCallback(() => {
    runIdRef.current++;
    autoRunIdRef.current++;
    controllerRef.current?.abort();
    controllerRef.current = null;
    if (autoTimerRef.current !== null) clearTimeout(autoTimerRef.current);
    inFlightRef.current = false;
    if (mountedRef.current) {
      setIsCheckingPing(false); setCheckingPingServerIds([]); setPingProgress(EMPTY_PING_PROGRESS);
    }
  }, []);

  const refreshPing = useCallback(async (options: PingOptions = {}) => {
    if (inFlightRef.current) return;
    const snapshot = serversRef.current;
    const activeId = connectionStateRef.current === 'connected'
      ? connectedServerIdRef.current || runtimeStatusRef.current.lastPreparedServerId || selectedServerIdRef.current : selectedServerIdRef.current;
    const targets = getPingableServers().filter(server => !options.activeOnly || server.id === activeId);
    if (!targets.length) return;
    const runId = ++runIdRef.current;
    const controller = new AbortController(); controllerRef.current = controller;

    inFlightRef.current = true;
    setIsCheckingPing(true);
    // One checking state for every target; retain previous latency until the batch
    // completes so optional ping sorting cannot jump on individual completions.
    setCheckingPingServerIds(targets.map(server => server.id));
    setPingProgress({ active: true, total: targets.length, completed: 0, success: 0, failed: 0 });
    void writeNativeInterfaceLog(`Ping batch started: ${targets.length}.`, options.reason ?? 'manual');
    try {
      const batch = await runPingBatch(targets, pingNativeServer, controller.signal, completed => {
        if (runIdRef.current === runId && mountedRef.current) setPingProgress({ active: true, total: targets.length, completed, success: 0, failed: 0 });
      });
      if (runIdRef.current !== runId || controller.signal.aborted || !mountedRef.current || serversRef.current !== snapshot) return;
      setServers(current => applyPingBatch(current, snapshot, batch));
      const probe = batch.results.find(result => result.id === activeId)?.probe;
      const currentId = connectionStateRef.current === 'connected'
        ? connectedServerIdRef.current || runtimeStatusRef.current.lastPreparedServerId || selectedServerIdRef.current : selectedServerIdRef.current;
      if (probe && activeId === currentId) setConnectivityProbe(probe);
      void writeNativeRoutingLog('Ping batch complete.', `total=${targets.length}; success=${batch.success}; timeout=${batch.timeout}; unreachable=${batch.unreachable}; cancelled=${batch.cancelled}; durationMs=${Math.round(batch.durationMs)}`);
      void refreshDiagnosticsAndRuntime();
      if (!options.silent) pushToast(tr(languageRef.current,
        `Пинг: ${batch.success}/${targets.length}; timeout: ${batch.timeout}; недоступны: ${batch.unreachable}; ${Math.round(batch.durationMs)} мс.`,
        `Ping: ${batch.success}/${targets.length}; timeout: ${batch.timeout}; unreachable: ${batch.unreachable}; ${Math.round(batch.durationMs)} ms.`), batch.success ? 'success' : 'info');
    } finally {
      if (runIdRef.current === runId && mountedRef.current) {
        inFlightRef.current = false; controllerRef.current = null;
        setIsCheckingPing(false); setCheckingPingServerIds([]); setPingProgress(EMPTY_PING_PROGRESS);
      }
    }
  }, [getPingableServers, pushToast, refreshDiagnosticsAndRuntime, setConnectivityProbe, setServers]);

  const scheduleAutoPing = useCallback((reason = 'auto-main-refresh', delayMs = 450) => {
    const runId = autoRunIdRef.current + 1;
    autoRunIdRef.current = runId;

    if (autoTimerRef.current !== null) clearTimeout(autoTimerRef.current);
    autoTimerRef.current = setTimeout(() => {
      if (!mountedRef.current || autoRunIdRef.current !== runId || inFlightRef.current || !serversRef.current.length) {
        return;
      }

      void writeNativeInterfaceLog('Автоматическая проверка пинга запланирована.', reason);
      void refreshPing({ silent: true, reason, activeOnly: true });
    }, delayMs);
  }, [refreshPing]);

  useEffect(() => {
    if (connectionState !== 'connected') return;
    const previousRuntime = lastActiveRuntimeRef.current;
    if (previousRuntime && !runtimeStatus.runtimeId) {
      pendingRuntimeRefreshRef.current = true;
      if (inFlightRef.current) cancelPing();
      return;
    }
    if (runtimeStatus.runtimeId) lastActiveRuntimeRef.current = runtimeStatus.runtimeId;
    const runtimeChanged = Boolean(previousRuntime && runtimeStatus.runtimeId && previousRuntime !== runtimeStatus.runtimeId);
    if (runtimeChanged) {
      pendingRuntimeRefreshRef.current = true;
      cancelPing();
    }
    const checkActive = (force = false) => {
      const id = connectedServerIdRef.current || runtimeStatusRef.current.lastPreparedServerId || selectedServerIdRef.current;
      const server = serversRef.current.find(item => item.id === id);
      const checked = server?.latencyCheckedAt ? Date.parse(server.latencyCheckedAt) : NaN;
      const fresh = (server?.latencyStatus === 'ok' || server?.latencyStatus === 'failed') && Number.isFinite(checked) && Date.now()-checked >= 0 && Date.now()-checked < 60000;
      if (server && !inFlightRef.current && (force || pendingRuntimeRefreshRef.current || !fresh)) {
        pendingRuntimeRefreshRef.current = false;
        void refreshPing({silent:true,reason:'active-profile',activeOnly:true});
      }
    };
    const timer = window.setTimeout(() => checkActive(runtimeChanged), 450);
    // Focus/pageshow invalidate latency after sleep/resume; never modify VPN state.
    const resume = () => checkActive(true);
    window.addEventListener('focus', resume); window.addEventListener('pageshow', resume);
    return () => { window.clearTimeout(timer); window.removeEventListener('focus',resume);window.removeEventListener('pageshow',resume); };
  }, [connectionState, connectedServerId, runtimeStatus.xrayPid, runtimeStatus.runtimeId, isCheckingPing, refreshPing, cancelPing]);

  useEffect(() => { if (inFlightRef.current) cancelPing(); }, [servers, connectionState, selectedServerId, connectedServerId, cancelPing]);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; cancelPing(); };
  }, [cancelPing]);

  return {
    isCheckingPing,
    pingProgress,
    checkingPingServerIds,
    refreshPing,
    scheduleAutoPing,
    cancelPing
  };
}
