import { useCallback, useMemo, useRef, useState } from 'react';
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';

export type OperationName = string;

type ConflictMap = Record<OperationName, OperationName[]>;

type OperationTimeoutMap = Record<OperationName, number>;

const DEFAULT_CONFLICTS: ConflictMap = {
  connect: ['connect', 'disconnect', 'reconnect', 'updateInstall', 'logout', 'repairRuntime'],
  disconnect: ['connect', 'disconnect', 'reconnect', 'updateInstall', 'logout', 'repairRuntime'],
  reconnect: ['connect', 'disconnect', 'reconnect', 'updateInstall', 'logout', 'repairRuntime'],
  updateCheck: ['updateCheck', 'updateInstall'],
  updateInstall: ['updateCheck', 'updateInstall', 'connect', 'disconnect', 'reconnect', 'proxy', 'logout', 'repairRuntime'],
  proxy: ['proxy', 'updateInstall', 'repairRuntime'],
  probe: ['probe'],
  syncProfile: ['syncProfile'],
  splitApps: ['splitApps'],
  pickExecutable: ['pickExecutable'],
  appInfo: ['appInfo'],
  exportDiagnostics: ['exportDiagnostics'],
  repairRuntime: ['repairRuntime', 'connect', 'disconnect', 'reconnect', 'proxy', 'updateInstall', 'logout'],
  logout: ['logout', 'connect', 'disconnect', 'reconnect', 'updateInstall', 'repairRuntime']
};

const DEFAULT_OPERATION_TIMEOUTS_MS: OperationTimeoutMap = {
  connect: 70000,
  disconnect: 26000,
  reconnect: 80000,
  updateCheck: 25000,
  updateInstall: 120000,
  proxy: 22000,
  probe: 22000,
  syncProfile: 35000,
  splitApps: 18000,
  pickExecutable: 130000,
  appInfo: 22000,
  exportDiagnostics: 18000,
  repairRuntime: 40000,
  logout: 26000
};

function releaseBusyOperation(
  operation: OperationName,
  busyActionsRef: MutableRefObject<Record<OperationName, boolean>>,
  setBusyActions: Dispatch<SetStateAction<Record<OperationName, boolean>>>
) {
  if (!busyActionsRef.current[operation]) {
    return;
  }

  const nextBusyActions = { ...busyActionsRef.current };
  delete nextBusyActions[operation];
  busyActionsRef.current = nextBusyActions;
  setBusyActions((current) => {
    if (!current[operation]) {
      return current;
    }
    const next = { ...current };
    delete next[operation];
    return next;
  });
}

export function useOperationManager(customConflicts: ConflictMap = DEFAULT_CONFLICTS) {
  const conflicts = useMemo(() => customConflicts, [customConflicts]);
  const [busyActions, setBusyActions] = useState<Record<OperationName, boolean>>({});
  const busyActionsRef = useRef<Record<OperationName, boolean>>({});

  const isBusy = useCallback((operation: OperationName) => Boolean(busyActionsRef.current[operation]), []);

  const hasConflict = useCallback((operation: OperationName) => {
    const blockedByOperation = new Set<OperationName>([operation, ...(conflicts[operation] ?? [])]);

    return Object.keys(busyActionsRef.current).some((activeOperation) => (
      blockedByOperation.has(activeOperation) || (conflicts[activeOperation] ?? []).includes(operation)
    ));
  }, [conflicts]);

  const run = useCallback(async <T,>(operation: OperationName, task: () => Promise<T>): Promise<T | null> => {
    if (hasConflict(operation)) {
      return null;
    }

    busyActionsRef.current = { ...busyActionsRef.current, [operation]: true };
    setBusyActions((current) => ({ ...current, [operation]: true }));

    let watchdog: number | undefined;
    const timeoutMs = DEFAULT_OPERATION_TIMEOUTS_MS[operation] ?? 30000;

    try {
      if (typeof window !== 'undefined') {
        watchdog = window.setTimeout(() => {
          releaseBusyOperation(operation, busyActionsRef, setBusyActions);
        }, timeoutMs + 2500);
      }

      const taskPromise = task();
      taskPromise.catch(() => {
        // Ошибка будет обработана вызывающим кодом. Здесь catch нужен только для того,
        // чтобы поздний reject после UI-timeout не оставлял unhandled rejection.
      });

      return await taskPromise;
    } finally {
      if (watchdog !== undefined) {
        window.clearTimeout(watchdog);
      }
      releaseBusyOperation(operation, busyActionsRef, setBusyActions);
    }
  }, [hasConflict]);

  return {
    busyActions,
    busyActionsRef,
    isBusy,
    hasConflict,
    run
  };
}
