import { useCallback, useMemo, useRef, useState } from 'react';

export type OperationName = string;

type ConflictMap = Record<OperationName, OperationName[]>;

const DEFAULT_CONFLICTS: ConflictMap = {
  connect: ['connect', 'disconnect', 'reconnect', 'updateInstall', 'logout'],
  disconnect: ['connect', 'disconnect', 'reconnect', 'updateInstall', 'logout'],
  reconnect: ['connect', 'disconnect', 'reconnect', 'updateInstall', 'logout'],
  updateCheck: ['updateCheck', 'updateInstall'],
  updateInstall: ['updateCheck', 'updateInstall', 'connect', 'disconnect', 'reconnect', 'proxy', 'logout'],
  proxy: ['proxy', 'updateInstall'],
  probe: ['probe'],
  syncProfile: ['syncProfile'],
  splitApps: ['splitApps'],
  pickExecutable: ['pickExecutable'],
  appInfo: ['appInfo'],
  exportDiagnostics: ['exportDiagnostics'],
  logout: ['logout', 'connect', 'disconnect', 'reconnect', 'updateInstall']
};

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

    try {
      return await task();
    } finally {
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
  }, [hasConflict]);

  return {
    busyActions,
    busyActionsRef,
    isBusy,
    hasConflict,
    run
  };
}
