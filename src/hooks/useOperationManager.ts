import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { OperationOwnership } from '../utils/operationOwnership';
import {nativeMutations} from '../services/nativeTransport';

export type OperationName = string;

type ConflictMap = Record<OperationName, OperationName[]>;

type OperationTimeoutMap = Record<OperationName, number>;

const DEFAULT_CONFLICTS: ConflictMap = {
  connect: ['connect', 'disconnect', 'reconnect', 'updateInstall', 'logout', 'repairRuntime'],
  disconnect: ['connect', 'disconnect', 'reconnect', 'updateInstall', 'logout', 'repairRuntime'],
  reconnect: ['connect', 'disconnect', 'reconnect', 'updateInstall', 'logout', 'repairRuntime'],
  updateCheck: ['updateCheck', 'updateInstall'],
  updateInstall: ['updateCheck', 'updateInstall', 'connect', 'disconnect', 'reconnect', 'proxy', 'logout', 'repairRuntime'],
  proxy: ['proxy', 'connect', 'disconnect', 'reconnect', 'updateInstall', 'logout', 'repairRuntime'],
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
  connect: 90000,
  disconnect: 26000,
  reconnect: 90000,
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
const MUTATING_OPERATIONS=new Set(['connect','disconnect','reconnect','proxy','repairRuntime','logout','updateInstall']);

export function useOperationManager(customConflicts: ConflictMap = DEFAULT_CONFLICTS) {
  const conflicts = useMemo(() => customConflicts, [customConflicts]);
  const [busyActions, setBusyActions] = useState<Record<OperationName, boolean>>({});
  const ownership = useRef(new OperationOwnership());
  const mounted=useRef(true);
  const timers=useRef(new Set<number>());
  useEffect(()=>{const ownedTimers=timers.current;mounted.current=true;return()=>{mounted.current=false;for(const timer of ownedTimers)window.clearTimeout(timer);ownedTimers.clear();};},[]);
  const publish=useCallback(()=>{const next=ownership.current.snapshot();busyActionsRef.current=next;if(mounted.current)setBusyActions(next);},[]);
  const busyActionsRef = useRef<Record<OperationName, boolean>>({});
  useEffect(()=>{window.addEventListener('vkarmani:native-mutation-changed',publish);return()=>window.removeEventListener('vkarmani:native-mutation-changed',publish);},[publish]);

  const isBusy = useCallback((operation: OperationName) => Boolean(busyActionsRef.current[operation]), []);

  const hasConflict = useCallback((operation: OperationName) => {
    if(MUTATING_OPERATIONS.has(operation)&&nativeMutations.pending())return true;
    const blockedByOperation = new Set<OperationName>([operation, ...(conflicts[operation] ?? [])]);

    return Object.keys(busyActionsRef.current).some((activeOperation) => (
      blockedByOperation.has(activeOperation) || (conflicts[activeOperation] ?? []).includes(operation)
    ));
  }, [conflicts]);

  const run = useCallback(async <T,>(operation: OperationName, task: () => Promise<T>): Promise<T | null> => {
    if(MUTATING_OPERATIONS.has(operation)&&nativeMutations.pending())return null;
    const token=ownership.current.acquire(operation,conflicts);
    if(token===null)return null;
    publish();

    let watchdog: number | undefined;
    const timeoutMs = DEFAULT_OPERATION_TIMEOUTS_MS[operation] ?? 30000;

    try {
      if (typeof window !== 'undefined') {
        watchdog = window.setTimeout(() => {
          // A deadline is observational: only the task's actual settlement can
          // release its owner. The native registry also survives IPC deadlines.
          if(mounted.current)window.dispatchEvent(new CustomEvent('vkarmani:operation-overdue',{detail:{operation}}));
        }, timeoutMs + 2500);
        timers.current.add(watchdog);
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
        timers.current.delete(watchdog);
      }
      if(ownership.current.release(operation,token))publish();
    }
  }, [conflicts,publish]);

  return {
    busyActions,
    busyActionsRef,
    isBusy,
    hasConflict,
    run
  };
}
