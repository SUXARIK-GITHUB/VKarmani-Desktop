import { useCallback, useEffect, useRef, useState } from 'react';
import type { ConnectionState } from '../types/vpn';

export type SetConnectionStateSafe = (next: ConnectionState | ((current: ConnectionState) => ConnectionState)) => void;

export function useConnectionStateController(initialState: ConnectionState = 'idle') {
  const [connectionState, setConnectionState] = useState<ConnectionState>(initialState);
  const connectionStateRef = useRef<ConnectionState>(initialState);
  const connectionActionStartedAt = useRef<number | null>(null);

  const trackConnectionStateTransition = useCallback((nextState: ConnectionState, currentState = connectionStateRef.current) => {
    if (nextState === 'connecting' || nextState === 'disconnecting') {
      if (currentState !== nextState || connectionActionStartedAt.current === null) {
        connectionActionStartedAt.current = Date.now();
      }
      return;
    }

    connectionActionStartedAt.current = null;
  }, []);

  const setConnectionStateSafe = useCallback<SetConnectionStateSafe>((next) => {
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
  }, [trackConnectionStateTransition]);

  useEffect(() => {
    connectionStateRef.current = connectionState;
  }, [connectionState]);

  return {
    connectionState,
    connectionStateRef,
    connectionActionStartedAt,
    setConnectionStateSafe
  };
}
