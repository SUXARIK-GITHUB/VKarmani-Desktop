export type PendingServerSwitch = {
  nextServerId: string;
  previousServerId: string;
};

export type PingProgressState = {
  active: boolean;
  total: number;
  completed: number;
  success: number;
  failed: number;
};

export const EMPTY_PING_PROGRESS: PingProgressState = {
  active: false,
  total: 0,
  completed: 0,
  success: 0,
  failed: 0
};
