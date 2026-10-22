export interface NativeStateSnapshot {
  schemaVersion: 2;
  generation: string;
  revision: string;
  updatedAt: string;
  readOnly: boolean;
  recoveryToken: string | null;
  payload: {
    public: Record<string, unknown>;
    protected: Record<string, unknown>;
    accessKey: string | null;
    sessionGeneration: string;
    legacyWebView: Record<string, unknown> | null;
  };
}
export class NativeStorageError extends Error {
  readonly category = 'storage';
  constructor(readonly code: string, message: string, readonly recoverable = true) {
    super(message); this.name = 'NativeStorageError';
  }
}
export function storageFailure(error: unknown): NativeStorageError {
  if (error instanceof NativeStorageError) return error;
  const value = error && typeof error === 'object' ? error as Record<string, unknown> : null;
  return new NativeStorageError(typeof value?.code === 'string' ? value.code : 'STATE_UNAVAILABLE', typeof value?.message === 'string' ? value.message : 'Хранилище недоступно. Сохранённые данные не сбрасывались.', value?.recoverable !== false);
}

let snapshot: NativeStateSnapshot | null = null;
let loading: Promise<NativeStateSnapshot> | null = null;
let conflict: NativeStorageError | null = null;

async function rpc<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  const { invoke } = await import('@tauri-apps/api/core');
  try { return await invoke<T>(command, args); } catch (error) { throw storageFailure(error); }
}
function validate(value: NativeStateSnapshot): NativeStateSnapshot {
  const counter = (item: unknown): item is string => typeof item === 'string' && /^(0|[1-9]\d{0,19})$/.test(item) && BigInt(item) <= 18446744073709551615n;
  const object = (item: unknown) => typeof item === 'object' && item !== null && !Array.isArray(item);
  if (value?.schemaVersion !== 2 || typeof value.generation !== 'string' || !/^[0-9a-f]{48}$/.test(value.generation) || !counter(value.revision) || !counter(value.updatedAt) || !value.payload || !object(value.payload.public) || !object(value.payload.protected) || !counter(value.payload.sessionGeneration) || (value.payload.accessKey !== null && typeof value.payload.accessKey !== 'string') || typeof value.readOnly !== 'boolean' || (value.recoveryToken !== null && (typeof value.recoveryToken !== 'string' || !/^[0-9a-f]{64}$/.test(value.recoveryToken))) || (value.readOnly && value.recoveryToken === null) || (value.payload.legacyWebView !== null && !object(value.payload.legacyWebView))) {
    throw new NativeStorageError('STATE_PROTOCOL_INVALID', 'Native state snapshot не прошёл проверку.', false);
  }
  return value;
}
export function peekNativeState(): NativeStateSnapshot | null { return snapshot; }
export async function inspectNativeState(force = false): Promise<NativeStateSnapshot> {
  if (!force && snapshot) return snapshot;
  if (loading) return loading;
  loading = rpc<NativeStateSnapshot>('load_state_snapshot').then(value => {
    snapshot = validate(value);
    if (force) conflict = null;
    return snapshot;
  }).finally(() => { loading = null; });
  return loading;
}
export async function readNativeState(): Promise<NativeStateSnapshot> {
  const value = await inspectNativeState();
  if (value.readOnly) throw new NativeStorageError('STATE_RECOVERY_REQUIRED', 'Доступна проверенная резервная копия. Для записи требуется подтверждённое восстановление.', false);
  return value;
}
export async function commitNativeChange(scope: string, key: string, value: unknown, expectedSession?: string): Promise<void> {
  if (conflict) throw conflict;
  const current = await readNativeState();
  if (expectedSession !== undefined && expectedSession !== current.payload.sessionGeneration) throw new NativeStorageError('STATE_SESSION_CHANGED', 'Устаревшая запись кэша отменена после смены сессии.');
  const request = { generation: current.generation, expectedRevision: current.revision, expectedSessionGeneration: current.payload.sessionGeneration, operationId: crypto.randomUUID(), changes: [{ scope, key, value: value ?? null }] };
  try {
    const result = await rpc<{ snapshot: NativeStateSnapshot; deduplicated: boolean }>('commit_state_patch', { request });
    const next = validate(result.snapshot);
    if (next.readOnly || next.generation !== current.generation || BigInt(next.revision) < BigInt(current.revision) || BigInt(next.revision) > BigInt(current.revision) + 1n) throw new NativeStorageError('STATE_PROTOCOL_INVALID', 'Некорректное подтверждение записи.', false);
    snapshot = next;
  } catch (error) {
    const failure = storageFailure(error);
    // Old queued edits must never be silently rebased after another writer.
    if (failure.code === 'STATE_CONFLICT') conflict = failure;
    throw failure;
  }
}
export async function recoverNativeState(): Promise<NativeStateSnapshot> {
  const current = await inspectNativeState(true);
  if (!current.readOnly) return current;
  if (!current.recoveryToken) throw new NativeStorageError('STATE_RECOVERY_REQUIRED', 'Нет проверенной резервной копии.', false);
  snapshot = validate(await rpc<NativeStateSnapshot>('recover_state_snapshot', { token: current.recoveryToken }));
  conflict = null;
  return snapshot;
}
export async function exportNativeStateLegacy(): Promise<{ directory: string; generation: string; revision: string }> {
  const current = await readNativeState();
  return rpc('export_state_legacy', { generation: current.generation, revision: current.revision });
}
// Legacy service function names are internal adapters, not legacy write IPC.
export async function invokeStateProtocol<T>(command: string, args: Record<string, unknown>, expectedSession?: string): Promise<T> {
  if (command.startsWith('load_')) {
    const current = await readNativeState();
    if (command === 'load_access_key_secure') return current.payload.accessKey as T;
    const values = command === 'load_sensitive_client_state_value' ? current.payload.protected : current.payload.public;
    const value = values[String(args.key)];
    return (value === undefined ? null : JSON.stringify(value)) as T;
  }
  const credential = command === 'save_access_key_secure' || command === 'clear_access_key_secure';
  const scope = credential ? 'credential' : command.includes('sensitive') ? 'protected' : 'public';
  const value = command.startsWith('clear_') ? null : credential ? String(args.value) : JSON.parse(String(args.value));
  await commitNativeChange(scope, credential ? 'accessKey' : String(args.key), value, expectedSession);
  return undefined as T;
}
