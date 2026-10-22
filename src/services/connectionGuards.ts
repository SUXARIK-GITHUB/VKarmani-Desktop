import type { RuntimeStatus } from '../types/vpn';
import {nativeErrorCode,NativeOperationError} from '../utils/nativeErrors';

export function getRuntimePreparedServerId(runtime: RuntimeStatus | null | undefined) {
  return runtime?.lastPreparedServerId?.trim() ?? '';
}

export function getRuntimePreparedServerFingerprint(runtime: RuntimeStatus | null | undefined) {
  return runtime?.lastPreparedServerFingerprint?.trim() ?? '';
}

export function runtimeConfirmsTargetServer(
  runtime: RuntimeStatus | null | undefined,
  targetServerId: string,
  targetFingerprint = ''
) {
  const expectedId = targetServerId.trim();
  const expectedFingerprint = targetFingerprint.trim();
  const actualFingerprint = getRuntimePreparedServerFingerprint(runtime);

  return Boolean(
    runtime?.tunnelActive
      && expectedId
      && getRuntimePreparedServerId(runtime) === expectedId
      && (!expectedFingerprint || actualFingerprint === expectedFingerprint)
  );
}

export function assertNativeRuntimeServerMatches(
  nativeServerId: string | null | undefined,
  targetServerId: string,
  nativeFingerprint = '',
  targetFingerprint = ''
) {
  const actual = nativeServerId?.trim();
  const expected = targetServerId.trim();
  const actualFingerprint = nativeFingerprint.trim();
  const expectedFingerprint = targetFingerprint.trim();

  if (!actual || actual !== expected) {
    throw new NativeOperationError('RUNTIME_IDENTITY_UNCONFIRMED','network',false,'Native server identity was not confirmed.');
  }

  if (expectedFingerprint && actualFingerprint !== expectedFingerprint) {
    throw new NativeOperationError('RUNTIME_IDENTITY_UNCONFIRMED','network',false,'Native configuration identity was not confirmed.');
  }
}
export function nativeConnectFailurePreservesRuntime(error: unknown): boolean {
  return ['SUBSCRIPTION_UNAVAILABLE','SUBSCRIPTION_REJECTED','SESSION_CHANGED','OPERATION_CANCELLED','REQUEST_IDENTITY','CONNECT_PREFLIGHT','RUNTIME_BUSY','NATIVE_COMMAND_TIMEOUT'].includes(nativeErrorCode(error)??'');
}
